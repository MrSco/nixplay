/// Pure-Rust HomeKit Accessory Protocol (HAP) Pairing & Encrypted Channel for AirPlay 2.
///
/// Implements:
/// - TLV8 encoding/decoding (including >255-byte fragmented items)
/// - HAP Transient Pairing (`pair-setup` M1..M4 with PIN "3939", `X-Apple-HKP: 4`)
/// - HAP Normal PIN Pairing (`pair-setup` M1..M6 with 4-digit on-screen PIN, Ed25519 keys, `X-Apple-HKP: 3`)
/// - HAP Pair-Verify (`pair-verify` M1..M4 with X25519 + Ed25519 using saved credentials)
/// - HKDF-SHA-512 control & event channel key derivation
/// - ChaCha20-Poly1305 length-prefixed framed RTSP transport encryption

use crate::config::HapCredentials;
use anyhow::{bail, Context, Result};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use num_bigint::BigUint;
use rand::RngCore;
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

pub const TLV_METHOD: u8 = 0x00;
pub const TLV_IDENTIFIER: u8 = 0x01;
pub const TLV_SALT: u8 = 0x02;
pub const TLV_PUBLIC_KEY: u8 = 0x03;
pub const TLV_PROOF: u8 = 0x04;
pub const TLV_ENCRYPTED_DATA: u8 = 0x05;
pub const TLV_STATE: u8 = 0x06;
pub const TLV_ERROR: u8 = 0x07;
pub const TLV_SIGNATURE: u8 = 0x0A;
pub const TLV_FLAGS: u8 = 0x13;

pub const PAIRING_METHOD_PAIR_SETUP: u8 = 0x00;
pub const PAIRING_FLAG_TRANSIENT: u8 = 0x10;

const SRP_USERNAME: &[u8] = b"Pair-Setup";
const DEFAULT_TRANSIENT_PIN: &str = "3939";
const N_LEN: usize = 384; // 3072 bits

/// RFC 5054 Appendix A 3072-bit safe prime N
const SRP_3072_N_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B",
    "139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485",
    "B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1F",
    "E649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23",
    "DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32",
    "905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF69558",
    "17183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521",
    "ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D7",
    "1E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B1817",
    "7B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82",
    "D120A93AD2CAFFFFFFFFFFFFFFFF"
);

/// Encode TLV8 items (automatically fragmenting values longer than 255 bytes per HAP spec).
pub fn tlv8_encode(items: &[(u8, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(tag, val) in items {
        if val.is_empty() {
            out.push(tag);
            out.push(0);
            continue;
        }
        for chunk in val.chunks(255) {
            out.push(tag);
            out.push(chunk.len() as u8);
            out.extend_from_slice(chunk);
        }
    }
    out
}

/// Decode TLV8 buffer, coalescing adjacent fragments with the same tag.
pub fn tlv8_decode(data: &[u8]) -> Result<Vec<(u8, Vec<u8>)>> {
    let mut items: Vec<(u8, Vec<u8>)> = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if i + 2 > data.len() {
            bail!("truncated TLV8 header at offset {i}");
        }
        let tag = data[i];
        let len = data[i + 1] as usize;
        i += 2;
        if i + len > data.len() {
            bail!("truncated TLV8 value for tag 0x{tag:02x}");
        }
        let slice = &data[i..i + len];
        i += len;

        if let Some(last) = items.last_mut() {
            if last.0 == tag {
                last.1.extend_from_slice(slice);
                continue;
            }
        }
        items.push((tag, slice.to_vec()));
    }
    Ok(items)
}

pub fn tlv8_get<'a>(items: &'a [(u8, Vec<u8>)], tag: u8) -> Option<&'a [u8]> {
    items.iter().find(|(t, _)| *t == tag).map(|(_, v)| v.as_slice())
}

fn pad_to(bytes: &[u8], len: usize) -> Vec<u8> {
    if bytes.len() >= len {
        return bytes[bytes.len() - len..].to_vec();
    }
    let mut out = vec![0u8; len - bytes.len()];
    out.extend_from_slice(bytes);
    out
}

fn sha512(chunks: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
    for c in chunks {
        h.update(c);
    }
    h.finalize().into()
}

fn hkdf_sha512_32(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha512>::new(Some(salt), ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .map_err(|_| anyhow::anyhow!("HKDF-SHA-512 expand failed"))?;
    Ok(out)
}

fn hap_nonce_str(label: &[u8; 8]) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..12].copy_from_slice(label);
    n
}

/// Supports both HAP Transient Pairing (M1..M4, PIN "3939") and
/// HAP Normal PIN Pairing (M1..M6, 4-digit on-screen PIN + Ed25519 long-term keys).
pub struct HapTransientPairer {
    pin: String,
    transient: bool,
    client_id: String,
    signing_key: SigningKey,
    n: BigUint,
    g: BigUint,
    a: BigUint,
    pub_a: BigUint,
    session_key: Option<[u8; 64]>,
    expected_m2: Option<[u8; 64]>,
}

impl HapTransientPairer {
    pub fn new(pin: Option<&str>) -> Self {
        let transient = pin.is_none();
        let n = BigUint::parse_bytes(SRP_3072_N_HEX.as_bytes(), 16).expect("valid RFC 5054 N");
        let g = BigUint::from(5u32);

        let mut a_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut a_bytes);
        let a = BigUint::from_bytes_be(&a_bytes);
        let pub_a = g.modpow(&a, &n);

        let mut sk_seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut sk_seed);
        let signing_key = SigningKey::from_bytes(&sk_seed);
        let client_id = format!("{:016X}", rand::random::<u64>());

        Self {
            pin: pin.unwrap_or(DEFAULT_TRANSIENT_PIN).to_string(),
            transient,
            client_id,
            signing_key,
            n,
            g,
            a,
            pub_a,
            session_key: None,
            expected_m2: None,
        }
    }

    /// Build M1 payload for `POST /pair-setup`.
    pub fn build_m1(&self) -> Vec<u8> {
        if self.transient {
            tlv8_encode(&[
                (TLV_STATE, &[0x01]),
                (TLV_METHOD, &[PAIRING_METHOD_PAIR_SETUP]),
                (TLV_FLAGS, &[PAIRING_FLAG_TRANSIENT]),
            ])
        } else {
            tlv8_encode(&[
                (TLV_STATE, &[0x01]),
                (TLV_METHOD, &[PAIRING_METHOD_PAIR_SETUP]),
            ])
        }
    }

    /// Process M2 response from accessory and return M3 payload for `POST /pair-setup`.
    pub fn process_m2_and_build_m3(&mut self, m2_tlv: &[u8]) -> Result<Vec<u8>> {
        let items = tlv8_decode(m2_tlv)?;
        if let Some(err) = tlv8_get(&items, TLV_ERROR) {
            bail!("HAP pair-setup M2 returned error code: {:?}", err);
        }
        let salt_raw = tlv8_get(&items, TLV_SALT).context("M2 missing salt")?;
        let pub_b_raw = tlv8_get(&items, TLV_PUBLIC_KEY).context("M2 missing server public key B")?;

        let b_big = BigUint::from_bytes_be(pub_b_raw);
        if &b_big % &self.n == BigUint::from(0u32) {
            bail!("Invalid SRP server public key B (0 mod N)");
        }

        let n_bytes = self.n.to_bytes_be();
        let g_bytes = self.g.to_bytes_be();
        let a_bytes = self.pub_a.to_bytes_be();
        let b_bytes = b_big.to_bytes_be();

        // k = H(PAD(N) || PAD(g))
        let k_hash = sha512(&[&pad_to(&n_bytes, N_LEN), &pad_to(&g_bytes, N_LEN)]);
        let k = BigUint::from_bytes_be(&k_hash);

        // u = H(PAD(A) || PAD(B))
        let u_hash = sha512(&[&pad_to(&a_bytes, N_LEN), &pad_to(&b_bytes, N_LEN)]);
        let u = BigUint::from_bytes_be(&u_hash);
        if u == BigUint::from(0u32) {
            bail!("Invalid SRP scrambling parameter u == 0");
        }

        // x = H(s || H("Pair-Setup:" || pin))
        let salt_big = BigUint::from_bytes_be(salt_raw);
        let salt_min = salt_big.to_bytes_be();
        let up_hash = sha512(&[SRP_USERNAME, b":", self.pin.as_bytes()]);
        let x_hash = sha512(&[&salt_min, &up_hash]);
        let x = BigUint::from_bytes_be(&x_hash);

        let v = self.g.modpow(&x, &self.n);
        let kv = (&k * &v) % &self.n;
        let base = if b_big >= kv {
            (&b_big - &kv) % &self.n
        } else {
            (&b_big + &self.n - &kv) % &self.n
        };
        let exp = &self.a + (&u * &x);
        let s_big = base.modpow(&exp, &self.n);
        let s_bytes = s_big.to_bytes_be();

        let session_key = sha512(&[&s_bytes]);

        let h_n = sha512(&[&n_bytes]);
        let h_g = sha512(&[&g_bytes]);
        let mut h_xor = [0u8; 64];
        for i in 0..64 {
            h_xor[i] = h_n[i] ^ h_g[i];
        }
        let h_i = sha512(&[SRP_USERNAME]);
        let m1 = sha512(&[&h_xor, &h_i, &salt_min, &a_bytes, &b_bytes, &session_key]);
        let expected_m2 = sha512(&[&a_bytes, &m1, &session_key]);

        self.session_key = Some(session_key);
        self.expected_m2 = Some(expected_m2);

        Ok(tlv8_encode(&[
            (TLV_STATE, &[0x03]),
            (TLV_PUBLIC_KEY, &a_bytes),
            (TLV_PROOF, &m1),
        ]))
    }

    /// Verify M4 response from accessory and return the 64-byte SRP session shared secret.
    pub fn process_m4(&self, m4_tlv: &[u8]) -> Result<[u8; 64]> {
        let items = tlv8_decode(m4_tlv)?;
        if let Some(err) = tlv8_get(&items, TLV_ERROR) {
            bail!("HAP pair-setup M4 returned error code: {:?} (wrong PIN?)", err);
        }
        let proof = tlv8_get(&items, TLV_PROOF).context("M4 missing server proof")?;
        let expected = self
            .expected_m2
            .context("process_m4 called before process_m2")?;
        if proof != expected {
            bail!("HAP pair-setup M4 server proof mismatch");
        }
        self.session_key
            .context("session key missing after verification")
    }

    /// Build M5 payload for normal (non-transient) PIN pairing: signs client Ed25519 identity.
    pub fn build_m5(&self) -> Result<Vec<u8>> {
        let session_key = self
            .session_key
            .context("build_m5 called before M4 verified")?;

        let device_x = hkdf_sha512_32(
            &session_key,
            b"Pair-Setup-Controller-Sign-Salt",
            b"Pair-Setup-Controller-Sign-Info",
        )?;
        let pub_bytes = self.signing_key.verifying_key().to_bytes();

        let mut device_info = Vec::with_capacity(32 + self.client_id.len() + 32);
        device_info.extend_from_slice(&device_x);
        device_info.extend_from_slice(self.client_id.as_bytes());
        device_info.extend_from_slice(&pub_bytes);

        let sig = self.signing_key.sign(&device_info).to_bytes();

        let sub_tlv = tlv8_encode(&[
            (TLV_IDENTIFIER, self.client_id.as_bytes()),
            (TLV_PUBLIC_KEY, &pub_bytes),
            (TLV_SIGNATURE, &sig),
        ]);

        let enc_key = hkdf_sha512_32(
            &session_key,
            b"Pair-Setup-Encrypt-Salt",
            b"Pair-Setup-Encrypt-Info",
        )?;
        let cipher = ChaCha20Poly1305::new((&enc_key).into());
        let nonce_bytes = hap_nonce_str(b"PS-Msg05");
        let encrypted = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), sub_tlv.as_slice())
            .map_err(|_| anyhow::anyhow!("M5 ChaCha20 encryption failed"))?;

        Ok(tlv8_encode(&[
            (TLV_STATE, &[0x05]),
            (TLV_ENCRYPTED_DATA, &encrypted),
        ]))
    }

    /// Decrypt and verify M6 response from accessory and return persistent `HapCredentials`.
    pub fn process_m6(&self, m6_tlv: &[u8]) -> Result<HapCredentials> {
        let session_key = self
            .session_key
            .context("process_m6 called before M4 verified")?;
        let items = tlv8_decode(m6_tlv)?;
        if let Some(err) = tlv8_get(&items, TLV_ERROR) {
            bail!("HAP pair-setup M6 returned error code: {:?}", err);
        }
        let enc_data =
            tlv8_get(&items, TLV_ENCRYPTED_DATA).context("M6 missing encrypted data")?;

        let enc_key = hkdf_sha512_32(
            &session_key,
            b"Pair-Setup-Encrypt-Salt",
            b"Pair-Setup-Encrypt-Info",
        )?;
        let cipher = ChaCha20Poly1305::new((&enc_key).into());
        let nonce_bytes = hap_nonce_str(b"PS-Msg06");
        let decrypted = cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), enc_data)
            .map_err(|_| anyhow::anyhow!("M6 ChaCha20 decryption failed"))?;

        let sub_items = tlv8_decode(&decrypted)?;
        let server_pk =
            tlv8_get(&sub_items, TLV_PUBLIC_KEY).context("M6 missing accessory public key")?;
        if server_pk.len() != 32 {
            bail!("M6 accessory public key invalid length {}", server_pk.len());
        }

        Ok(HapCredentials {
            client_id: self.client_id.clone(),
            client_sk_hex: hex::encode(self.signing_key.to_bytes()),
            server_pk_hex: hex::encode(server_pk),
        })
    }
}

/// HAP Pair-Verify (M1..M4) using saved persistent Ed25519 credentials.
/// Produces a fresh 32-byte X25519 shared secret for encrypted control/event/audio channels.
pub struct HapPairVerifier {
    client_id: String,
    signing_key: SigningKey,
    server_vk: VerifyingKey,
    eph_secret: X25519Secret,
    eph_public: X25519Public,
    shared_secret: Option<[u8; 32]>,
    server_eph_public: Option<[u8; 32]>,
}

impl HapPairVerifier {
    pub fn from_credentials(creds: &HapCredentials) -> Result<Self> {
        let sk_bytes: [u8; 32] = hex::decode(&creds.client_sk_hex)
            .context("invalid client_sk_hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("client_sk must be 32 bytes"))?;
        let pk_bytes: [u8; 32] = hex::decode(&creds.server_pk_hex)
            .context("invalid server_pk_hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("server_pk must be 32 bytes"))?;

        let signing_key = SigningKey::from_bytes(&sk_bytes);
        let server_vk = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|e| anyhow::anyhow!("invalid server Ed25519 pubkey: {e}"))?;

        let mut eph_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut eph_bytes);
        let eph_secret = X25519Secret::from(eph_bytes);
        let eph_public = X25519Public::from(&eph_secret);

        Ok(Self {
            client_id: creds.client_id.clone(),
            signing_key,
            server_vk,
            eph_secret,
            eph_public,
            shared_secret: None,
            server_eph_public: None,
        })
    }

    pub fn build_m1(&self) -> Vec<u8> {
        tlv8_encode(&[
            (TLV_STATE, &[0x01]),
            (TLV_PUBLIC_KEY, self.eph_public.as_bytes()),
        ])
    }

    pub fn process_m2_and_build_m3(&mut self, m2_tlv: &[u8]) -> Result<Vec<u8>> {
        let items = tlv8_decode(m2_tlv)?;
        if let Some(err) = tlv8_get(&items, TLV_ERROR) {
            bail!("HAP pair-verify M2 returned error code: {:?}", err);
        }
        let server_pub_slice =
            tlv8_get(&items, TLV_PUBLIC_KEY).context("pair-verify M2 missing public key")?;
        let server_pub_arr: [u8; 32] = server_pub_slice
            .try_into()
            .map_err(|_| anyhow::anyhow!("pair-verify M2 server pubkey must be 32 bytes"))?;
        let enc_data = tlv8_get(&items, TLV_ENCRYPTED_DATA)
            .context("pair-verify M2 missing encrypted data")?;

        let server_pub = X25519Public::from(server_pub_arr);
        let shared = self.eph_secret.diffie_hellman(&server_pub).to_bytes();

        let session_key = hkdf_sha512_32(
            &shared,
            b"Pair-Verify-Encrypt-Salt",
            b"Pair-Verify-Encrypt-Info",
        )?;
        let cipher = ChaCha20Poly1305::new((&session_key).into());

        // Decrypt M2 and verify accessory Ed25519 signature
        let dec = cipher
            .decrypt(Nonce::from_slice(&hap_nonce_str(b"PV-Msg02")), enc_data)
            .map_err(|_| anyhow::anyhow!("pair-verify M2 decryption failed"))?;
        let sub = tlv8_decode(&dec)?;
        let acc_id = tlv8_get(&sub, TLV_IDENTIFIER).context("M2 missing accessory id")?;
        let acc_sig_bytes: [u8; 64] = tlv8_get(&sub, TLV_SIGNATURE)
            .context("M2 missing accessory signature")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("M2 signature must be 64 bytes"))?;

        let mut acc_info = Vec::with_capacity(32 + acc_id.len() + 32);
        acc_info.extend_from_slice(&server_pub_arr);
        acc_info.extend_from_slice(acc_id);
        acc_info.extend_from_slice(self.eph_public.as_bytes());
        let acc_sig = Signature::from_bytes(&acc_sig_bytes);
        self.server_vk
            .verify(&acc_info, &acc_sig)
            .map_err(|_| anyhow::anyhow!("pair-verify M2 server signature invalid"))?;

        // Build and sign M3 client info
        let mut dev_info = Vec::with_capacity(32 + self.client_id.len() + 32);
        dev_info.extend_from_slice(self.eph_public.as_bytes());
        dev_info.extend_from_slice(self.client_id.as_bytes());
        dev_info.extend_from_slice(&server_pub_arr);
        let sig = self.signing_key.sign(&dev_info).to_bytes();

        let m3_sub = tlv8_encode(&[
            (TLV_IDENTIFIER, self.client_id.as_bytes()),
            (TLV_SIGNATURE, &sig),
        ]);
        let m3_enc = cipher
            .encrypt(Nonce::from_slice(&hap_nonce_str(b"PV-Msg03")), m3_sub.as_slice())
            .map_err(|_| anyhow::anyhow!("pair-verify M3 encryption failed"))?;

        self.shared_secret = Some(shared);
        self.server_eph_public = Some(server_pub_arr);

        Ok(tlv8_encode(&[
            (TLV_STATE, &[0x03]),
            (TLV_ENCRYPTED_DATA, &m3_enc),
        ]))
    }

    pub fn process_m4(&self, m4_tlv: &[u8]) -> Result<[u8; 32]> {
        let items = tlv8_decode(m4_tlv)?;
        if let Some(err) = tlv8_get(&items, TLV_ERROR) {
            bail!("HAP pair-verify M4 returned error code: {:?}", err);
        }
        self.shared_secret
            .context("process_m4 called before process_m2")
    }
}

/// ChaCha20-Poly1305 encrypted framing for the AirPlay 2 RTSP/HTTP control & event channels.
pub struct HapControlCipher {
    write_cipher: ChaCha20Poly1305,
    read_cipher: ChaCha20Poly1305,
    write_counter: u64,
    read_counter: u64,
    read_buf: Vec<u8>,
}

impl HapControlCipher {
    pub fn from_shared_secret(shared_secret: &[u8]) -> Result<Self> {
        Self::from_salt_and_info(
            shared_secret,
            b"Control-Salt",
            b"Control-Write-Encryption-Key",
            b"Control-Read-Encryption-Key",
        )
    }

    pub fn from_events_secret(shared_secret: &[u8]) -> Result<Self> {
        // Events channel is reversed (device writes to us, we read from device)
        Self::from_salt_and_info(
            shared_secret,
            b"Events-Salt",
            b"Events-Read-Encryption-Key",
            b"Events-Write-Encryption-Key",
        )
    }

    fn from_salt_and_info(
        shared_secret: &[u8],
        salt: &[u8],
        write_info: &[u8],
        read_info: &[u8],
    ) -> Result<Self> {
        let write_key = hkdf_sha512_32(shared_secret, salt, write_info)?;
        let read_key = hkdf_sha512_32(shared_secret, salt, read_info)?;

        Ok(Self {
            write_cipher: ChaCha20Poly1305::new((&write_key).into()),
            read_cipher: ChaCha20Poly1305::new((&read_key).into()),
            write_counter: 0,
            read_counter: 0,
            read_buf: Vec::new(),
        })
    }

    fn make_nonce(counter: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&counter.to_le_bytes());
        nonce
    }

    /// Encrypt arbitrary plaintext into HAP 1024-byte-max framed blocks:
    /// `[len_le: u16][ciphertext: len][poly1305_tag: 16]`.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        const MAX_BLOCK: usize = 0x400;
        let mut out = Vec::with_capacity(plaintext.len() + (plaintext.len() / MAX_BLOCK + 1) * 18);
        for chunk in plaintext.chunks(MAX_BLOCK) {
            let len_le = (chunk.len() as u16).to_le_bytes();
            let nonce_bytes = Self::make_nonce(self.write_counter);
            let nonce = Nonce::from_slice(&nonce_bytes);
            let ct = self
                .write_cipher
                .encrypt(
                    nonce,
                    Payload {
                        msg: chunk,
                        aad: &len_le,
                    },
                )
                .map_err(|_| anyhow::anyhow!("HAP control channel encryption failed"))?;
            out.extend_from_slice(&len_le);
            out.extend_from_slice(&ct);
            self.write_counter += 1;
        }
        Ok(out)
    }

    /// Feed newly received encrypted bytes and decrypt any complete blocks.
    pub fn feed_and_decrypt(&mut self, incoming: &[u8]) -> Result<Vec<u8>> {
        self.read_buf.extend_from_slice(incoming);
        let mut plaintext = Vec::new();

        loop {
            if self.read_buf.len() < 2 {
                break;
            }
            let block_len = u16::from_le_bytes([self.read_buf[0], self.read_buf[1]]) as usize;
            let total_frame = 2 + block_len + 16;
            if self.read_buf.len() < total_frame {
                break;
            }
            let aad = [self.read_buf[0], self.read_buf[1]];
            let nonce_bytes = Self::make_nonce(self.read_counter);
            let nonce = Nonce::from_slice(&nonce_bytes);
            let pt = self
                .read_cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: &self.read_buf[2..total_frame],
                        aad: &aad,
                    },
                )
                .map_err(|_| anyhow::anyhow!("HAP control channel decryption failed"))?;
            plaintext.extend_from_slice(&pt);
            self.read_buf.drain(..total_frame);
            self.read_counter += 1;
        }
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlv8_roundtrip_large_fragmented_value() {
        let big = vec![0xABu8; 384];
        let encoded = tlv8_encode(&[(TLV_STATE, &[0x03]), (TLV_PUBLIC_KEY, &big)]);
        assert_eq!(encoded.len(), 3 + (2 + 255) + (2 + 129));
        let decoded = tlv8_decode(&encoded).unwrap();
        assert_eq!(tlv8_get(&decoded, TLV_STATE), Some(&[0x03][..]));
        assert_eq!(tlv8_get(&decoded, TLV_PUBLIC_KEY), Some(big.as_slice()));
    }

    #[test]
    fn hap_control_cipher_encrypt_decrypt_roundtrip() {
        let secret = [0x42u8; 64];
        let mut client = HapControlCipher::from_shared_secret(&secret).unwrap();
        let wk = hkdf_sha512_32(&secret, b"Control-Salt", b"Control-Write-Encryption-Key").unwrap();
        let rk = hkdf_sha512_32(&secret, b"Control-Salt", b"Control-Read-Encryption-Key").unwrap();
        let mut server = HapControlCipher {
            write_cipher: ChaCha20Poly1305::new((&rk).into()),
            read_cipher: ChaCha20Poly1305::new((&wk).into()),
            write_counter: 0,
            read_counter: 0,
            read_buf: Vec::new(),
        };

        let msg = vec![b'X'; 2500];
        let enc = client.encrypt(&msg).unwrap();
        let mut out = Vec::new();
        for c in enc.chunks(73) {
            out.extend_from_slice(&server.feed_and_decrypt(c).unwrap());
        }
        assert_eq!(out, msg);
    }
}
