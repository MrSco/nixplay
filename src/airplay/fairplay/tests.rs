// SPDX-License-Identifier: GPL-3.0-or-later
// Portions ported from doubletake (https://github.com/omarroth/doubletake), LGPL-3.0-or-later.

//! Golden-vector tests ported from doubletake's fpsap_test.go,
//! fairplay_vectors_test.go, fairplay_key_test.go and fairplay_streamkey_test.go.

use super::crypto::{derive_wrapping_key, wrap_key};
use super::md5::{self, Mutation};
use super::message::{decrypt_body, decrypt_message, encrypt_message};
use super::sap::{descriptor_for_sap, exchange_for_sap, new_record, validate_m4};
use super::sap_hash::sap_hash;
use super::tables::{NetworkTables, FIRST_INPUT_MASK, FIRST_TABLES, SECOND_TABLES};
use super::*;
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes128;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn require_hex(name: &str, got: &[u8], want: &str) {
    assert_eq!(hex::encode(got), want, "{name}");
}

fn unwrap_key_for_test(receiver_sap: &[u8; 128], m3: &[u8], ekey: &[u8]) -> [u8; 16] {
    let aes_key = derive_wrapping_key(receiver_sap, m3);
    let cipher = Aes128::new(&aes_key.into());
    let mut block: [u8; 16] = ekey[56..72].try_into().unwrap();
    let mut b = block.into();
    cipher.decrypt_block(&mut b);
    block.copy_from_slice(&b);
    for i in 0..16 {
        block[i] ^= ekey[16 + i];
    }
    block
}

fn filled_payload(value: u8) -> [u8; 128] {
    [value; 128]
}

fn sparse_payload(index: usize) -> [u8; 128] {
    let mut p = [0u8; 128];
    p[index] = 0x42;
    p
}

/// SAP test vector recovered from the old post-m1 emulator snapshot.
fn reference_local_sap() -> [u8; 128] {
    unhex(concat!(
        "0001e4e3dd688293e6fa66b95ba41768e587c65f750218ff1be21543d573cefb",
        "087bd36e0c6363c3c8242f4abcfa6d660b801032015405eb4ab04dda7aeff38f",
        "fb36f4cfa48f0b5d92ae363f68b45925bbe6413ab6bdc4968f548d21e67d20f",
        "1912b6820e53f1013cde29df7350a9b9fa7c51320aea62d2949786c87642e34ba"
    ))
    .try_into()
    .unwrap()
}

/// Receiver SAP from the independent playfair_decrypt reference vector.
fn reference_receiver_sap() -> [u8; 128] {
    unhex(concat!(
        "0001cc342a5e5b1a6773c20e21b8224df862481864ef810aae2e3703c8819c23",
        "539de5f5d749bc5b7a266c496283ce7f03937ae1f616de0c15ff338ccaffb09e",
        "aabbe40f5d5f558fb97f1731f8f7da60a0ec6579c33ea98312c3b67135a6694f",
        "f82305d9ba5c615fa254d2b1834583cee42d4426c835a7a5f6c8421c0da3f1c7"
    ))
    .try_into()
    .unwrap()
}

fn test_m3(mode: u8) -> Vec<u8> {
    let mut m3 = vec![0u8; 164];
    m3[..4].copy_from_slice(b"FPLY");
    m3[4..8].copy_from_slice(&[3, 1, 3, 0]);
    m3[8..12].copy_from_slice(&152u32.to_be_bytes());
    m3[12] = mode;
    for i in 13..m3.len() {
        m3[i] = (i * 7 + 3) as u8;
    }
    m3
}

fn test_receiver_sap(seed: u8) -> [u8; 128] {
    let mut sap = [0u8; 128];
    sap[1] = 1;
    for i in 2..128 {
        sap[i] = ((i * 11) as u8) ^ seed;
    }
    sap
}

fn counting_entropy() -> Vec<u8> {
    (0..126).map(|i| (i + 1) as u8).collect()
}

// ---- fpsap_test.go ----

#[test]
fn fpsap_table_data() {
    const WANT: &str = "28d0986abebe30458348dfa2957aa1d52d6f3ad5a9468c5d8a9c4139b7ca2b43";
    let mut hash = Sha256::new();
    let mut written = 0usize;
    let mut write = |data: &[u8]| {
        hash.update(data);
        written += data.len();
    };
    write(&FIRST_INPUT_MASK);
    for tables in [&FIRST_TABLES, &SECOND_TABLES] as [&NetworkTables; 2] {
        for round in &tables.round_substitution {
            for lookup in round {
                let expanded: Vec<u8> = (0..=255u8).map(|v| lookup.substitute(v)).collect();
                write(&expanded);
            }
        }
        for input_table in &tables.mix_columns {
            let mut expanded = [0u8; 256 * 4];
            for value in 0..256usize {
                for (output_byte, lookup) in input_table.iter().enumerate() {
                    expanded[value * 4 + output_byte] = lookup.mix(value as u8);
                }
            }
            write(&expanded);
        }
        for lookup in &tables.final_substitution {
            let expanded: Vec<u8> = (0..=255u8).map(|v| lookup.substitute(v)).collect();
            write(&expanded);
        }
    }
    assert_eq!(written, 90128);
    assert_eq!(hex::encode(hash.finalize()), WANT);
}

#[test]
fn fpsap_exchange_golden_vectors() {
    let captured_m2 = unhex("46504c59030102000000008202034a114c26b77d4e2eec2c8f89fdb653b5b32d3576bc176816d110a14c3f53c08dbb936183bfdfe0a4f3c12e85216003b46f738c40c54da6c436d29d1b342d63c7b314309ae79a33bb1787709ef077cbfe4190117a3423e270fd1a2eac44da1a7934f59dc681d1b70783f228c4d077c2d495f5285c3bf8df586fc2ebfe17fb5b65");
    let captured: [u8; 128] = captured_m2[14..142].try_into().unwrap();
    let cases: [(&str, [u8; 128], &str); 7] = [
        ("all-zeros", [0; 128], "6f627565f3e77f5b5ede91beee7baf92e4241e0b"),
        ("all-ff", filled_payload(0xff), "dc2cc74f2ed55484f59f95b96082f0f5c017dd17"),
        ("captured-m2", captured, "4b911e48af23d8406368aeafbb61bfcd569e3e55"),
        ("42-at-0", sparse_payload(0), "9bfb9556b8659c2ac94b7ef9e587d71e159ea624"),
        ("42-at-63", sparse_payload(63), "150d9fa4eb456e73ba48de5779c5c996b16b3b23"),
        ("42-at-64", sparse_payload(64), "a167db30424ff8890d085c0f1c92b2c5cc06fc45"),
        ("42-at-127", sparse_payload(127), "d246ec5e7adc8118994b8df77146529486ac7caf"),
    ];
    for (name, payload, want) in cases {
        let got = exchange_for_sap(&reference_local_sap(), &decrypt_body(3, &payload).unwrap());
        require_hex(name, &got, want);
    }
}

#[test]
fn fpsap_descriptor() {
    let mut one = [0u8; 128];
    one[0] = 1;
    let cases: [(&str, [u8; 128], &str); 2] = [
        ("zero", [0; 128], "7e38958ffe4ed433743919fe7eb16376afa4eb9e"),
        ("one-at-zero", one, "ea46797d726c6a9be43ffa72385ff97ce1c54f1b"),
    ];
    for (name, payload, want) in cases {
        let got = descriptor_for_sap(&reference_local_sap(), &decrypt_body(3, &payload).unwrap());
        require_hex(name, &got, want);
    }
}

#[test]
fn fpsap_session_exchange() {
    let mut m2 = vec![0u8; 142];
    m2[..4].copy_from_slice(b"FPLY");
    m2[4..8].copy_from_slice(&[3, 1, 2, 0]);
    m2[8..12].copy_from_slice(&130u32.to_be_bytes());
    m2[12] = 2;
    m2[13] = 3;
    let entropy = counting_entropy();
    let mut session = FpSapSession::with_entropy(&mut &entropy[..]).unwrap();
    require_hex("m1", &session.message1(), "46504c590301010000000004020003bb");

    let m3 = session.exchange_m3(&m2).unwrap();
    assert_eq!(m3.len(), 164);
    assert_eq!(&m3[..4], b"FPLY");
    let mut got_sap = [0u8; 128];
    decrypt_message(&m3, &mut got_sap);
    let mut want_sap = [0u8; 128];
    want_sap[1] = 1;
    want_sap[2..].copy_from_slice(&entropy);
    assert_eq!(got_sap, want_sap, "m3 SAP");

    let m2_ciphertext: [u8; 128] = m2[14..].try_into().unwrap();
    let want_receiver_sap = decrypt_body(3, &m2_ciphertext).unwrap();
    assert_eq!(session.remote_sap, want_receiver_sap, "stored receiver SAP");
    let want_tail = exchange_for_sap(&want_sap, &want_receiver_sap);
    assert_eq!(&m3[144..], &want_tail[..], "m3 tail");

    let raw_key: [u8; 16] = core::array::from_fn(|i| i as u8);
    let mask = [0x5au8; 16];
    let ekey = session.wrap_key_with_entropy(raw_key, &mut &mask[..]).unwrap();
    assert_eq!(unwrap_key_for_test(&want_receiver_sap, &m3, &ekey), raw_key);
    // The OS-randomness path must also round-trip.
    let ekey = session.wrap_key(raw_key).unwrap();
    assert_eq!(unwrap_key_for_test(&want_receiver_sap, &m3, &ekey), raw_key);

    assert!(session.exchange_m3(&[0u8; 141]).is_err(), "short m2 was accepted");
    for mode in [4u8, 0xff] {
        let mut bad = m2.clone();
        bad[13] = mode;
        assert!(session.exchange_m3(&bad).is_err(), "m2 with unsupported mode {mode} was accepted");
    }
    assert!(
        FpSapSession::with_entropy(&mut &entropy[..125]).is_err(),
        "short entropy source was accepted"
    );

    let other_entropy = [0xa5u8; 126];
    let mut other = FpSapSession::with_entropy(&mut &other_entropy[..]).unwrap();
    let other_m3 = other.exchange_m3(&m2).unwrap();
    assert_ne!(&m3[16..144], &other_m3[16..144], "distinct sessions reused the same m3 body");

    // FpSapSession::new() draws OS randomness; two sessions must differ.
    let mut a = FpSapSession::new().unwrap();
    let mut b = FpSapSession::new().unwrap();
    assert_ne!(a.exchange_m3(&m2).unwrap(), b.exchange_m3(&m2).unwrap());
}

#[test]
fn fpsap_session_uses_receiver_selected_mode() {
    let mut receiver_sap = [0u8; 128];
    receiver_sap[1] = 1;
    for i in 2..128 {
        receiver_sap[i] = (i * 7 + 3) as u8;
    }
    let entropy = counting_entropy();
    let mut want_local_sap = [0u8; 128];
    want_local_sap[1] = 1;
    want_local_sap[2..].copy_from_slice(&entropy);

    for mode in 0u8..=3 {
        let mut m2 = new_record(2, 130);
        m2[12] = 2;
        m2[13] = mode;
        encrypt_message(mode, &receiver_sap, &mut m2[14..142]).unwrap();

        let mut session = FpSapSession::with_entropy(&mut &entropy[..]).unwrap();
        let m3 = session.exchange_m3(&m2).unwrap();
        assert_eq!(m3[12], mode, "m3 mode");

        let mut got_local_sap = [0u8; 128];
        decrypt_message(&m3, &mut got_local_sap);
        assert_eq!(got_local_sap, want_local_sap, "mode {mode}: m3 SAP");
        assert_eq!(session.remote_sap, receiver_sap, "mode {mode}: stored receiver SAP");
        let want_tail = exchange_for_sap(&want_local_sap, &receiver_sap);
        assert_eq!(&m3[144..], &want_tail[..], "mode {mode}: m3 tail");
    }
}

#[test]
fn validate_fpsap_m4() {
    let mut m3 = [0u8; 164];
    for i in 144..164 {
        m3[i] = i as u8;
    }
    let mut m4 = vec![0u8; 32];
    m4[..4].copy_from_slice(b"FPLY");
    m4[4..8].copy_from_slice(&[3, 1, 4, 0]);
    m4[8..12].copy_from_slice(&20u32.to_be_bytes());
    m4[12..].copy_from_slice(&m3[144..]);

    validate_m4(&m4, &m3).expect("valid m4 rejected");
    let session = FpSapSession {
        local_sap: [0; 128],
        remote_sap: [0; 128],
        m3: Some(m3),
    };
    session.confirm_m4(&m4).expect("session rejected valid m4");
    m4[31] ^= 1;
    assert!(validate_m4(&m4, &m3).is_err(), "mismatched m4 accepted");
    assert!(session.confirm_m4(&m4).is_err(), "session accepted mismatched m4");
}

#[test]
fn fpsap_session_requires_m3() {
    let zeros = [0u8; 126];
    let session = FpSapSession::with_entropy(&mut &zeros[..]).unwrap();
    assert!(session.confirm_m4(&[0u8; 32]).is_err(), "m4 confirmed before m3");
    let mask = [0u8; 36];
    assert!(
        session.wrap_key_with_entropy([0; 16], &mut &mask[..]).is_err(),
        "key wrapped before m3"
    );
    assert!(session.wrap_key([0; 16]).is_err(), "key wrapped before m3");
}

// ---- fairplay_vectors_test.go ----

#[test]
fn fairplay_primitive_vectors() {
    let block: [u8; 64] = core::array::from_fn(|i| (i * 3 + 1) as u8);
    let key: [u8; 16] = core::array::from_fn(|i| i as u8);

    let words = md5::compress(md5::words_from_le(&key), &block, Mutation::Kdf);
    let mut modified = [0u8; 16];
    for (i, w) in words.iter().enumerate() {
        modified[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    require_hex("modified MD5", &modified, "f6f728cb5a4397b675664f9291b859aa");
    require_hex("SAP hash", &sap_hash(&block), "75498a4e218773030e9cdf04f0c49367");
}

#[test]
fn fairplay_sap_hash_corpus() {
    // Aggregate generated independently by the upstream C reference implementation.
    let mut corpus = Sha256::new();
    let mut state: u64 = 0x6a09e667f3bcc909;
    for _ in 0..64 {
        let mut block = [0u8; 64];
        for b in block.iter_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *b = state as u8;
        }
        corpus.update(sap_hash(&block));
    }
    require_hex(
        "SAP hash corpus",
        &corpus.finalize(),
        "36ad2a7920076af59452d9f0c91e3b7d1aebc53f9143bd6819e39119d4535c92",
    );
}

#[test]
fn fairplay_message_vectors() {
    let cases: [(u8, &str, &str); 4] = [
        (0, "b66a3295ffa6b56e02ed1b3d67fef74b90fe148570de65e6773669126a4905d8405644cae0b2f5ed6109c099c7aea7398dac8d623fbd69b87242b374d98f89502bb5a63e29c46a8ed0e98466966191ec1e6c8675087fde21337db1c8fab4c21db824026335f6fc37e2e5b6f53357d06994bd383d6029a0aff654fb1521bcdde4", "f7dd1ccb9e745f7951a6e325d73a1f5f"),
        (1, "0f95c6ddc8987eda18577da2db074e7c04715af8b3914a73be1b3d6c111953017ee0a39dfcab3e0d57f2f9fbd59c5e18101788c2ab8e3cbb403bcb48b53f3e5bf74f949e79fa5ca679df4bfcb33a69b1442675d03f948fe5bd0c5ffb64b73a5ab58f46d6baae097b599624147c2487991163ecffc4d966240f9526346a10fdb0", "b44ad891396f097aa309bc132f5b8889"),
        (2, "40f18751b44d733e0aa0416401a7d3f40375fad3ce56900602578bca14660909820e6ef3a5e943cafef5370f72c52177d9b82278b414811201a3d99202bedcca26a4d1ad08bc2669f4bae6ca54b8a120d0425edb6082f51f5aecdb547bfdb319099c9ea2729ae6a1c4480827ce9991e273843cf1c7d74ebbebc2657659bcea9f", "d38cd8efecdb20f333273c4312d9b236"),
        (3, "70a3c30edf0e1dfa1785ce4336ed547062672a47f714a0c1f89a83d95691103dfe5cf653d4cb8299793faf33fd0d4482ef5333b41ab094a90e1baf996bcf4989783f6918397fbacddaf00a2b97556dd8099841578bc5eb1444912b47298eaf356fdd6701bb3f64e725a80eb4c6f3556195de35c93e7cc703bdd24351468e9847", "769e2fe4c5ad7fbe6fd6772d00f529f4"),
    ];
    for (mode, want_decrypted, want_aes_key) in cases {
        let mut message = vec![0u8; 164];
        message[12] = mode;
        for i in 16..144 {
            message[i] = (i * 5 + 7) as u8;
        }
        let mut decrypted = [0u8; 128];
        decrypt_message(&message, &mut decrypted);
        require_hex("decrypted message", &decrypted, want_decrypted);

        let mut encrypted = [0u8; 128];
        encrypt_message(mode, &decrypted, &mut encrypted).unwrap();
        assert_eq!(&encrypted[..], &message[16..144], "mode {mode}: encrypted message");

        // Go also checks in-place decryption for mode 3; Rust's borrow rules
        // forbid aliasing, so check that decrypting into the frame's own body
        // (via a copy) yields the same plaintext.
        if mode == 3 {
            let mut in_place = message.clone();
            let src = in_place.clone();
            decrypt_message(&src, &mut in_place[16..144]);
            require_hex("in-place decrypted message", &in_place[16..144], want_decrypted);
        }

        let aes_key = derive_wrapping_key(&reference_receiver_sap(), &message);
        require_hex("AES key", &aes_key, want_aes_key);
    }
}

#[test]
fn fairplay_key_unwrap_vector() {
    let mut m3 = vec![0u8; 164];
    m3[12] = 3;
    for i in 16..144 {
        m3[i] = (i * 5 + 7) as u8;
    }
    let ekey: [u8; 72] = core::array::from_fn(|i| (i * 7 + 3) as u8);
    let got = unwrap_key_for_test(&reference_receiver_sap(), &m3, &ekey);
    require_hex("FairPlay key", &got, "903e5be94732428e9965afb262b193a4");
}

// ---- fairplay_key_test.go ----

#[test]
fn fairplay_key_wrap_round_trip() {
    for mode in 0u8..=3 {
        let m3 = test_m3(mode);
        let receiver_sap = test_receiver_sap(mode);
        let raw_key = [
            0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, //
            0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, mode,
        ];
        let entropy: [u8; 16] = core::array::from_fn(|i| (i + 1) as u8);

        let ekey = wrap_key(&receiver_sap, &m3, &raw_key, &mut &entropy[..]).unwrap();
        require_hex("ekey header", &ekey[..16], "46504c59010201000000003c00000000");
        assert_eq!(u32::from_be_bytes(ekey[32..36].try_into().unwrap()), 16);
        assert_eq!(&ekey[16..32], &entropy[..], "ekey mask");

        let mut sender_sap = [0u8; 128];
        decrypt_message(&m3, &mut sender_sap);
        let mac_key = descriptor_for_sap(&sender_sap, &receiver_sap);
        let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&mac_key).unwrap();
        mac.update(&ekey[..36]);
        mac.update(&raw_key);
        mac.verify_slice(&ekey[36..56]).expect("ekey MAC mismatch");
        assert_eq!(unwrap_key_for_test(&receiver_sap, &m3, &ekey), raw_key, "mode {mode}");
    }
}

#[test]
fn fairplay_key_wrap_rejects_invalid_input() {
    let receiver_sap = test_receiver_sap(3);
    let zeros = [0u8; 16];
    assert!(
        wrap_key(&receiver_sap, &[0u8; 143], &[0; 16], &mut &zeros[..]).is_err(),
        "short m3 accepted"
    );
    let mut m3 = test_m3(3);
    m3[12] = 4;
    assert!(
        wrap_key(&receiver_sap, &m3, &[0; 16], &mut &zeros[..]).is_err(),
        "unsupported mode accepted"
    );
    assert!(
        wrap_key(&receiver_sap, &test_m3(3), &[0; 16], &mut &zeros[..15]).is_err(),
        "short entropy accepted"
    );
}

#[test]
fn fairplay_alternate_mac_vector() {
    // Checks the authenticated prefix only; the alternate path uses a
    // different final key transform from AirPlay v3.
    let m2 = unhex("46504c5903010200000000820201cf32a25714b2524f8aa0ad7af164e37bcf4424e200047efc0ad67afcd95ded1c2730bb591b962ed63a9c4ded88ba8fc78de64d91ccfd5c7b56da88e31f5cceafc7431995a01665a54e1939d25b94db64b9e45d8d063e1e6af07e9656162b0efa404275ea5a44d9591c7256b9fbe6513898b80227721988571650942ad946688a");
    let m3 = unhex("46504c590301030000000098018f1a9c5b9228300aafe0b41f28b66a62a6cd62bf84eb623273dead10b1f034a8d568126faa133f6ad5ab91acda3839817b4d9530b679fee43ac9e950f6e7aaf1381bd2d3d5198a03bf5648890d19234270a3583e4651893be09c6c75463c42e544fec9abc9f7722a2cc254364365ef91ded76b8c00f9674b08920fb9401e4be6d52a33f2f9ed6fadb672be45c3cde5ad94f3fea5b32ee4");
    let raw_key: [u8; 16] = unhex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
    let mask = unhex("c853e777b9b65e7652d768d97c974f15");

    let mut m2_frame = vec![0u8; 144];
    m2_frame[12] = m2[13];
    m2_frame[16..].copy_from_slice(&m2[14..]);
    let mut receiver_sap = [0u8; 128];
    decrypt_message(&m2_frame, &mut receiver_sap);
    assert_eq!(receiver_sap, reference_receiver_sap(), "upstream receiver SAP");

    let ekey = wrap_key(&receiver_sap, &m3, &raw_key, &mut &mask[..]).unwrap();
    require_hex(
        "authenticated ekey prefix",
        &ekey[..56],
        "46504c59010201000000003c00000000c853e777b9b65e7652d768d97c974f15000000102a53a0008888fe26bfb1e1f825f38f50d6730059",
    );
    let mut sender_sap = [0u8; 128];
    decrypt_message(&m3, &mut sender_sap);
    let mac_key = descriptor_for_sap(&sender_sap, &receiver_sap);
    require_hex("session MAC key", &mac_key, "2fd95dc2c23122bc77c57b983a9188c4760db322");
}

#[test]
fn fairplay_key_decrypt_vector() {
    // Also exercised by the C playfair_decrypt path.
    let m3 = unhex("46504c590301030000000098018f1a9c7d0af257b31f21f5c2d2bc814c032d457835ad0b06250574bbc7ab4a58cca6eead2c911d7f3e1e7ed4c058955dff3d5ceef014387a985bdb34995015e3dfbdacc56047cb926e093b13e9fdb5e1eee317c018bbc87fc5453c7671647da686da3d564875d03f8aea9d60092de06110bc7be0c16f391c369c75344ae47f33acfcf10e63a9b58bfce215e96001c49e4be967c5067f2a");
    let ekey = unhex("46504c59010201000000003c0000000088e4f82c8178c18b4751ac24b27c0c2a00000010c899dc6965c1081de6a9d966e2ba3e34548cdbc651c322db18dc22f58fe154a60aecee18");
    assert_eq!(u32::from_be_bytes(ekey[32..36].try_into().unwrap()), 16);
    let got = unwrap_key_for_test(&reference_receiver_sap(), &m3, &ekey);
    require_hex("captured raw key", &got, "8e1214398d46d72e7b1b8e32f80c8bf0");
}

// ---- fairplay_streamkey_test.go ----

#[test]
fn fairplay_derive_stream_master_key() {
    let raw = [0xa5u8; 16];
    let secret = [0x5au8; 32];
    let mut h = Sha512::new();
    h.update(raw);
    h.update(secret);
    let mixed = h.finalize()[..16].to_vec();

    let cases: [(&str, &[u8], bool, &[u8]); 4] = [
        ("physical legacy receiver, secret present", &secret, false, &raw),
        ("physical legacy receiver, no secret", &[], false, &raw),
        ("HAP or UxPlay pairing", &secret, true, &mixed),
        ("mix requested but no secret", &[], true, &raw),
    ];
    for (name, secret, mix, want) in cases {
        assert_eq!(derive_stream_master_key(&raw, secret, mix), want, "{name}");
    }
}

#[test]
fn fairplay_derive_stream_master_key_branches_differ() {
    let raw = [0xa5u8; 16];
    let secret = [0x5au8; 32];
    assert_ne!(
        derive_stream_master_key(&raw, &secret, false),
        derive_stream_master_key(&raw, &secret, true)
    );
}

// ---- mirror.go helpers (vectors computed independently with Python hashlib/hmac) ----

#[test]
fn fairplay_derive_video_keys() {
    let shk: Vec<u8> = (0..32u8).collect();
    let (key, iv) = derive_video_keys(&shk, 1234567890123);
    require_hex("video key", &key, "5a878b2cced1d3d80edb6325a78e2fe1");
    require_hex("video iv", &iv, "23ddf84a2cdc6421d916d341d7b078d2");
    // Negative IDs are formatted as unsigned 64-bit (Go uint64(id)).
    let (key, iv) = derive_video_keys(&shk, -1);
    require_hex("video key (-1)", &key, "18c030b8c5ec61b83047948eee7475e7");
    require_hex("video iv (-1)", &iv, "05b18abb311252e5e0f67dd1a1b0c73e");
}

#[test]
fn fairplay_derive_chacha_key() {
    let ikm: Vec<u8> = (0..32u8).collect();
    let key = derive_chacha_key(&ikm, 1234567890123).unwrap();
    require_hex("chacha key", &key, "9307fb9842674fe68d821434309568d6b74c1e0ee97b1019af355ae52507a2aa");
    let key = derive_chacha_key(&ikm, -1).unwrap();
    require_hex("chacha key (-1)", &key, "738dbafeb6b578a77b07323adcf09867ec5921aac04031c4d6415974b6c5a80c");
}
