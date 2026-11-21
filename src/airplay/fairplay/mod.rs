// SPDX-License-Identifier: GPL-3.0-or-later
// Portions ported from doubletake (https://github.com/omarroth/doubletake), LGPL-3.0-or-later.

//! FairPlay SAP (FPSAP) sender, as used by AirPlay screen mirroring.
//!
//! Handshake (both POSTs go to `/fp-setup` with `X-Apple-ET: 32`):
//!
//! 1. [`FpSapSession::message1`] → 16-byte m1 (fixed bytes, no randomness).
//! 2. Receiver answers with m2 (142 bytes: 12-byte FPLY header + 130 payload;
//!    payload byte 0 is `2`, byte 1 is the selected mode 0..=3, then the
//!    128-byte encrypted receiver SAP).
//! 3. [`FpSapSession::exchange_m3`] → 164-byte m3 (header + mode + label +
//!    128-byte encrypted sender SAP + 20-byte exchange tail).
//! 4. Receiver answers with m4 (32 bytes: header + 20-byte payload which must
//!    echo the m3 tail), checked by [`FpSapSession::confirm_m4`].
//! 5. [`FpSapSession::wrap_key`] wraps a 16-byte AES key into the 72-byte
//!    `ekey` sent in the SETUP plist.

mod crypto;
mod md5;
mod message;
mod sap;
mod sap_hash;
#[rustfmt::skip]
mod tables;

use anyhow::{bail, Context, Result};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha512};
use std::io::Read;

/// `X-Apple-ET` header value for the FairPlay encryption type this module implements.
#[allow(dead_code)]
pub const FAIRPLAY_ENCRYPTION_TYPE: &str = "32";

/// `std::io::Read` adapter over the OS CSPRNG.
struct OsEntropy;

impl Read for OsEntropy {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        OsRng.try_fill_bytes(buf).map_err(std::io::Error::other)?;
        Ok(buf.len())
    }
}

/// One FairPlay SAP context, kept for m1, m3 and `ekey` creation for the
/// lifetime of one authentication attempt.
pub struct FpSapSession {
    local_sap: [u8; 128],
    remote_sap: [u8; 128],
    m3: Option<[u8; sap::M3_LEN]>,
}

#[allow(dead_code)]
impl FpSapSession {
    /// Create a session whose local SAP is `00 01` followed by 126 bytes of OS randomness.
    pub fn new() -> Result<Self> {
        Self::with_entropy(&mut OsEntropy)
    }

    /// Create a session drawing the 126 opaque local-SAP bytes from `entropy`.
    pub(crate) fn with_entropy(entropy: &mut dyn Read) -> Result<Self> {
        let mut local_sap = [0u8; 128];
        local_sap[1] = 1;
        entropy
            .read_exact(&mut local_sap[2..])
            .context("initialize local SAP")?;
        Ok(Self {
            local_sap,
            remote_sap: [0; 128],
            m3: None,
        })
    }

    /// Body for the first `POST /fp-setup` (16 bytes, constant).
    pub fn message1(&self) -> Vec<u8> {
        sap::message1()
    }

    /// Consume the receiver's m2 and produce the 164-byte m3 body for the
    /// second `POST /fp-setup`.
    pub fn exchange_m3(&mut self, m2: &[u8]) -> Result<Vec<u8>> {
        let (m3, remote_sap) = sap::exchange_m3(&self.local_sap, m2)?;
        self.remote_sap = remote_sap;
        self.m3 = Some(m3);
        Ok(m3.to_vec())
    }

    /// Check the receiver's m4 (it must echo the 20-byte m3 tail).
    pub fn confirm_m4(&self, m4: &[u8]) -> Result<()> {
        let Some(m3) = &self.m3 else {
            bail!("m3 has not been generated");
        };
        sap::validate_m4(m4, m3)
    }

    /// Wrap `raw_key` into the 72-byte `ekey` record, using a random mask.
    pub fn wrap_key(&self, raw_key: [u8; 16]) -> Result<[u8; 72]> {
        self.wrap_key_with_entropy(raw_key, &mut OsEntropy)
    }

    /// Like [`Self::wrap_key`], drawing the 16-byte mask from `entropy`.
    pub(crate) fn wrap_key_with_entropy(&self, raw_key: [u8; 16], entropy: &mut dyn Read) -> Result<[u8; 72]> {
        let Some(m3) = &self.m3 else {
            bail!("m3 has not been generated");
        };
        crypto::wrap_key(&self.remote_sap, m3, &raw_key, entropy).context("wrap FairPlay key")
    }
}

/// The key the receiver decrypts the stream with, given the raw FairPlay key
/// that `ekey` wraps.
///
/// A HAP-paired receiver mixes the pair-verify secret in:
/// `SHA-512(raw_key || ecdh_secret)[..16]`. Otherwise (or if `secret` is
/// empty) the raw key is returned unchanged.
#[allow(dead_code)]
pub fn derive_stream_master_key(raw_key: &[u8], secret: &[u8], mix_pair_verify_secret: bool) -> Vec<u8> {
    if !mix_pair_verify_secret || secret.is_empty() {
        return raw_key.to_vec();
    }
    let mut h = Sha512::new();
    h.update(raw_key);
    h.update(secret);
    h.finalize()[..16].to_vec()
}

/// AES-128-CTR key/IV for mirroring video, per UxPlay `mirror_buffer.c`:
/// `SHA-512("AirPlayStreamKey<id>" || shk)[..16]` and
/// `SHA-512("AirPlayStreamIV<id>" || shk)[..16]`.
///
/// `<id>` is the stream connection ID formatted as an *unsigned* 64-bit
/// decimal (negative IDs are reinterpreted, matching the Go `uint64(id)`).
#[allow(dead_code)]
pub fn derive_video_keys(shk: &[u8], stream_connection_id: i64) -> ([u8; 16], [u8; 16]) {
    let id = stream_connection_id as u64;
    let digest = |label: &str| -> [u8; 16] {
        let mut h = Sha512::new();
        h.update(format!("{label}{id}").as_bytes());
        h.update(shk);
        h.finalize()[..16].try_into().unwrap()
    };
    (digest("AirPlayStreamKey"), digest("AirPlayStreamIV"))
}

/// 32-byte ChaCha20-Poly1305 key for mirroring data streams, via HKDF-SHA512:
/// IKM = `ikm` (pair-verify shared secret, or raw FairPlay key as fallback),
/// salt = `"DataStream-Salt" + decimal(id as u64)`,
/// info = `"DataStream-Output-Encryption-Key"`.
#[allow(dead_code)]
pub fn derive_chacha_key(ikm: &[u8], stream_connection_id: i64) -> Result<[u8; 32]> {
    let salt = format!("DataStream-Salt{}", stream_connection_id as u64);
    let hk = Hkdf::<Sha512>::new(Some(salt.as_bytes()), ikm);
    let mut key = [0u8; 32];
    hk.expand(b"DataStream-Output-Encryption-Key", &mut key)
        .map_err(|e| anyhow::anyhow!("hkdf expand: {e}"))?;
    Ok(key)
}

#[cfg(test)]
mod tests;
