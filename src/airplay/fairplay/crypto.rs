// SPDX-License-Identifier: GPL-3.0-or-later
// Portions ported from doubletake (https://github.com/omarroth/doubletake), LGPL-3.0-or-later.

//! FairPlay key-wrapping KDF and the 72-byte AirPlay v3 `ekey` record.

use super::md5::{self, Mutation};
use super::message::{decrypt_message, MODE_COUNT};
use super::sap::{descriptor_for_sap, validate_record, INITIAL_SESSION_KEY, M3_PAYLOAD_LEN};
use super::sap_hash::sap_hash;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::io::Read;

const KDF_PREFIX: [u8; 17] = [
    0xfa, 0x9c, 0xad, 0x4d, 0x4b, 0x68, 0x26, 0x8c, //
    0x7f, 0xf3, 0x88, 0x99, 0xde, 0x92, 0x2e, 0x95, 0x1e,
];

const KDF_SUFFIX: [u8; 17] = [
    0xec, 0x4e, 0x27, 0x5e, 0xfd, 0xf2, 0xe8, 0x30, //
    0x97, 0xae, 0x70, 0xfb, 0xe0, 0x00, 0x3f, 0x1c, 0x39,
];

const EKEY_HEADER: [u8; 16] = [
    b'F', b'P', b'L', b'Y', 0x01, 0x02, 0x01, 0x00, //
    0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00,
];

/// Derive the AES-128 key that wraps the raw FairPlay key, from the receiver
/// SAP and an FPLY message (m3) whose body is the sender SAP.
pub(super) fn derive_wrapping_key(receiver_sap: &[u8; 128], message: &[u8]) -> [u8; 16] {
    let mut decrypted = [0u8; 128];
    decrypt_message(message, &mut decrypted);

    // The KDF input is a 290-byte protocol record followed by ordinary MD5
    // padding. The compression itself is FairPlay's modified MD5/SAP-hash
    // combination, not a standard MD5 digest.
    let mut material = [0u8; 320];
    let mut offset = 0;
    for part in [&KDF_PREFIX[..], &decrypted[..], &receiver_sap[..], &KDF_SUFFIX[..]] {
        material[offset..offset + part.len()].copy_from_slice(part);
        offset += part.len();
    }
    material[offset] = 0x80;
    let bit_len = (offset as u64) * 8;
    material[320 - 8..].copy_from_slice(&bit_len.to_le_bytes());

    let mut state = md5::words_from_le(&INITIAL_SESSION_KEY);
    for block in material.chunks_exact(64) {
        let modified = md5::compress(state, block, Mutation::Kdf);
        let hashed = sap_hash(block);
        for (word, out) in state.iter_mut().enumerate() {
            *out = modified[word]
                .wrapping_add(u32::from_le_bytes(hashed[word * 4..word * 4 + 4].try_into().unwrap()));
        }
    }
    md5::words_to_be(state)
}

/// Emit the 72-byte AirPlay v3 encrypted-key record:
///
/// ```text
/// [0:16]  FPLY encrypted-key header
/// [16:32] per-key random mask
/// [32:36] big-endian raw-key length (16)
/// [36:56] HMAC-SHA1(session MAC key, record[0:36] || raw key)
/// [56:72] AES-128-ECB(wrapping key, raw key XOR mask)
/// ```
///
/// Both session keys depend on the receiver's decrypted m2 SAP.
pub(super) fn wrap_key(
    receiver_sap: &[u8; 128],
    m3: &[u8],
    raw_key: &[u8; 16],
    entropy: &mut dyn Read,
) -> Result<[u8; 72]> {
    validate_record(m3, 3, M3_PAYLOAD_LEN).context("invalid m3")?;
    let mode = m3[12];
    if mode as usize >= MODE_COUNT {
        bail!("unsupported FairPlay mode {mode}");
    }

    let mut ekey = [0u8; 72];
    ekey[..16].copy_from_slice(&EKEY_HEADER);
    entropy
        .read_exact(&mut ekey[16..32])
        .context("generate FairPlay key mask")?;
    ekey[32..36].copy_from_slice(&(raw_key.len() as u32).to_be_bytes());

    let wrapping_key = derive_wrapping_key(receiver_sap, m3);
    let cipher = Aes128::new(&wrapping_key.into());
    let mut masked = [0u8; 16];
    for i in 0..16 {
        masked[i] = raw_key[i] ^ ekey[16 + i];
    }
    let mut block = masked.into();
    cipher.encrypt_block(&mut block);
    ekey[56..72].copy_from_slice(&block);

    let mut sender_sap = [0u8; 128];
    decrypt_message(m3, &mut sender_sap);
    let mac_key = descriptor_for_sap(&sender_sap, receiver_sap);
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&mac_key).expect("HMAC accepts any key length");
    mac.update(&ekey[..36]);
    mac.update(raw_key);
    ekey[36..56].copy_from_slice(&mac.finalize().into_bytes());
    Ok(ekey)
}
