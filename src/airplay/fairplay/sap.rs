// SPDX-License-Identifier: GPL-3.0-or-later
// Portions ported from doubletake (https://github.com/omarroth/doubletake), LGPL-3.0-or-later.

//! FairPlay SAP (FPSAP) sender-side handshake: m1, m3 and the white-box
//! exchange that produces the 20-byte m3 tail (echoed back by the receiver in m4).

use super::md5::{self, Mutation};
use super::message::{decrypt_body, encrypt_message, MODE_COUNT};
use super::sap_hash::sap_hash;
use super::tables::{NetworkTables, FIRST_INPUT_MASK, FIRST_TABLES, SECOND_OUTPUT_MASK, SECOND_TABLES};
use anyhow::{bail, Context, Result};

/// This m1 capability byte is a bit mask, not the message mode. All available
/// capabilities produce 3; the receiver selects mode 0..3 in m2.
const M1_CAPABILITIES: u8 = 3;
const M1_PAYLOAD: [u8; 4] = [0x02, 0x00, M1_CAPABILITIES, 0xbb];

const M3_LABEL: [u8; 3] = [0x8f, 0x1a, 0x9c];

const DESCRIPTOR_PREFIX: [u8; 17] = [
    0xa0, 0x44, 0x9c, 0x4d, 0x09, 0xe4, 0xbd, 0x7f, 0x6e, //
    0xc5, 0xd0, 0xcc, 0x35, 0x9d, 0xa7, 0x46, 0x7a,
];

const DESCRIPTOR_SUFFIX: [u8; 17] = [
    0x97, 0xb5, 0x0f, 0x84, 0xe2, 0x15, 0x5a, 0x9c, 0x24, //
    0x99, 0x1c, 0xf4, 0x3a, 0x09, 0x63, 0x55, 0x47,
];

const FIXED_BLOCK: [u8; 16] = [
    0xaf, 0xc2, 0x2b, 0xa0, 0x49, 0xef, 0xfc, 0xfb, //
    0xfe, 0x67, 0xac, 0x5e, 0xbe, 0xf6, 0xfb, 0xcb,
];

const FIRST_POSITION_MAP: [usize; 16] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];
const SECOND_POSITION_MAP: [usize; 16] = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3];

pub(super) const INITIAL_SESSION_KEY: [u8; 16] = [
    0xdc, 0xdc, 0xf3, 0xb9, 0x0b, 0x74, 0xdc, 0xfb, //
    0x86, 0x7f, 0xf7, 0x60, 0x16, 0x72, 0x90, 0x51,
];

pub(super) const M1_LEN: usize = 12 + M1_PAYLOAD.len();
pub(super) const M2_PAYLOAD_LEN: usize = 130;
pub(super) const M3_PAYLOAD_LEN: usize = 152;
pub(super) const M3_LEN: usize = 12 + M3_PAYLOAD_LEN;
pub(super) const M4_PAYLOAD_LEN: usize = 20;

pub(super) fn message1() -> Vec<u8> {
    let mut m1 = new_record(1, M1_PAYLOAD.len());
    m1[12..].copy_from_slice(&M1_PAYLOAD);
    debug_assert_eq!(m1.len(), M1_LEN);
    m1
}

/// Derive the white-box seed (also the HMAC key for ekey) from both halves of
/// an exchange: the sender SAP sent in m3 and the receiver SAP decrypted from m2.
pub(super) fn descriptor_for_sap(m3_sap: &[u8; 128], m2_sap: &[u8; 128]) -> [u8; 20] {
    let mut padded = [0u8; 320];
    let mut offset = 0;
    for part in [&DESCRIPTOR_PREFIX[..], &m3_sap[..], &m2_sap[..], &DESCRIPTOR_SUFFIX[..]] {
        padded[offset..offset + part.len()].copy_from_slice(part);
        offset += part.len();
    }
    padded[offset] = 0x80;
    let bit_len = (offset as u64) * 8;
    padded[320 - 8..].copy_from_slice(&bit_len.to_le_bytes());

    let mut state = md5::words_from_le(&INITIAL_SESSION_KEY);
    let mut first_final = [0u32; 4];
    for block_offset in (0..padded.len()).step_by(64) {
        let block = &padded[block_offset..block_offset + 64];
        let add = sap_hash(block);
        for (i, word) in state.iter_mut().enumerate() {
            *word = word.wrapping_add(u32::from_le_bytes(add[i * 4..i * 4 + 4].try_into().unwrap()));
        }
        state = md5::compress(state, block, Mutation::Cycle);
        if block_offset == padded.len() - 64 {
            first_final = state;
            state = md5::compress(state, block, Mutation::Cycle);
        }
    }

    let mut out = [0u8; 20];
    out[..4].copy_from_slice(&first_final[0].to_be_bytes());
    out[4..].copy_from_slice(&md5::words_to_be(state));
    out
}

fn masks(seed: &[u8; 20]) -> [[u8; 16]; 9] {
    let state = [0x1d4a4587u32, 0x92f39fcc, 0x1d87d836, 0xcdc86697];
    const SUFFIX: [u8; 15] = [
        0x57, 0xd8, 0xee, 0xcb, 0xde, 0xfb, 0xcf, 0x59, //
        0x1c, 0x27, 0xa2, 0xcf, 0xbe, 0xb0, 0x89,
    ];
    let mut masks = [[0u8; 16]; 9];
    for (i, mask) in masks.iter_mut().enumerate() {
        let mut block = [0u8; 64];
        block[..20].copy_from_slice(seed);
        block[20] = i as u8;
        block[21..36].copy_from_slice(&SUFFIX);
        block[36] = 0x80;
        block[56..60].copy_from_slice(&0x320u32.to_le_bytes());
        *mask = md5::words_to_be(md5::compress(state, &block, Mutation::Swap));
    }
    masks
}

fn digest32(left: &[u8; 16], right: &[u8; 16]) -> [u8; 16] {
    let mut block = [0u8; 64];
    block[..16].copy_from_slice(left);
    block[16..32].copy_from_slice(right);
    block[32] = 0x80;
    block[56..60].copy_from_slice(&0x100u32.to_le_bytes());
    let state = [0xb9f3dcdcu32, 0xfbdc740b, 0x60f77f86, 0x51907216];
    md5::words_to_be(md5::compress(state, &block, Mutation::Swap))
}

fn first_network(masks: &[[u8; 16]; 9]) -> [u8; 16] {
    let tables = &FIRST_TABLES;
    let mut state = FIXED_BLOCK;
    for (s, m) in state.iter_mut().zip(FIRST_INPUT_MASK.iter()) {
        *s ^= m;
    }
    for (bank, mask) in masks.iter().enumerate() {
        let mut substituted = [0u8; 16];
        for (output, &input) in FIRST_POSITION_MAP.iter().enumerate() {
            substituted[output] = tables.round_substitution[bank][input].substitute(state[input]);
        }
        mix(tables, &mut state, &substituted);
        for (s, m) in state.iter_mut().zip(mask.iter()) {
            *s ^= m;
        }
    }
    let mut out = [0u8; 16];
    for (output, &input) in FIRST_POSITION_MAP.iter().enumerate() {
        out[output] = tables.final_substitution[input].substitute(state[input]);
    }
    out
}

fn second_network(mut state: [u8; 16], masks: &[[u8; 16]; 9]) -> [u8; 16] {
    let tables = &SECOND_TABLES;
    for bank in (0..9).rev() {
        let mut substituted = [0u8; 16];
        for (output, &input) in SECOND_POSITION_MAP.iter().enumerate() {
            substituted[output] = tables.round_substitution[bank][output].substitute(state[input])
                ^ masks[bank][output];
        }
        mix(tables, &mut state, &substituted);
    }
    let mut out = [0u8; 16];
    for (output, &input) in SECOND_POSITION_MAP.iter().enumerate() {
        out[output] = tables.final_substitution[output].substitute(state[input]) ^ SECOND_OUTPUT_MASK[output];
    }
    out
}

fn mix(tables: &NetworkTables, state: &mut [u8; 16], substituted: &[u8; 16]) {
    for word in 0..4 {
        let offset = word * 4;
        for output_byte in 0..4 {
            let mut mixed = 0u8;
            for input_byte in 0..4 {
                mixed ^= tables.mix_columns[input_byte][output_byte].mix(substituted[offset + input_byte]);
            }
            state[offset + output_byte] = mixed;
        }
    }
}

pub(super) fn exchange_for_sap(m3_sap: &[u8; 128], m2_sap: &[u8; 128]) -> [u8; 20] {
    exchange_seed(&descriptor_for_sap(m3_sap, m2_sap))
}

fn exchange_seed(seed: &[u8; 20]) -> [u8; 20] {
    let masks = masks(seed);
    let intermediate = first_network(&masks);
    let left = digest32(&intermediate, &FIXED_BLOCK);
    let whitebox_output = second_network(left, &masks);
    let digest = digest32(&left, &whitebox_output);

    let mut out = [0u8; 20];
    out[..4].copy_from_slice(&whitebox_output[..4]);
    out[4..].copy_from_slice(&digest);
    out
}

/// Build m3 from m2. Returns `(m3, receiver_sap)`.
pub(super) fn exchange_m3(local_sap: &[u8; 128], m2: &[u8]) -> Result<([u8; M3_LEN], [u8; 128])> {
    validate_record(m2, 2, M2_PAYLOAD_LEN).context("invalid m2")?;
    if m2[12] != 2 {
        bail!("invalid m2 payload marker {}", m2[12]);
    }
    let mode = m2[13];
    if mode as usize >= MODE_COUNT {
        bail!("m2 selected unsupported mode {mode}");
    }

    let mut m3 = [0u8; M3_LEN];
    m3.copy_from_slice(&new_record(3, M3_PAYLOAD_LEN));
    m3[12] = mode;
    m3[13..16].copy_from_slice(&M3_LABEL);
    encrypt_message(mode, local_sap, &mut m3[16..144]).context("encrypt m3 SAP")?;

    let m2_ciphertext: [u8; 128] = m2[14..142].try_into().unwrap();
    let m2_sap = decrypt_body(mode, &m2_ciphertext).context("decrypt m2 SAP")?;
    let tail = exchange_for_sap(local_sap, &m2_sap);
    m3[144..].copy_from_slice(&tail);
    Ok((m3, m2_sap))
}

pub(super) fn validate_m4(m4: &[u8], m3: &[u8]) -> Result<()> {
    validate_record(m4, 4, M4_PAYLOAD_LEN)?;
    if m3.len() != M3_LEN {
        bail!("invalid m3 length {}", m3.len());
    }
    if m4[12..] != m3[144..] {
        bail!("m4 confirmation does not match m3");
    }
    Ok(())
}

pub(super) fn validate_record(record: &[u8], message_type: u8, payload_length: usize) -> Result<()> {
    let want_length = 12 + payload_length;
    if record.len() != want_length {
        bail!("length {}, want {}", record.len(), want_length);
    }
    if &record[..4] != b"FPLY" {
        bail!("invalid magic {}", hex::encode(&record[..4]));
    }
    if record[4] != 3 || record[5] != 1 || record[6] != message_type || record[7] != 0 {
        bail!("invalid version/type {}", hex::encode(&record[4..8]));
    }
    let got = u32::from_be_bytes(record[8..12].try_into().unwrap()) as usize;
    if got != payload_length {
        bail!("declared payload length {got}, want {payload_length}");
    }
    Ok(())
}

pub(super) fn new_record(message_type: u8, payload_length: usize) -> Vec<u8> {
    let mut record = vec![0u8; 12 + payload_length];
    record[..4].copy_from_slice(b"FPLY");
    record[4..8].copy_from_slice(&[3, 1, message_type, 0]);
    record[8..12].copy_from_slice(&(payload_length as u32).to_be_bytes());
    record
}
