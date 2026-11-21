/// Pure-Rust Apple Lossless (ALAC) decoder for AirPlay real-time audio streams
/// (44.1 kHz / 16-bit stereo, 352 samples per packet) plus big-endian L16 PCM helper.
///
/// Handles both:
/// - Verbatim (uncompressed) ALAC Channel Pair Elements (CPE)
/// - Compressed ALAC CPE frames (adaptive FIR LPC prediction + Golomb-Rice entropy coding +
///   joint-stereo mid/side un-mixing), as sent by iOS, iPadOS, and macOS AirPlay senders.

use anyhow::{bail, Result};

struct BitReader<'a> {
    data: &'a [u8],
    bit_pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, bit_pos: 0 }
    }

    fn bits_left(&self) -> usize {
        self.data.len().saturating_mul(8).saturating_sub(self.bit_pos)
    }

    fn read_bits(&mut self, n: u8) -> Result<u32> {
        if n == 0 {
            return Ok(0);
        }
        if (n as usize) > self.bits_left() {
            bail!("ALAC bitstream truncated (need {n} bits, {} left)", self.bits_left());
        }
        let mut out = 0u32;
        let mut rem = n as usize;
        while rem > 0 {
            let byte_idx = self.bit_pos >> 3;
            let bit_off = self.bit_pos & 7;
            let avail = 8 - bit_off;
            let take = rem.min(avail);
            let shift = avail - take;
            let mask = ((1u16 << take) - 1) as u8;
            let val = (self.data[byte_idx] >> shift) & mask;
            out = (out << take) | (val as u32);
            self.bit_pos += take;
            rem -= take;
        }
        Ok(out)
    }

    fn read_bit(&mut self) -> Result<u32> {
        self.read_bits(1)
    }

    fn read_leading_ones(&mut self, limit: u32) -> Result<u32> {
        let mut count = 0u32;
        while count < limit && self.bits_left() > 0 {
            if self.read_bit()? == 1 {
                count += 1;
            } else {
                break;
            }
        }
        Ok(count)
    }
}

/// Sign-extend an unsigned `bits`-wide two's complement value to `i32`.
#[inline]
fn sign_extend(val: u32, bits: u8) -> i32 {
    if bits == 0 || bits >= 32 {
        return val as i32;
    }
    let shift = 32 - bits;
    ((val << shift) as i32) >> shift
}

/// Decode a single ALAC frame (from an AirPlay RTP packet) into interleaved 16-bit LE stereo PCM.
/// `default_samples` is typically 352 (from SDP `fmtp` or AirPlay 2 `spf`).
pub fn decode_alac_stereo_16(alac: &[u8], default_samples: usize) -> Result<Vec<u8>> {
    let mut br = BitReader::new(alac);
    let elem = br.read_bits(3)?;
    match elem {
        // ID_SCE (mono) — duplicate into stereo
        0 => {
            let _tag = br.read_bits(4)?;
            let _unused = br.read_bits(12)?;
            let has_size = br.read_bit()? != 0;
            let unused_bytes = br.read_bits(2)?;
            let is_verbatim = br.read_bit()? != 0;
            let num_samples = if has_size {
                br.read_bits(32)? as usize
            } else {
                default_samples
            };
            if num_samples > 16384 {
                bail!("ALAC frame sample count {num_samples} too large");
            }
            if is_verbatim {
                let mut pcm = Vec::with_capacity(num_samples * 4);
                for _ in 0..num_samples {
                    let s = (br.read_bits(16)? as i16).to_le_bytes();
                    pcm.extend_from_slice(&s);
                    pcm.extend_from_slice(&s);
                }
                return Ok(pcm);
            }
            let _extra = unused_bytes;
            let mut ch = vec![0i32; num_samples];
            decode_compressed_channels(&mut br, &mut [&mut ch], 16, 0, 0)?;
            let mut pcm = Vec::with_capacity(num_samples * 4);
            for s in ch {
                let b = (s.clamp(i16::MIN as i32, i16::MAX as i32) as i16).to_le_bytes();
                pcm.extend_from_slice(&b);
                pcm.extend_from_slice(&b);
            }
            Ok(pcm)
        }
        // ID_CPE (stereo Channel Pair Element)
        1 => {
            let _tag = br.read_bits(4)?;
            let _unused = br.read_bits(12)?;
            let has_size = br.read_bit()? != 0;
            let unused_bytes = br.read_bits(2)?;
            let is_verbatim = br.read_bit()? != 0;
            let num_samples = if has_size {
                br.read_bits(32)? as usize
            } else {
                default_samples
            };
            if num_samples > 16384 {
                bail!("ALAC frame sample count {num_samples} too large");
            }

            if is_verbatim {
                let mut pcm = Vec::with_capacity(num_samples * 4);
                for _ in 0..num_samples {
                    let l = (br.read_bits(16)? as i16).to_le_bytes();
                    let r = (br.read_bits(16)? as i16).to_le_bytes();
                    pcm.extend_from_slice(&l);
                    pcm.extend_from_slice(&r);
                }
                return Ok(pcm);
            }

            let shift_bits = (unused_bytes * 8) as u8;
            let sample_bits = 16u8.saturating_sub(shift_bits);
            let mix_bits = br.read_bits(8)? as u8;
            let mix_res = br.read_bits(8)? as i8;

            let mut left = vec![0i32; num_samples];
            let mut right = vec![0i32; num_samples];
            decode_compressed_channels(
                &mut br,
                &mut [&mut left, &mut right],
                sample_bits + 1, // stereo mid/side uses +1 bit
                mix_bits,
                mix_res,
            )?;

            // Un-mix joint stereo if mix_res != 0
            if mix_res != 0 {
                let mb = mix_bits as i32;
                let mr = mix_res as i32;
                for i in 0..num_samples {
                    let u = left[i];
                    let v = right[i];
                    let r = u - ((v * mr) >> mb);
                    let l = r + v;
                    left[i] = l;
                    right[i] = r;
                }
            }

            // Read any shifted lower bits (unused_bytes > 0; rare for 16-bit)
            if shift_bits > 0 {
                for i in 0..num_samples {
                    let lo_l = br.read_bits(shift_bits)? as i32;
                    let lo_r = br.read_bits(shift_bits)? as i32;
                    left[i] = (left[i] << shift_bits) | lo_l;
                    right[i] = (right[i] << shift_bits) | lo_r;
                }
            }

            let mut pcm = Vec::with_capacity(num_samples * 4);
            for i in 0..num_samples {
                let l = (left[i].clamp(i16::MIN as i32, i16::MAX as i32) as i16).to_le_bytes();
                let r = (right[i].clamp(i16::MIN as i32, i16::MAX as i32) as i16).to_le_bytes();
                pcm.extend_from_slice(&l);
                pcm.extend_from_slice(&r);
            }
            Ok(pcm)
        }
        other => bail!("unsupported ALAC element type {other}"),
    }
}

struct PredictorParams {
    pred_type: u8,
    quant_shift: u8,
    rice_modifier: u8,
    coefs: Vec<i16>,
}

fn decode_compressed_channels(
    br: &mut BitReader<'_>,
    channels: &mut [&mut [i32]],
    coded_bits: u8,
    _mix_bits: u8,
    _mix_res: i8,
) -> Result<()> {
    // 1. Read per-channel predictor headers
    let mut preds = Vec::with_capacity(channels.len());
    for _ in 0..channels.len() {
        let pred_type = br.read_bits(4)? as u8;
        let quant_shift = br.read_bits(4)? as u8;
        let rice_modifier = br.read_bits(3)? as u8;
        let num_coefs = br.read_bits(5)? as usize;
        let mut coefs = Vec::with_capacity(num_coefs);
        for _ in 0..num_coefs {
            coefs.push(br.read_bits(16)? as i16);
        }
        preds.push(PredictorParams {
            pred_type,
            quant_shift,
            rice_modifier,
            coefs,
        });
    }

    // Standard AirPlay ALAC codec parameters: history_mult=40, initial_history=10, k_modifier=14
    const HISTORY_MULT: u32 = 40;
    const INITIAL_HISTORY: u32 = 10;
    const K_MODIFIER: u32 = 14;

    // 2. Entropy decode + dynamic predictor per channel
    for (ch_idx, out) in channels.iter_mut().enumerate() {
        let pred = &preds[ch_idx];
        let residuals = entropy_decode(
            br,
            out.len(),
            coded_bits,
            INITIAL_HISTORY,
            (pred.rice_modifier as u32 * HISTORY_MULT) / 4,
            K_MODIFIER,
        )?;
        unpredict(
            &residuals,
            out,
            coded_bits,
            pred.pred_type,
            pred.quant_shift,
            &pred.coefs,
        );
    }
    Ok(())
}

/// Adaptive Golomb-Rice decoder matching Apple's open-source ALAC reference (`ag_dec.c`).
fn entropy_decode(
    br: &mut BitReader<'_>,
    num_samples: usize,
    sample_bits: u8,
    initial_history: u32,
    history_mult: u32,
    k_limit: u32,
) -> Result<Vec<i32>> {
    let mut out = vec![0i32; num_samples];
    let mut mb: u32 = initial_history << 9;
    let mut sign_modifier: u32 = 0;
    let mut i = 0usize;

    while i < num_samples {
        let k = ((mb >> 9) + 3).ilog2().min(k_limit);
        let value = dyn_get_32(br, k, sample_bits)?;
        let adjusted = value + sign_modifier;
        sign_modifier = 0;

        // Zigzag unmap: even -> positive, odd -> negative
        let decoded = if (adjusted & 1) != 0 {
            -(((adjusted + 1) >> 1) as i32)
        } else {
            (adjusted >> 1) as i32
        };
        out[i] = decoded;
        i += 1;

        // Update history mb
        if adjusted > 0xFFFF {
            mb = 0xFFFF;
        } else {
            let delta = (adjusted * history_mult) as i64 - ((mb * history_mult) >> 9) as i64;
            mb = (mb as i64 + delta).clamp(0, 0xFFFF * 512) as u32;
        }

        // Check for zero-run compression when history drops below threshold
        if (mb < 128) && (i < num_samples) {
            let k_zero = (7u32.saturating_sub(mb.leading_zeros().saturating_sub(23)))
                .min(k_limit);
            let k_zero = if mb == 0 {
                7
            } else {
                let lz = mb.leading_zeros() - 16; // 16-bit leading zeros
                let z = (mb >> 9) + 3;
                let _ = (k_zero, z);
                (7i32 - (lz as i32 - 8)).clamp(0, k_limit as i32) as u32
            };
            // Standard Apple ALAC formula: k = lead(mb) - 24 + ((mb + 16) >> 6)
            let k_run = {
                let lead = mb.leading_zeros();
                let raw = (lead as i32) - 24 + (((mb + 16) >> 6) as i32);
                raw.clamp(0, 16) as u32
            };
            let _ = k_zero;
            let run = dyn_get_16(br, k_run)? as usize;
            let count = run.min(num_samples - i);
            for slot in &mut out[i..i + count] {
                *slot = 0;
            }
            i += count;
            if run < 0xFFFF {
                sign_modifier = 1;
            }
            mb = 0;
        }
    }

    Ok(out)
}

fn dyn_get_32(br: &mut BitReader<'_>, k: u32, max_bits: u8) -> Result<u32> {
    let q = br.read_leading_ones(9)?;
    if q == 9 {
        return br.read_bits(max_bits);
    }
    if k <= 1 {
        return Ok(q);
    }
    let m = (1u32 << k) - 1;
    let extra = br.read_bits((k - 1) as u8)?;
    if extra > 1 {
        let next = br.read_bit()?;
        let r = (extra << 1) + next - 2;
        Ok(q * m + r)
    } else {
        Ok(q * m + extra)
    }
}

fn dyn_get_16(br: &mut BitReader<'_>, k: u32) -> Result<u32> {
    let q = br.read_leading_ones(9)?;
    if q == 9 {
        return br.read_bits(16);
    }
    if k <= 1 {
        return Ok(q);
    }
    let m = (1u32 << k) - 1;
    let extra = br.read_bits((k - 1) as u8)?;
    if extra > 1 {
        let next = br.read_bit()?;
        let r = (extra << 1) + next - 2;
        Ok(q * m + r)
    } else {
        Ok(q * m + extra)
    }
}

/// Inverse adaptive FIR linear predictor (`dp_dec.c` from Apple ALAC reference).
fn unpredict(
    residuals: &[i32],
    out: &mut [i32],
    bits: u8,
    pred_type: u8,
    quant_shift: u8,
    coefs_in: &[i16],
) {
    let n = residuals.len();
    if n == 0 {
        return;
    }

    let num_coefs = coefs_in.len();
    if num_coefs == 0 {
        out.copy_from_slice(residuals);
        return;
    }

    // Order 31 = simple first-order delta predictor
    if num_coefs == 31 || pred_type == 15 {
        out[0] = residuals[0];
        for i in 1..n {
            out[i] = sign_extend((out[i - 1].wrapping_add(residuals[i])) as u32, bits);
        }
        return;
    }

    let mut coefs = coefs_in.to_vec();
    out[0] = residuals[0];

    let init_end = (num_coefs + 1).min(n);
    for i in 1..init_end {
        out[i] = sign_extend((out[i - 1].wrapping_add(residuals[i])) as u32, bits);
    }

    let den_half = 1i32 << (quant_shift.saturating_sub(1));

    for i in init_end..n {
        let top = out[i - num_coefs - 1];
        let mut sum: i32 = den_half;
        for j in 0..num_coefs {
            let diff = out[i - 1 - j].wrapping_sub(top);
            sum = sum.wrapping_add(diff.wrapping_mul(coefs[j] as i32));
        }
        let pred = top.wrapping_add(sum >> quant_shift);
        let mut err = residuals[i];
        out[i] = sign_extend(pred.wrapping_add(err) as u32, bits);

        // Adapt FIR coefficients according to error sign
        if err > 0 {
            for j in (0..num_coefs).rev() {
                let d = top.wrapping_sub(out[i - 1 - j]);
                let s = d.signum();
                coefs[j] = coefs[j].wrapping_sub(s as i16);
                let step = (d.wrapping_mul(s)) >> quant_shift;
                err -= step.wrapping_mul((num_coefs - j) as i32);
                if err <= 0 {
                    break;
                }
            }
        } else if err < 0 {
            for j in (0..num_coefs).rev() {
                let d = top.wrapping_sub(out[i - 1 - j]);
                let s = d.signum();
                coefs[j] = coefs[j].wrapping_add(s as i16);
                let step = (d.wrapping_mul(s)) >> quant_shift;
                err += step.wrapping_mul((num_coefs - j) as i32);
                if err >= 0 {
                    break;
                }
            }
        }
    }
}

/// Convert big-endian signed 16-bit stereo PCM (`L16` from AirPlay) to little-endian PCM.
pub fn decode_l16_be_to_le(be: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(be.len());
    for chunk in be.chunks_exact(2) {
        out.push(chunk[1]);
        out.push(chunk[0]);
    }
    out
}

/// Apply AirPlay volume dB (-144.0 = mute, -30.0..=0.0 dB) to 16-bit LE PCM in place.
pub fn apply_airplay_volume_db(pcm_le: &mut [u8], volume_db: f32) {
    if volume_db <= -140.0 {
        pcm_le.fill(0);
        return;
    }
    if volume_db >= -0.05 {
        return;
    }
    let gain = 10.0f32.powf(volume_db / 20.0).clamp(0.0, 1.0);
    for chunk in pcm_le.chunks_exact_mut(2) {
        let s = i16::from_le_bytes([chunk[0], chunk[1]]) as f32;
        let scaled = (s * gain).round().clamp(i16::MIN as f32, i16::MAX as f32) as i16;
        let b = scaled.to_le_bytes();
        chunk[0] = b[0];
        chunk[1] = b[1];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audio::alac::{encode_alac_verbatim_stereo_16, SAMPLES_PER_FRAME};

    #[test]
    fn roundtrip_verbatim_alac_stereo_352() {
        let mut pcm = Vec::with_capacity(SAMPLES_PER_FRAME * 4);
        for i in 0..SAMPLES_PER_FRAME {
            let l = ((i as f32 * 0.1).sin() * 18000.0) as i16;
            let r = ((i as f32 * 0.17).cos() * 12000.0) as i16;
            pcm.extend_from_slice(&l.to_le_bytes());
            pcm.extend_from_slice(&r.to_le_bytes());
        }
        let encoded = encode_alac_verbatim_stereo_16(&pcm);
        let decoded = decode_alac_stereo_16(&encoded, SAMPLES_PER_FRAME).unwrap();
        assert_eq!(decoded, pcm);
    }

    #[test]
    fn volume_mute_zeroes_pcm() {
        let mut pcm = vec![0x34u8, 0x12, 0xFF, 0x7F];
        apply_airplay_volume_db(&mut pcm, -144.0);
        assert_eq!(pcm, vec![0, 0, 0, 0]);
    }

    #[test]
    fn l16_be_swaps_bytes() {
        assert_eq!(decode_l16_be_to_le(&[0x12, 0x34, 0xAB, 0xCD]), vec![0x34, 0x12, 0xCD, 0xAB]);
    }
}
