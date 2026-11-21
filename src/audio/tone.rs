use super::alac::{SAMPLES_PER_FRAME, SAMPLE_RATE};
use std::f64::consts::PI;

/// Generate a pleasant, gentle two-note harmonic chime (C5 -> G5 soft sine + subtle overtone)
/// lasting ~1.1 seconds as 44.1kHz 16-bit LE stereo PCM chunks of `SAMPLES_PER_FRAME`.
pub fn generate_test_chime_frames() -> Vec<Vec<u8>> {
    let total_samples = (SAMPLE_RATE as f64 * 1.15) as usize;
    let mut pcm = Vec::with_capacity(total_samples * 4);

    let note1_freq = 523.25; // C5
    let note2_freq = 783.99; // G5
    let note2_start = (SAMPLE_RATE as f64 * 0.22) as usize;

    for i in 0..total_samples {
        let t = i as f64 / SAMPLE_RATE as f64;
        let mut val = 0.0;

        // First note: soft warm bell envelope
        let env1 = (1.0 - (-t * 60.0).exp()) * (-t * 4.2).exp();
        val += 0.22 * env1 * ((2.0 * PI * note1_freq * t).sin() + 0.18 * (2.0 * PI * note1_freq * 2.0 * t).sin());

        // Second note: uplifting fifth
        if i >= note2_start {
            let t2 = (i - note2_start) as f64 / SAMPLE_RATE as f64;
            let env2 = (1.0 - (-t2 * 60.0).exp()) * (-t2 * 3.8).exp();
            val += 0.24 * env2 * ((2.0 * PI * note2_freq * t2).sin() + 0.15 * (2.0 * PI * note2_freq * 2.0 * t2).sin());
        }

        let sample = (val.clamp(-0.95, 0.95) * i16::MAX as f64) as i16;
        let bytes = sample.to_le_bytes();
        pcm.extend_from_slice(&bytes);
        pcm.extend_from_slice(&bytes);
    }

    let frame_bytes = SAMPLES_PER_FRAME * 4;
    pcm.chunks(frame_bytes)
        .map(|chunk| {
            let mut v = chunk.to_vec();
            v.resize(frame_bytes, 0);
            v
        })
        .collect()
}
