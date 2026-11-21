pub mod alac;
pub mod pulse;
pub mod tone;

use alac::{encode_alac_verbatim_stereo_16, SAMPLES_PER_FRAME, SAMPLE_RATE};
use pulse::{read_pcm_frame, PulseAudioManager};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, Mutex};
use tracing::{debug, info, warn};

/// Seconds between NTP epoch (1900-01-01) and Unix epoch (1970-01-01).
pub const NTP_EPOCH_DELTA: u64 = 2_208_988_800;

/// A single encoded audio packet ready for synchronized broadcast to all active speakers.
#[derive(Debug, Clone)]
pub struct AudioPacket {
    pub seq: u16,
    pub rtp_time: u32,
    pub ntp_sec: u32,
    pub ntp_frac: u32,
    pub alac_payload: Arc<Vec<u8>>,
    pub is_sync_tick: bool,
}

pub fn system_time_to_ntp(t: SystemTime) -> (u32, u32) {
    let dur = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let sec = (dur.as_secs() + NTP_EPOCH_DELTA) as u32;
    let frac = ((dur.subsec_nanos() as u64 * (1u64 << 32)) / 1_000_000_000) as u32;
    (sec, frac)
}

pub fn now_ntp() -> (u32, u32) {
    system_time_to_ntp(SystemTime::now())
}

/// Master 44.1kHz real-time audio clock and broadcaster shared by every connected AirPlay speaker.
///
/// Running a single master clock guarantees sample-accurate multi-room synchronization
/// across HomePods, Apple TVs, Macs, and Shairport Sync receivers simultaneously.
pub struct AudioEngine {
    pub pulse: Arc<PulseAudioManager>,
    packet_tx: broadcast::Sender<AudioPacket>,
    overlay_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    retransmit_ring: Arc<Mutex<VecDeque<AudioPacket>>>,
    running: Arc<AtomicBool>,
    /// Live RMS peak level encoded as 0..=1000 for smooth UI VU meters
    level_milli: Arc<AtomicU32>,
    /// Current RTP timestamp (44.1kHz sample clock)
    current_rtp_time: Arc<AtomicU32>,
    /// Current RTP sequence number
    current_seq: Arc<AtomicU32>,
    /// Master volume percentage (0..=100) applied optionally or forwarded
    packets_sent: Arc<AtomicU64>,
}

impl AudioEngine {
    pub fn new() -> Arc<Self> {
        let (packet_tx, _) = broadcast::channel(256);
        let start_rtp: u32 = rand::random::<u32>() & 0x7FFF_FFFF;
        let start_seq: u16 = rand::random();

        Arc::new(Self {
            pulse: PulseAudioManager::new(),
            packet_tx,
            overlay_queue: Arc::new(Mutex::new(VecDeque::new())),
            retransmit_ring: Arc::new(Mutex::new(VecDeque::with_capacity(1024))),
            running: Arc::new(AtomicBool::new(false)),
            level_milli: Arc::new(AtomicU32::new(0)),
            current_rtp_time: Arc::new(AtomicU32::new(start_rtp)),
            current_seq: Arc::new(AtomicU32::new(start_seq as u32)),
            packets_sent: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<AudioPacket> {
        self.packet_tx.subscribe()
    }

    pub fn current_rtp_time(&self) -> u32 {
        self.current_rtp_time.load(Ordering::Relaxed)
    }

    pub fn current_seq(&self) -> u16 {
        self.current_seq.load(Ordering::Relaxed) as u16
    }

    pub fn level(&self) -> f32 {
        self.level_milli.load(Ordering::Relaxed) as f32 / 1000.0
    }

    /// Queue a gentle musical test chime (mixed cleanly into the live stream).
    pub async fn play_test_chime(&self) {
        let frames = tone::generate_test_chime_frames();
        let mut q = self.overlay_queue.lock().await;
        for f in frames {
            q.push_back(f);
        }
    }

    /// Lookup a recent packet by RTP sequence number for AirPlay retransmit requests.
    pub async fn get_retransmit_packet(&self, seq: u16) -> Option<AudioPacket> {
        let ring = self.retransmit_ring.lock().await;
        ring.iter().rev().find(|p| p.seq == seq).cloned()
    }

    /// Start the real-time 44.1kHz capture & ALAC broadcast loop if not already active.
    pub fn ensure_started(self: &Arc<Self>, capture_system_audio: bool) {
        if self.running.swap(true, Ordering::SeqCst) {
            return;
        }
        let engine = self.clone();
        tokio::spawn(async move {
            engine.run_loop(capture_system_audio).await;
        });
    }

    pub async fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.pulse.stop_capture().await;
        self.level_milli.store(0, Ordering::Relaxed);
    }

    async fn run_loop(self: Arc<Self>, capture_system_audio: bool) {
        info!(
            "AudioEngine real-time loop starting (capture_system_audio={})",
            capture_system_audio
        );

        let frame_bytes = SAMPLES_PER_FRAME * 4;
        // Dedicated reader channel so capture I/O never blocks our exact 7.981859ms audio clock!
        let (pcm_tx, mut pcm_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);

        if capture_system_audio {
            let pulse = self.pulse.clone();
            let running = self.running.clone();
            tokio::spawn(async move {
                while running.load(Ordering::Relaxed) {
                    match pulse.start_capture_reader().await {
                        Ok(mut stdout) => {
                            let mut buf = vec![0u8; frame_bytes];
                            while running.load(Ordering::Relaxed) {
                                if !read_pcm_frame(&mut stdout, &mut buf).await {
                                    warn!("Audio capture stream ended; retrying...");
                                    break;
                                }
                                if pcm_tx.try_send(buf.clone()).is_err() {
                                    // Drop oldest frame implicitly if consumer momentarily lags
                                }
                            }
                            pulse.stop_capture().await;
                        }
                        Err(e) => {
                            debug!("System audio capture unavailable ({e}); streaming silence/overlays");
                            tokio::time::sleep(Duration::from_secs(2)).await;
                        }
                    }
                }
            });
        }

        // Exact monotonic pacing: 352 samples @ 44100 Hz = 7,981,859.4104 nanoseconds
        let start_instant = Instant::now();
        let mut frame_index: u64 = 0;
        let mut samples_since_sync: u32 = SAMPLE_RATE; // Trigger an immediate sync packet on start
        let mut seq = self.current_seq.load(Ordering::Relaxed) as u16;
        let mut rtp_time = self.current_rtp_time.load(Ordering::Relaxed);

        while self.running.load(Ordering::Relaxed) {
            let target_ns = ((frame_index as u128) * (SAMPLES_PER_FRAME as u128) * 1_000_000_000u128)
                / (SAMPLE_RATE as u128);
            let target_time = start_instant + Duration::from_nanos(target_ns as u64);
            let now = Instant::now();
            if target_time > now {
                tokio::time::sleep(target_time - now).await;
            }
            frame_index += 1;

            // Grab captured system audio frame (or silence if no audio is arriving)
            let mut pcm = pcm_rx
                .try_recv()
                .unwrap_or_else(|_| vec![0u8; frame_bytes]);

            // Mix in any overlay frame (e.g. test chime) with soft clipping
            if let Some(overlay) = self.overlay_queue.lock().await.pop_front() {
                for (dst, src) in pcm.chunks_exact_mut(2).zip(overlay.chunks_exact(2)) {
                    let a = i16::from_le_bytes([dst[0], dst[1]]) as i32;
                    let b = i16::from_le_bytes([src[0], src[1]]) as i32;
                    let mixed = (a + b).clamp(i16::MIN as i32, i16::MAX as i32) as i16;
                    let bytes = mixed.to_le_bytes();
                    dst[0] = bytes[0];
                    dst[1] = bytes[1];
                }
            }

            // Compute live peak level for UI meter
            let mut peak: i32 = 0;
            for chunk in pcm.chunks_exact(2) {
                let s = (i16::from_le_bytes([chunk[0], chunk[1]]) as i32).abs();
                if s > peak {
                    peak = s;
                }
            }
            let norm = ((peak as f32 / i16::MAX as f32).sqrt() * 1000.0) as u32;
            self.level_milli.store(norm.min(1000), Ordering::Relaxed);

            let alac_payload = Arc::new(encode_alac_verbatim_stereo_16(&pcm));
            let (ntp_sec, ntp_frac) = now_ntp();

            let is_sync_tick = samples_since_sync >= SAMPLE_RATE;
            if is_sync_tick {
                samples_since_sync = 0;
            }
            samples_since_sync += SAMPLES_PER_FRAME as u32;

            let pkt = AudioPacket {
                seq,
                rtp_time,
                ntp_sec,
                ntp_frac,
                alac_payload,
                is_sync_tick,
            };

            seq = seq.wrapping_add(1);
            rtp_time = rtp_time.wrapping_add(SAMPLES_PER_FRAME as u32);
            self.current_seq.store(seq as u32, Ordering::Relaxed);
            self.current_rtp_time.store(rtp_time, Ordering::Relaxed);
            self.packets_sent.fetch_add(1, Ordering::Relaxed);

            {
                let mut ring = self.retransmit_ring.lock().await;
                if ring.len() >= 1000 {
                    ring.pop_front();
                }
                ring.push_back(pkt.clone());
            }

            let _ = self.packet_tx.send(pkt);
        }

        info!("AudioEngine real-time loop stopped");
    }
}
