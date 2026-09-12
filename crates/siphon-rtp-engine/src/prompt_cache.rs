//! A bounded cache of decoded prompts, so a bed played to many callers is decoded once.
//!
//! # The cost it removes
//!
//! Every `play_media` on a file did a fresh `tokio::fs::read` (the whole file into a `Vec<u8>`), a
//! fresh RIFF parse (allocating a `Vec<i16>` and filling it sample by sample) and a fresh downmix
//! (allocating a second `Vec<i16>`). Three allocations proportional to prompt length, on every call.
//!
//! A queue with thirty waiting callers plays the same hold music thirty times; an office PBX plays
//! the same handful of prompts thousands of times a day. For a 30-second 8 kHz mono prompt that is
//! ~480 KB read plus ~480 KB parsed plus ~480 KB downmixed, churned per announcement.
//!
//! # What it caches, and what it does not
//!
//! The **decoded mono samples** plus their native rate — the form
//! [`siphon_rtp_media::player::PcmPlayer::from_shared`] takes. Resampling onto a leg's codec rate is
//! deliberately *not* cached: it depends on the leg, not the file, and the player already does it
//! once per playback. The cursor state (position, repeat count, seek point) lives in the player, so
//! N callers over one cached prompt is one buffer and N cursors.
//!
//! # Freshness
//!
//! Keyed by path **plus the file's modification time and length**, so replacing a prompt on disk is
//! picked up on the next play with no cache-clearing step and no staleness window. That is the whole
//! reason the key is not the path alone: an operator who re-records a greeting and sees the old one
//! keep playing has no way to tell the cache is why.
//!
//! # Bounds
//!
//! Capped in bytes and evicted least-recently-used. A cache that could grow without limit would turn
//! a directory of prompts into an unbounded memory leak on a long-running daemon — the exact failure
//! the memory-leak soak exists to catch.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use siphon_rtp_media::player::{WavError, WavSource};

/// A decoded prompt, ready to hand to a player.
#[derive(Debug, Clone)]
pub struct CachedPrompt {
    /// Downmixed mono samples at `sample_rate_hz`, shared by every player over this prompt.
    pub mono: Arc<[i16]>,
    /// The prompt's native rate. The engine resamples onto the leg from here.
    pub sample_rate_hz: u32,
}

impl CachedPrompt {
    /// Bytes this entry holds, for the cache's budget.
    fn size_bytes(&self) -> usize {
        self.mono.len() * std::mem::size_of::<i16>()
    }
}

/// What identifies a cached file. Modification time and length together are what make a re-recorded
/// prompt take effect immediately: either changing is a different key, so the old entry is simply
/// never looked up again (and is evicted in LRU order like any other).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PromptKey {
    path: PathBuf,
    /// `mtime` as nanoseconds since the epoch, or `None` on a filesystem that does not report one —
    /// in which case the length alone keys it, which is weaker but never *wrong*, only less
    /// discriminating.
    modified_nanos: Option<u128>,
    len: u64,
}

/// A bounded LRU cache of decoded prompts.
///
/// Shared behind one `Mutex` rather than a `DashMap`: the critical section is a hash lookup and a
/// counter bump on the **call-setup** path (never per packet, never per frame), and the eviction
/// order is global state that a sharded map cannot maintain without its own lock anyway.
pub struct PromptCache {
    inner: Mutex<Inner>,
    capacity_bytes: usize,
}

struct Inner {
    entries: HashMap<PromptKey, (CachedPrompt, u64)>,
    /// Monotonic tick stamped on each use; the smallest is the least recently used.
    clock: u64,
    used_bytes: usize,
    hits: u64,
    misses: u64,
}

impl PromptCache {
    /// A cache holding at most `capacity_bytes` of decoded audio. `0` disables caching entirely —
    /// every play decodes afresh, which is exactly the behaviour before this existed.
    #[must_use]
    pub fn new(capacity_bytes: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                entries: HashMap::new(),
                clock: 0,
                used_bytes: 0,
                hits: 0,
                misses: 0,
            }),
            capacity_bytes,
        }
    }

    /// Cache hits and misses so far, for observability.
    #[must_use]
    pub fn stats(&self) -> (u64, u64) {
        match self.inner.lock() {
            Ok(inner) => (inner.hits, inner.misses),
            Err(poisoned) => {
                let inner = poisoned.into_inner();
                (inner.hits, inner.misses)
            }
        }
    }

    /// Bytes of decoded audio currently held.
    #[must_use]
    pub fn used_bytes(&self) -> usize {
        self.inner
            .lock()
            .map(|inner| inner.used_bytes)
            .unwrap_or_else(|poisoned| poisoned.into_inner().used_bytes)
    }

    /// Look up a prompt, reading and decoding it on a miss.
    ///
    /// The file is `stat`ed on **every** call — that is the freshness check, and it is a single
    /// syscall against a read-plus-parse-plus-downmix. A file whose metadata cannot be read falls
    /// through to an uncached load rather than failing: the read below reports the real error, and
    /// a filesystem that hides `mtime` should still be able to play a prompt.
    pub async fn get_or_load(&self, path: &Path) -> Result<CachedPrompt, PromptError> {
        let key = match tokio::fs::metadata(path).await {
            Ok(metadata) => Some(PromptKey {
                path: path.to_path_buf(),
                modified_nanos: metadata.modified().ok().and_then(|time| {
                    time.duration_since(std::time::SystemTime::UNIX_EPOCH)
                        .ok()
                        .map(|since| since.as_nanos())
                }),
                len: metadata.len(),
            }),
            Err(_) => None,
        };

        if let Some(key) = key.as_ref() {
            if let Some(hit) = self.lookup(key) {
                return Ok(hit);
            }
        }

        let bytes = tokio::fs::read(path)
            .await
            .map_err(|error| PromptError::Read(error.to_string()))?;
        let source = WavSource::parse(&bytes).map_err(PromptError::Parse)?;
        let prompt = CachedPrompt {
            mono: source.to_mono(),
            sample_rate_hz: source.sample_rate_hz(),
        };
        if let Some(key) = key {
            self.insert(key, prompt.clone());
        }
        Ok(prompt)
    }

    /// Take a decoded prompt from the cache, stamping its use.
    fn lookup(&self, key: &PromptKey) -> Option<CachedPrompt> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.clock += 1;
        let stamp = inner.clock;
        match inner.entries.get_mut(key) {
            Some((prompt, used)) => {
                *used = stamp;
                let prompt = prompt.clone();
                inner.hits += 1;
                Some(prompt)
            }
            None => {
                inner.misses += 1;
                None
            }
        }
    }

    /// Store a decoded prompt, evicting least-recently-used entries to stay inside the budget.
    fn insert(&self, key: PromptKey, prompt: CachedPrompt) {
        if self.capacity_bytes == 0 {
            return;
        }
        let size = prompt.size_bytes();
        // A single prompt larger than the whole budget is played, never cached — caching it would
        // evict everything else to hold one entry that the next prompt immediately evicts.
        if size > self.capacity_bytes {
            return;
        }
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.clock += 1;
        let stamp = inner.clock;
        if let Some((old, _)) = inner.entries.insert(key, (prompt, stamp)) {
            inner.used_bytes = inner.used_bytes.saturating_sub(old.size_bytes());
        }
        inner.used_bytes += size;
        while inner.used_bytes > self.capacity_bytes {
            let Some(victim) = inner
                .entries
                .iter()
                .min_by_key(|(_, (_, used))| *used)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            if let Some((evicted, _)) = inner.entries.remove(&victim) {
                inner.used_bytes = inner.used_bytes.saturating_sub(evicted.size_bytes());
            }
        }
    }
}

/// Why a prompt could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PromptError {
    /// The file could not be read.
    #[error("read file: {0}")]
    Read(String),
    /// The bytes are not a WAV this engine can decode.
    #[error("parse WAV: {0}")]
    Parse(#[from] WavError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use siphon_rtp_media::fanout::MediaSink;
    use siphon_rtp_media::wav::WavRecorder;

    /// Write a mono 8 kHz WAV of `samples` constant-valued samples.
    fn write_prompt(path: &Path, samples: usize, value: i16) {
        let mut recorder = WavRecorder::new(8000, 1);
        recorder.write_pcm(&vec![value; samples]);
        std::fs::write(path, recorder.into_wav()).expect("write prompt");
    }

    #[tokio::test]
    async fn a_second_play_of_one_prompt_reuses_the_decoded_buffer() {
        // The point of the cache: N callers on one hold bed is one decode and one buffer.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("hold.wav");
        write_prompt(&path, 800, 1234);
        let cache = PromptCache::new(1 << 20);

        let first = cache.get_or_load(&path).await.expect("first load");
        let second = cache.get_or_load(&path).await.expect("second load");
        assert!(
            Arc::ptr_eq(&first.mono, &second.mono),
            "the second play reads the same samples rather than decoding again"
        );
        assert_eq!(cache.stats(), (1, 1), "one miss then one hit");
        assert_eq!(first.sample_rate_hz, 8000);
        assert_eq!(first.mono.len(), 800);
    }

    #[tokio::test]
    async fn re_recording_a_prompt_takes_effect_on_the_next_play() {
        // Keyed by mtime + length precisely so this needs no cache-clearing step. An operator who
        // re-records a greeting and hears the old one has no way to tell the cache is why.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("greeting.wav");
        write_prompt(&path, 400, 100);
        let cache = PromptCache::new(1 << 20);
        let before = cache.get_or_load(&path).await.expect("load");
        assert_eq!(before.mono.len(), 400);

        // A different length is a different key even if the clock has not moved.
        write_prompt(&path, 800, 200);
        let after = cache.get_or_load(&path).await.expect("reload");
        assert_eq!(after.mono.len(), 800, "the new recording is served");
        assert!(!Arc::ptr_eq(&before.mono, &after.mono));
    }

    #[tokio::test]
    async fn the_cache_stays_inside_its_budget_and_evicts_the_least_recently_used() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Three prompts of 400 samples = 800 bytes each; a budget that holds exactly two.
        let paths: Vec<PathBuf> = (0..3)
            .map(|index| {
                let path = dir.path().join(format!("prompt-{index}.wav"));
                write_prompt(&path, 400, index as i16 + 1);
                path
            })
            .collect();
        let cache = PromptCache::new(1600);

        cache.get_or_load(&paths[0]).await.expect("load 0");
        cache.get_or_load(&paths[1]).await.expect("load 1");
        // Touch 0 so 1 becomes the least recently used.
        cache.get_or_load(&paths[0]).await.expect("hit 0");
        cache.get_or_load(&paths[2]).await.expect("load 2");
        assert!(
            cache.used_bytes() <= 1600,
            "the cache never exceeds its budget, got {}",
            cache.used_bytes()
        );

        let (hits_before, _) = cache.stats();
        cache.get_or_load(&paths[0]).await.expect("0 is still held");
        let (hits_after, _) = cache.stats();
        assert_eq!(
            hits_after,
            hits_before + 1,
            "the recently used entry stayed"
        );

        let (_, misses_before) = cache.stats();
        cache.get_or_load(&paths[1]).await.expect("1 was evicted");
        let (_, misses_after) = cache.stats();
        assert_eq!(
            misses_after,
            misses_before + 1,
            "the least recently used entry was the one evicted"
        );
    }

    #[tokio::test]
    async fn a_prompt_larger_than_the_whole_budget_is_played_but_never_cached() {
        // Caching it would evict everything to hold one entry the next prompt immediately evicts.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("huge.wav");
        write_prompt(&path, 4000, 7);
        let cache = PromptCache::new(1000);
        let loaded = cache.get_or_load(&path).await.expect("it still plays");
        assert_eq!(loaded.mono.len(), 4000);
        assert_eq!(cache.used_bytes(), 0, "and nothing was cached");
    }

    #[tokio::test]
    async fn a_zero_budget_disables_caching_without_breaking_playback() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("prompt.wav");
        write_prompt(&path, 200, 5);
        let cache = PromptCache::new(0);
        let first = cache.get_or_load(&path).await.expect("load");
        let second = cache.get_or_load(&path).await.expect("load again");
        assert_eq!(first.mono.len(), 200);
        assert!(
            !Arc::ptr_eq(&first.mono, &second.mono),
            "every play decodes afresh, exactly as before the cache existed"
        );
        assert_eq!(cache.used_bytes(), 0);
    }

    #[tokio::test]
    async fn a_missing_or_malformed_prompt_reports_a_typed_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = PromptCache::new(1 << 20);
        let missing = dir.path().join("not-there.wav");
        assert!(matches!(
            cache.get_or_load(&missing).await,
            Err(PromptError::Read(_))
        ));

        let garbage = dir.path().join("garbage.wav");
        std::fs::write(&garbage, b"this is not a RIFF file").expect("write");
        assert!(matches!(
            cache.get_or_load(&garbage).await,
            Err(PromptError::Parse(_))
        ));
    }

    #[tokio::test]
    async fn a_mu_law_prompt_loads_through_the_cache_like_any_other() {
        // The two changes compose: a G.711 prompt (the form most telephony exports arrive in) is
        // decoded once and shared like a linear one.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("mulaw.wav");
        let payload: Vec<u8> = (0..200u16).map(|index| (index % 256) as u8).collect();
        let mut buffer = Vec::new();
        buffer.extend_from_slice(b"RIFF");
        buffer.extend_from_slice(&0u32.to_le_bytes());
        buffer.extend_from_slice(b"WAVE");
        buffer.extend_from_slice(b"fmt ");
        buffer.extend_from_slice(&16u32.to_le_bytes());
        buffer.extend_from_slice(&7u16.to_le_bytes()); // mu-law
        buffer.extend_from_slice(&1u16.to_le_bytes());
        buffer.extend_from_slice(&8000u32.to_le_bytes());
        buffer.extend_from_slice(&8000u32.to_le_bytes());
        buffer.extend_from_slice(&1u16.to_le_bytes());
        buffer.extend_from_slice(&8u16.to_le_bytes());
        buffer.extend_from_slice(b"data");
        buffer.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&payload);
        std::fs::write(&path, &buffer).expect("write");

        let cache = PromptCache::new(1 << 20);
        let first = cache.get_or_load(&path).await.expect("mu-law loads");
        assert_eq!(first.mono.len(), payload.len());
        let second = cache.get_or_load(&path).await.expect("and caches");
        assert!(Arc::ptr_eq(&first.mono, &second.mono));
    }
}
