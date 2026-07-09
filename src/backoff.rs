//! Shared exponential-backoff ladder for client retry loops.
//!
//! Consolidates the retry cadence that clients currently re-derive per engine
//! (account sync, realm stream, session refresh) and per bridge. A single type
//! ends the seconds-vs-milliseconds unit drift by working exclusively in
//! [`Duration`].
//!
//! Semantics:
//! - starts at `floor`, doubles each step, saturates at `ceiling`;
//! - a server `retry-after` hint is honored as a hard *floor* for that step
//!   (the delay is never shorter than the hint, even after jitter);
//! - [`Backoff::reset`] returns the ladder to `floor` (call it after success);
//! - jitter is opt-in and only ever shortens the ladder-computed delay, never
//!   the server hint.
//!
//! ## Jitter and wasm
//!
//! Jitter must not pull in `rand`, whose default entropy source panics on
//! `wasm32-unknown-unknown`. Instead the caller *injects a seed* and jitter is
//! produced by a tiny deterministic SplitMix64 PRNG. This keeps the type
//! wasm-safe and its output fully reproducible in tests. The trade-off: the
//! caller is responsible for supplying a varied seed (e.g. an id, a monotonic
//! counter, or host entropy) if it wants independent jitter across instances;
//! two `Backoff`s built with the same seed produce identical jitter sequences.

use std::time::Duration;

/// Deterministic exponential-backoff ladder. See the module docs for semantics.
#[derive(Clone, Debug)]
pub struct Backoff {
    floor: Duration,
    ceiling: Duration,
    /// Base (pre-hint, pre-jitter) delay for the next step; `None` before the
    /// first step and after [`Backoff::reset`].
    next_base: Option<Duration>,
    jitter: Option<Jitter>,
}

#[derive(Clone, Debug)]
struct Jitter {
    /// Fraction of the delay that may be shaved off, clamped to `[0.0, 1.0]`.
    ratio: f64,
    rng: SplitMix64,
}

impl Backoff {
    /// Create a ladder bounded by `[floor, ceiling]`. If `ceiling < floor` the
    /// ceiling is clamped up to `floor` (a fixed-delay ladder).
    pub fn new(floor: Duration, ceiling: Duration) -> Self {
        Self {
            floor,
            ceiling: ceiling.max(floor),
            next_base: None,
            jitter: None,
        }
    }

    /// Enable jitter that shortens each ladder-computed delay by up to `ratio`
    /// of its value, driven by a deterministic PRNG seeded with `seed`.
    ///
    /// `ratio` is clamped to `[0.0, 1.0]`: `0.0` disables shaving, `1.0` is
    /// full jitter (delay in `[0, base)`). See the module docs for why the seed
    /// is injected rather than drawn from `rand`.
    pub fn with_jitter(mut self, ratio: f64, seed: u64) -> Self {
        self.jitter = Some(Jitter {
            ratio: ratio.clamp(0.0, 1.0),
            rng: SplitMix64::new(seed),
        });
        self
    }

    /// Advance the ladder and return the next delay.
    pub fn next_delay(&mut self) -> Duration {
        self.next_delay_with_hint(None)
    }

    /// Advance the ladder and return the next delay, honoring a server
    /// `retry-after` hint as a hard floor for this step.
    ///
    /// The doubling ladder advances from its own base regardless of the hint, so
    /// a one-off large hint does not permanently inflate subsequent delays.
    pub fn next_delay_with_hint(&mut self, retry_after: Option<Duration>) -> Duration {
        let base = self.next_base.unwrap_or(self.floor);
        // Advance the pure doubling ladder independently of hint/jitter.
        self.next_base = Some(base.saturating_mul(2).min(self.ceiling));

        let computed = self.apply_jitter(base);
        match retry_after {
            Some(hint) => computed.max(hint),
            None => computed,
        }
    }

    /// Reset the ladder to `floor`. Call after a successful attempt.
    pub fn reset(&mut self) {
        self.next_base = None;
    }

    /// The base delay the next step will use, before hint/jitter. Does not
    /// advance the ladder.
    pub fn peek_base(&self) -> Duration {
        self.next_base.unwrap_or(self.floor)
    }

    fn apply_jitter(&mut self, base: Duration) -> Duration {
        let Some(jitter) = self.jitter.as_mut() else {
            return base;
        };
        if jitter.ratio <= 0.0 {
            return base;
        }
        // factor in [1 - ratio, 1.0): shave up to `ratio` of the delay.
        let factor = 1.0 - jitter.ratio * jitter.rng.next_f64();
        Duration::from_secs_f64((base.as_secs_f64() * factor).max(0.0))
    }
}

/// Minimal, dependency-free deterministic PRNG (SplitMix64) used only for
/// jitter. Not cryptographic.
#[derive(Clone, Debug)]
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform `f64` in `[0.0, 1.0)` using the top 53 bits.
    fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: fn(u64) -> Duration = Duration::from_secs;

    #[test]
    fn ladder_doubles_then_saturates_at_ceiling() {
        let mut backoff = Backoff::new(S(1), S(8));
        let delays: Vec<_> = (0..6).map(|_| backoff.next_delay()).collect();
        assert_eq!(delays, vec![S(1), S(2), S(4), S(8), S(8), S(8)]);
    }

    #[test]
    fn reset_returns_ladder_to_floor() {
        let mut backoff = Backoff::new(S(1), S(16));
        assert_eq!(backoff.next_delay(), S(1));
        assert_eq!(backoff.next_delay(), S(2));
        assert_eq!(backoff.next_delay(), S(4));
        backoff.reset();
        assert_eq!(backoff.next_delay(), S(1));
        assert_eq!(backoff.next_delay(), S(2));
    }

    #[test]
    fn server_hint_acts_as_floor_without_inflating_ladder() {
        let mut backoff = Backoff::new(S(1), S(60));
        // base is 1s but the server asks for 5s -> honor 5s.
        assert_eq!(backoff.next_delay_with_hint(Some(S(5))), S(5));
        // ladder advanced from its own base (1 -> 2), not from the hint.
        assert_eq!(backoff.next_delay(), S(2));
        assert_eq!(backoff.next_delay(), S(4));
    }

    #[test]
    fn server_hint_below_base_is_ignored() {
        let mut backoff = Backoff::new(S(4), S(60));
        assert_eq!(backoff.next_delay(), S(4));
        assert_eq!(backoff.next_delay(), S(8));
        // base is now 16s; a 1s hint must not shorten it.
        assert_eq!(backoff.next_delay_with_hint(Some(S(1))), S(16));
    }

    #[test]
    fn ceiling_below_floor_is_clamped_to_floor() {
        let mut backoff = Backoff::new(S(5), S(1));
        assert_eq!(backoff.next_delay(), S(5));
        assert_eq!(backoff.next_delay(), S(5));
    }

    #[test]
    fn jitter_is_bounded_and_never_below_hint() {
        // Fixed base of 4s (floor == ceiling) so only jitter varies the output.
        let mut backoff = Backoff::new(S(4), S(4)).with_jitter(0.5, 0xC0FF_EE12_3456_789A);
        for _ in 0..64 {
            // ratio 0.5 -> delay in [2s, 4s].
            let delay = backoff.next_delay();
            assert!(delay <= S(4), "delay {delay:?} exceeded base");
            assert!(delay >= S(2), "delay {delay:?} below jitter floor");
        }
        // Hint remains a hard floor even with jitter shaving the base.
        let jittered = backoff.next_delay_with_hint(Some(S(10)));
        assert_eq!(jittered, S(10));
    }

    #[test]
    fn jitter_is_deterministic_for_a_given_seed() {
        let seq = |seed: u64| {
            let mut backoff = Backoff::new(S(1), S(60)).with_jitter(1.0, seed);
            (0..8).map(|_| backoff.next_delay()).collect::<Vec<_>>()
        };
        assert_eq!(seq(42), seq(42));
        assert_ne!(seq(42), seq(7));
    }

    #[test]
    fn zero_ratio_jitter_matches_plain_ladder() {
        let mut jittered = Backoff::new(S(1), S(8)).with_jitter(0.0, 99);
        let mut plain = Backoff::new(S(1), S(8));
        for _ in 0..6 {
            assert_eq!(jittered.next_delay(), plain.next_delay());
        }
    }
}
