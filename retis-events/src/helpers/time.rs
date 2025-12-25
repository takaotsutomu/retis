use std::ops;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use nix::time::{clock_gettime, ClockId};

use crate::{event_type, TimeFormat};

/// Timespec. Representation of `struct timespec` to hold time values.
#[event_type]
#[derive(Copy, Default)]
pub struct TimeSpec {
    sec: i64,
    nsec: i64,
}

impl TimeSpec {
    const NSECS_IN_SEC: i64 = 1000000000;

    pub fn new(mut sec: i64, mut nsec: i64) -> Self {
        if nsec >= Self::NSECS_IN_SEC {
            let diff = nsec / Self::NSECS_IN_SEC;
            sec += diff;
            nsec -= diff * Self::NSECS_IN_SEC;
        }

        Self { sec, nsec }
    }

    pub fn sec(&self) -> i64 {
        self.sec
    }

    pub fn nsec(&self) -> i64 {
        self.nsec
    }
}

impl ops::Add for TimeSpec {
    type Output = TimeSpec;

    fn add(self, rhs: Self) -> Self {
        let mut sec = self.sec + rhs.sec;
        let mut nsec = self.nsec + rhs.nsec;

        if nsec >= Self::NSECS_IN_SEC {
            sec += 1;
            nsec -= Self::NSECS_IN_SEC;
        }

        Self { sec, nsec }
    }
}

impl ops::Sub for TimeSpec {
    type Output = TimeSpec;

    fn sub(self, rhs: Self) -> Self {
        let mut sec = self.sec - rhs.sec;
        let mut nsec = self.nsec - rhs.nsec;

        if nsec < 0 {
            sec -= 1;
            nsec += Self::NSECS_IN_SEC;
        }

        Self { sec, nsec }
    }
}

impl From<TimeSpec> for DateTime<Utc> {
    fn from(val: TimeSpec) -> DateTime<Utc> {
        DateTime::from_timestamp(val.sec(), val.nsec() as u32)
            .expect("Could not convert TimeSpec to DateTime")
    }
}

impl From<TimeSpec> for i64 {
    fn from(ts: TimeSpec) -> Self {
        ts.sec * TimeSpec::NSECS_IN_SEC + ts.nsec
    }
}

pub fn format_date_time(
    format: TimeFormat,
    timestamp: u64,
    monotonic_offset: Option<TimeSpec>,
) -> String {
    match format {
        TimeFormat::MonotonicTimestamp => timestamp.to_string(),
        TimeFormat::UtcDate => match monotonic_offset {
            Some(offset) => {
                let timestamp = TimeSpec::new(0, timestamp as i64) + offset;
                let time: DateTime<Utc> = timestamp.into();
                format!("{}", time.format("%F %T.%6f"))
            }
            None => timestamp.to_string(),
        },
    }
}

/// Returns the monotonic timestamp in nanoseconds.
pub fn monotonic_timestamp() -> Result<u64> {
    let monotonic = clock_gettime(ClockId::CLOCK_MONOTONIC)?;

    let ts = monotonic.tv_sec() * 1000000000 + monotonic.tv_nsec();
    if ts < 0 {
        bail!("Monotonic timestamp is negative: {ts}");
    }

    Ok(ts as u64)
}

/// Computes and returns the offset of CLOCK_MONOTONIC to the wall-clock time.
pub fn monotonic_clock_offset() -> Result<TimeSpec> {
    let realtime = clock_gettime(ClockId::CLOCK_REALTIME)?;
    let monotonic = clock_gettime(ClockId::CLOCK_MONOTONIC)?;
    let offset = realtime - monotonic;

    Ok(TimeSpec::new(offset.tv_sec(), offset.tv_nsec()))
}

#[allow(dead_code)]
pub struct MonotonicOffsetCache {
    offset: TimeSpec,
    last_update: Instant,
    refresh_interval: Duration,
}

#[allow(dead_code)]
impl MonotonicOffsetCache {
    /// Default refresh interval (10 seconds).
    ///
    /// This balances accuracy (catching NTP adjustments) against
    /// the overhead of syscalls.
    pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

    pub fn new() -> Result<Self> {
        Self::with_refresh_interval(Self::DEFAULT_REFRESH_INTERVAL)
    }

    pub fn with_refresh_interval(refresh_interval: Duration) -> Result<Self> {
        Ok(Self {
            offset: monotonic_clock_offset()?,
            last_update: Instant::now(),
            refresh_interval,
        })
    }

    pub fn get_offset(&mut self) -> Result<TimeSpec> {
        if self.last_update.elapsed() > self.refresh_interval {
            self.refresh()?;
        }
        Ok(self.offset)
    }

    pub fn refresh(&mut self) -> Result<()> {
        self.offset = monotonic_clock_offset()?;
        self.last_update = Instant::now();
        Ok(())
    }

    /// Convert monotonic nanoseconds to epoch nanoseconds.
    pub fn monotonic_to_epoch_ns(&mut self, mono_ns: u64) -> Result<i64> {
        let offset = self.get_offset()?;
        let offset_ns: i64 = offset.into();
        Ok(mono_ns as i64 + offset_ns)
    }

    /// Convert monotonic nanoseconds to epoch without refresh check.
    #[inline]
    pub fn monotonic_to_epoch_ns_fast(&self, mono_ns: u64) -> i64 {
        let offset_ns: i64 = self.offset.into();
        mono_ns as i64 + offset_ns
    }

    pub fn last_update(&self) -> Instant {
        self.last_update
    }

    pub fn refresh_interval(&self) -> Duration {
        self.refresh_interval
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timespec_new() {
        let ts = TimeSpec::new(42, 100001);
        assert_eq!(ts.sec(), 42);
        assert_eq!(ts.nsec(), 100001);

        let ts = TimeSpec::new(42, TimeSpec::NSECS_IN_SEC + 1);
        assert_eq!(ts.sec(), 43);
        assert_eq!(ts.nsec(), 1);

        let ts = TimeSpec::new(42, TimeSpec::NSECS_IN_SEC * 10 + 1);
        assert_eq!(ts.sec(), 52);
        assert_eq!(ts.nsec(), 1);
    }

    #[test]
    fn timespec_add() {
        let ts = TimeSpec::new(42, 100001);

        let tmp = ts + TimeSpec::new(1, 30);
        assert_eq!(tmp.sec(), 43);
        assert_eq!(tmp.nsec(), 100031);

        let tmp = ts + TimeSpec::new(0, TimeSpec::NSECS_IN_SEC - 1);
        assert_eq!(tmp.sec(), 43);
        assert_eq!(tmp.nsec(), 100000);
    }

    #[test]
    fn timespec_sub() {
        let ts = TimeSpec::new(42, 100001);

        let tmp = ts - TimeSpec::new(1, 30);
        assert_eq!(tmp.sec(), 41);
        assert_eq!(tmp.nsec(), 99971);

        let tmp = ts - TimeSpec::new(0, 100002);
        assert_eq!(tmp.sec(), 41);
        assert_eq!(tmp.nsec(), TimeSpec::NSECS_IN_SEC - 1);

        let tmp = ts - TimeSpec::new(42, 100002);
        assert_eq!(tmp.sec(), -1);
        assert_eq!(tmp.nsec(), TimeSpec::NSECS_IN_SEC - 1);
    }

    #[test]
    fn conversion_produces_plausible_epoch() {
        let mut cache = MonotonicOffsetCache::new().unwrap();

        let mono_ns = monotonic_timestamp().unwrap();
        let epoch_ns = cache.monotonic_to_epoch_ns(mono_ns).unwrap();

        let year_2020_ns: i64 = 1577836800_000_000_000;
        assert!(epoch_ns > year_2020_ns, "Epoch time should be after 2020");

        let year_2100_ns: i64 = 4102444800_000_000_000;
        assert!(epoch_ns < year_2100_ns, "Epoch time should be before 2100");
    }

    #[test]
    fn ordering_preserved() {
        let mut cache = MonotonicOffsetCache::new().unwrap();

        let t1: u64 = 1_000_000_000;
        let t2: u64 = 2_000_000_000;
        let t3: u64 = 3_000_000_000;

        let e1 = cache.monotonic_to_epoch_ns(t1).unwrap();
        let e2 = cache.monotonic_to_epoch_ns(t2).unwrap();
        let e3 = cache.monotonic_to_epoch_ns(t3).unwrap();

        assert!(e1 < e2, "Ordering should be preserved");
        assert!(e2 < e3, "Ordering should be preserved");
        assert_eq!(e2 - e1, 1_000_000_000, "Delta should be 1 second");
    }

    #[test]
    fn auto_refresh_on_interval() {
        use std::thread;

        let mut cache =
            MonotonicOffsetCache::with_refresh_interval(Duration::from_millis(50)).unwrap();

        let initial = cache.last_update();

        thread::sleep(Duration::from_millis(100));

        let _ = cache.get_offset().unwrap();

        assert!(cache.last_update() > initial);
    }
}
