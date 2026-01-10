//! NTP synchronization monitoring for distributed tracing.

use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

const NANOS_PER_SEC: f64 = 1e9;

/// NTP synchronization status from chrony.
#[derive(Debug, Clone, Default)]
pub struct NtpStatus {
    pub synchronized: bool,
    /// Current offset from NTP server in nanoseconds (positive = local ahead).
    pub offset_ns: i64,
    pub stratum: u8,
    pub captured_at: Option<Instant>,
}

impl NtpStatus {
    pub fn sync_status(&self) -> NtpSyncStatus {
        if !self.synchronized {
            NtpSyncStatus::Unsynchronized
        } else if self.offset_ns.abs() > 50_000_000 {
            NtpSyncStatus::Degraded
        } else {
            NtpSyncStatus::Synchronized
        }
    }
}

#[derive(Debug, Clone, Default)]
pub enum NtpSyncStatus {
    Synchronized,
    Degraded,
    #[default]
    Unsynchronized,
}

/// Queries chrony and caches results to avoid excessive subprocess spawning.
#[derive(Default)]
pub struct NtpMonitor {
    cached_status: Option<NtpStatus>,
    cache_duration: Duration,
}

impl NtpMonitor {
    const DEFAULT_CACHE_DURATION: Duration = Duration::from_secs(5);

    /// Reference IDs indicating non-synchronized states.
    const CHRONY_REFID_UNSYNCED: &'static str = "00000000";
    const CHRONY_REFID_LOCALHOST: &'static str = "7F7F0101";

    pub fn new() -> Self {
        Self {
            cached_status: None,
            cache_duration: Self::DEFAULT_CACHE_DURATION,
        }
    }

    /// Get the current NTP status, using cache if valid.
    pub fn get_status(&mut self) -> Result<NtpStatus> {
        if let Some(ref status) = self.cached_status {
            if let Some(captured_at) = status.captured_at {
                if captured_at.elapsed() < self.cache_duration {
                    return Ok(status.clone());
                }
            }
        }

        let status = self.query_chrony()?;
        self.cached_status = Some(status.clone());
        Ok(status)
    }

    fn query_chrony(&self) -> Result<NtpStatus> {
        let output = Command::new("chronyc")
            .args(["-c", "tracking"])
            .output()
            .context("Failed to run chronyc")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("chronyc failed: {}", stderr);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_chrony_output(&stdout)
    }

    fn parse_chrony_output(&self, output: &str) -> Result<NtpStatus> {
        let line = output.trim();
        if line.is_empty() {
            bail!("Empty output from chronyc");
        }

        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 13 {
            bail!(
                "Unexpected chronyc output format: expected 13+ fields, got {}",
                fields.len()
            );
        }

        let ref_id = fields[0];
        let synchronized =
            ref_id != Self::CHRONY_REFID_UNSYNCED && ref_id != Self::CHRONY_REFID_LOCALHOST;

        let stratum: u8 = fields[2].parse().context("Failed to parse stratum")?;

        let offset_sec: f64 = fields[4].parse().context("Failed to parse offset")?;
        let offset_ns = (offset_sec * NANOS_PER_SEC) as i64;

        Ok(NtpStatus {
            synchronized,
            offset_ns,
            stratum,
            captured_at: Some(Instant::now()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_chrony_output() {
        let monitor = NtpMonitor::new();

        // Synchronized.
        let output = "C0A80001,192.168.0.1,2,1234567890.123,-0.000001234,\
                      -0.000001234,0.000000567,1.234,0.001,0.002,0.015,\
                      0.001,64,Normal";
        let status = monitor.parse_chrony_output(output).unwrap();
        assert!(status.synchronized);
        assert_eq!(status.stratum, 2);
        assert!(status.offset_ns < 0);

        // Unsynchronized (null refid).
        let output = "00000000,,16,0,0,0,0,0,0,0,0,0,0,Not synchronised";
        let status = monitor.parse_chrony_output(output).unwrap();
        assert!(!status.synchronized);
        assert_eq!(status.stratum, 16);

        // Unsynchronized (localhost refid).
        let output = "7F7F0101,127.127.1.1,10,0,0,0,0,0,0,0,0,0.001,0,Normal";
        let status = monitor.parse_chrony_output(output).unwrap();
        assert!(!status.synchronized);
    }

    #[test]
    fn sync_status_classification() {
        // Synchronized.
        let status = NtpStatus {
            synchronized: true,
            offset_ns: 1_000_000, // 1ms
            stratum: 2,
            captured_at: None,
        };
        assert!(matches!(status.sync_status(), NtpSyncStatus::Synchronized));

        // Degraded - high offset.
        let status = NtpStatus {
            synchronized: true,
            offset_ns: 100_000_000, // 100ms
            stratum: 2,
            captured_at: None,
        };
        assert!(matches!(status.sync_status(), NtpSyncStatus::Degraded));

        // Unsynchronized.
        let status = NtpStatus {
            synchronized: false,
            ..Default::default()
        };
        assert!(matches!(
            status.sync_status(),
            NtpSyncStatus::Unsynchronized
        ));
    }
}
