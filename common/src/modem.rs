//! Shared policy for the passive `openat` modem access adapter.

use crate::{DefenseAlert, ALERT_MODEM_TAMPER};

pub const MODEM_PATH_BYTES: usize = 128;
pub const MODEM_ACCESS_OPENAT: u32 = 1;

/// Exact, NUL-terminated syscall pathname match, not an inode or prefix match.
/// Configured paths must leave two bytes free so a truncated read cannot match.
pub fn modem_access_alert(
    requested: &[u8; MODEM_PATH_BYTES],
    monitored: &[u8; MODEM_PATH_BYTES],
    authorized: bool,
    pid: u32,
    timestamp_ns: u64,
) -> Option<DefenseAlert> {
    if authorized || monitored[0] == 0 {
        return None;
    }
    let mut i = 0;
    while i < MODEM_PATH_BYTES - 1 {
        if requested[i] != monitored[i] {
            return None;
        }
        if monitored[i] == 0 {
            let mut details = [0; 16];
            details[..4].copy_from_slice(&MODEM_ACCESS_OPENAT.to_le_bytes());
            return Some(DefenseAlert {
                alert_type: ALERT_MODEM_TAMPER,
                severity: 4,
                pid,
                _pad: 0,
                timestamp_ns,
                context: pid as u64,
                details,
            });
        }
        i += 1;
    }
    None
}
