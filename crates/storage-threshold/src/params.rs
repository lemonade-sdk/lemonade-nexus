//! Holder-count and threshold rules (design B4, B5).

use crate::{Result, StorageError};

/// The most holders a plan can have.
pub const MAX_HOLDERS: u16 = 50;

/// The fewest holders a plan can have. Key generation needs at least this
/// many holders (B4, B10). A refresh keeps `t`, and `t = ceil(0.65 × n)`
/// with `t ≥ 4` needs `n ≥ 5`, so no permitted refresh goes below it.
pub const MIN_HOLDERS: u16 = 5;

/// Threshold percentage of holders.
pub const THRESHOLD_PERCENT: u32 = 65;

/// `t = ceil(0.65 × n)` for `1 ≤ n ≤ MAX_HOLDERS`, else `None`.
///
/// Computed as `ceil(65·n / 100)` in integers, so no floating-point rounding
/// can change the result.
pub const fn threshold_for(holder_count: u16) -> Option<u16> {
    if holder_count == 0 || holder_count > MAX_HOLDERS {
        return None;
    }
    let n = holder_count as u32;
    Some((THRESHOLD_PERCENT * n).div_ceil(100) as u16)
}

/// The threshold of a plan with `holder_count` holders.
///
/// Fails with [`StorageError::HolderCount`] outside
/// `MIN_HOLDERS..=MAX_HOLDERS`.
pub fn plan_threshold(holder_count: usize) -> Result<u16> {
    let n = u16::try_from(holder_count).map_err(|_| StorageError::HolderCount)?;
    if !(MIN_HOLDERS..=MAX_HOLDERS).contains(&n) {
        return Err(StorageError::HolderCount);
    }
    threshold_for(n).ok_or(StorageError::HolderCount)
}

/// Whether `t` is the threshold of some permitted plan size.
pub fn is_plan_threshold(t: u16) -> bool {
    (MIN_HOLDERS..=MAX_HOLDERS).any(|n| threshold_for(n) == Some(t))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn design_table() {
        for (n, t) in [(5, 4), (7, 5), (10, 7), (20, 13), (31, 21), (50, 33)] {
            assert_eq!(threshold_for(n), Some(t), "n = {n}");
        }
    }

    #[test]
    fn exact_ceiling_for_every_count() {
        assert_eq!(threshold_for(0), None);
        assert_eq!(threshold_for(MAX_HOLDERS + 1), None);
        for n in 1..=MAX_HOLDERS {
            let t = threshold_for(n).unwrap() as u32;
            let n = n as u32;
            // t is the smallest integer with 100·t ≥ 65·n.
            assert!(100 * t >= 65 * n, "n = {n}");
            assert!(100 * (t - 1) < 65 * n, "n = {n}");
            assert!(t as u32 <= n);
        }
    }

    #[test]
    fn plan_bounds() {
        for n in 0..MIN_HOLDERS as usize {
            assert_eq!(plan_threshold(n), Err(StorageError::HolderCount));
        }
        assert_eq!(plan_threshold(51), Err(StorageError::HolderCount));
        assert_eq!(plan_threshold(70000), Err(StorageError::HolderCount));
        assert_eq!(plan_threshold(5), Ok(4));
        assert_eq!(plan_threshold(50), Ok(33));
    }

    #[test]
    fn refresh_never_drops_below_minimum() {
        // Every n that shares a threshold with a permitted plan is permitted.
        for n in MIN_HOLDERS..=MAX_HOLDERS {
            let t = threshold_for(n).unwrap();
            for m in 1..MIN_HOLDERS {
                assert_ne!(threshold_for(m), Some(t));
            }
        }
    }
}
