//! Holder-count and threshold rules (design B4, B5).

use crate::{Result, StorageError};

/// The most holders a plan can have.
pub const MAX_HOLDERS: u16 = 50;

/// The fewest holders a new storage key can be created with (B4, B10).
pub const MIN_HOLDERS: u16 = 5;

/// The fewest holders a re-share can keep. After holders are lost, Tier 1
/// refreshes the shares or rotates the key while at least this many holders
/// remain (4 holders give `t = 3`, 3 holders give `t = 2`). Below this count
/// the last plan stays in place. A plan with fewer holders cannot exist.
pub const MIN_RESHARE_HOLDERS: u16 = 3;

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

/// The threshold of a plan with `holder_count` holders: the plan of a refresh,
/// a rotation, or the first key.
///
/// Fails with [`StorageError::HolderCount`] outside
/// `MIN_RESHARE_HOLDERS..=MAX_HOLDERS`.
pub fn plan_threshold(holder_count: usize) -> Result<u16> {
    threshold_in(holder_count, MIN_RESHARE_HOLDERS)
}

/// The threshold of the first storage key with `holder_count` holders.
///
/// Fails with [`StorageError::HolderCount`] outside `MIN_HOLDERS..=MAX_HOLDERS`.
pub fn creation_threshold(holder_count: usize) -> Result<u16> {
    threshold_in(holder_count, MIN_HOLDERS)
}

fn threshold_in(holder_count: usize, minimum: u16) -> Result<u16> {
    let n = u16::try_from(holder_count).map_err(|_| StorageError::HolderCount)?;
    if !(minimum..=MAX_HOLDERS).contains(&n) {
        return Err(StorageError::HolderCount);
    }
    threshold_for(n).ok_or(StorageError::HolderCount)
}

/// Whether `t` is the threshold of some permitted plan size.
pub fn is_plan_threshold(t: u16) -> bool {
    (MIN_RESHARE_HOLDERS..=MAX_HOLDERS).any(|n| threshold_for(n) == Some(t))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn design_table() {
        for (n, t) in [(3, 2), (4, 3), (5, 4), (7, 5), (10, 7), (20, 13), (31, 21), (50, 33)] {
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
        for n in 0..MIN_RESHARE_HOLDERS as usize {
            assert_eq!(plan_threshold(n), Err(StorageError::HolderCount));
        }
        assert_eq!(plan_threshold(3), Ok(2));
        assert_eq!(plan_threshold(4), Ok(3));
        assert_eq!(plan_threshold(5), Ok(4));
        assert_eq!(plan_threshold(50), Ok(33));
        assert_eq!(plan_threshold(51), Err(StorageError::HolderCount));
        assert_eq!(plan_threshold(70000), Err(StorageError::HolderCount));
    }

    #[test]
    fn creation_bounds() {
        for n in 0..MIN_HOLDERS as usize {
            assert_eq!(creation_threshold(n), Err(StorageError::HolderCount), "n = {n}");
        }
        assert_eq!(creation_threshold(5), Ok(4));
        assert_eq!(creation_threshold(50), Ok(33));
        assert_eq!(creation_threshold(51), Err(StorageError::HolderCount));
    }

    #[test]
    fn plan_thresholds() {
        // t = 2 (n = 3) is the smallest plan threshold; t = 1 is never one.
        assert!(!is_plan_threshold(1));
        assert!(is_plan_threshold(2));
        assert!(is_plan_threshold(3));
        assert!(is_plan_threshold(33));
        assert!(!is_plan_threshold(34));
    }

    #[test]
    fn refresh_never_drops_below_minimum() {
        // n = 2 shares t = 2 with n = 3, so only the holder-count bound keeps a
        // refresh of a 3-holder plan from going to 2 holders. Above that, no
        // smaller count shares a threshold with a permitted plan.
        assert_eq!(threshold_for(2), threshold_for(3));
        assert_eq!(plan_threshold(2), Err(StorageError::HolderCount));
        for n in (MIN_RESHARE_HOLDERS + 1)..=MAX_HOLDERS {
            let t = threshold_for(n).unwrap();
            for m in 1..MIN_RESHARE_HOLDERS {
                assert_ne!(threshold_for(m), Some(t), "n = {n}, m = {m}");
            }
        }
    }
}
