//! Time-Travel Support — CTL time selectors for surfaces
//!
//! Following CTL patterns: surfaces support --at, --since, --range, --last selectors.

use serde::{Deserialize, Serialize};

/// Time selector for surface queries (mirrors CTL TimeSelector)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SurfaceTimeSelector {
    /// Current state (default)
    Now,
    /// Specific point in time
    At(i64),
    /// Since a timestamp
    Since(i64),
    /// Before a timestamp
    Before(i64),
    /// Time range
    Range { start: i64, end: i64 },
    /// Last N duration
    Last(SurfaceDuration),
    /// At a specific event
    AtEvent(String),
    /// At a snapshot
    AtSnapshot(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SurfaceDuration {
    pub value: u64,
    pub unit: DurationUnit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DurationUnit {
    Seconds, Minutes, Hours, Days, Weeks,
}

impl SurfaceDuration {
    pub fn seconds(n: u64) -> Self { Self { value: n, unit: DurationUnit::Seconds } }
    pub fn minutes(n: u64) -> Self { Self { value: n, unit: DurationUnit::Minutes } }
    pub fn hours(n: u64) -> Self { Self { value: n, unit: DurationUnit::Hours } }
    pub fn days(n: u64) -> Self { Self { value: n, unit: DurationUnit::Days } }

    pub fn to_ms(&self) -> i64 {
        let base = self.value as i64;
        match self.unit {
            DurationUnit::Seconds => base * 1000,
            DurationUnit::Minutes => base * 60 * 1000,
            DurationUnit::Hours => base * 60 * 60 * 1000,
            DurationUnit::Days => base * 24 * 60 * 60 * 1000,
            DurationUnit::Weeks => base * 7 * 24 * 60 * 60 * 1000,
        }
    }
}

impl SurfaceTimeSelector {
    /// Resolve to absolute time range
    pub fn resolve(&self, now_ms: i64) -> ResolvedTimeRange {
        match self {
            Self::Now => ResolvedTimeRange { start: now_ms, end: now_ms, is_point: true, is_time_travel: false },
            Self::At(ts) => ResolvedTimeRange { start: *ts, end: *ts, is_point: true, is_time_travel: *ts < now_ms },
            Self::Since(ts) => ResolvedTimeRange { start: *ts, end: now_ms, is_point: false, is_time_travel: true },
            Self::Before(ts) => ResolvedTimeRange { start: 0, end: *ts, is_point: false, is_time_travel: true },
            Self::Range { start, end } => ResolvedTimeRange { start: *start, end: *end, is_point: false, is_time_travel: true },
            Self::Last(dur) => ResolvedTimeRange { start: now_ms - dur.to_ms(), end: now_ms, is_point: false, is_time_travel: true },
            Self::AtEvent(_) | Self::AtSnapshot(_) => ResolvedTimeRange { start: now_ms, end: now_ms, is_point: true, is_time_travel: true },
        }
    }

    /// Parse from CLI string
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s == "now" || s.is_empty() {
            return Some(Self::Now);
        }
        if let Some(ts) = s.strip_prefix("@") {
            return ts.parse().ok().map(Self::At);
        }
        if let Some(ts) = s.strip_prefix("since:") {
            return ts.parse().ok().map(Self::Since);
        }
        if let Some(ts) = s.strip_prefix("before:") {
            return ts.parse().ok().map(Self::Before);
        }
        if let Some(range) = s.strip_prefix("range:") {
            let parts: Vec<&str> = range.split("..").collect();
            if parts.len() == 2 {
                if let (Ok(start), Ok(end)) = (parts[0].parse(), parts[1].parse()) {
                    return Some(Self::Range { start, end });
                }
            }
        }
        if let Some(dur) = s.strip_prefix("last:") {
            return Self::parse_duration(dur).map(Self::Last);
        }
        if let Some(event) = s.strip_prefix("event:") {
            return Some(Self::AtEvent(event.to_string()));
        }
        if let Some(snap) = s.strip_prefix("snapshot:") {
            return Some(Self::AtSnapshot(snap.to_string()));
        }
        None
    }

    fn parse_duration(s: &str) -> Option<SurfaceDuration> {
        let s = s.trim();
        if let Some(n) = s.strip_suffix("s") {
            return n.parse().ok().map(SurfaceDuration::seconds);
        }
        if let Some(n) = s.strip_suffix("m") {
            return n.parse().ok().map(SurfaceDuration::minutes);
        }
        if let Some(n) = s.strip_suffix("h") {
            return n.parse().ok().map(SurfaceDuration::hours);
        }
        if let Some(n) = s.strip_suffix("d") {
            return n.parse().ok().map(SurfaceDuration::days);
        }
        None
    }

    pub fn display(&self) -> String {
        match self {
            Self::Now => "now".into(),
            Self::At(ts) => format!("@{}", ts),
            Self::Since(ts) => format!("since:{}", ts),
            Self::Before(ts) => format!("before:{}", ts),
            Self::Range { start, end } => format!("range:{}..{}", start, end),
            Self::Last(dur) => format!("last:{}{}", dur.value, match dur.unit {
                DurationUnit::Seconds => "s", DurationUnit::Minutes => "m",
                DurationUnit::Hours => "h", DurationUnit::Days => "d", DurationUnit::Weeks => "w",
            }),
            Self::AtEvent(e) => format!("event:{}", e),
            Self::AtSnapshot(s) => format!("snapshot:{}", s),
        }
    }
}

/// Resolved absolute time range
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ResolvedTimeRange {
    pub start: i64,
    pub end: i64,
    pub is_point: bool,
    pub is_time_travel: bool,
}

impl ResolvedTimeRange {
    pub fn duration_ms(&self) -> i64 {
        self.end - self.start
    }

    pub fn contains(&self, ts: i64) -> bool {
        ts >= self.start && ts <= self.end
    }

    pub fn display(&self) -> String {
        if self.is_point {
            format_timestamp(self.start)
        } else {
            format!("{} → {}", format_timestamp(self.start), format_timestamp(self.end))
        }
    }
}

fn format_timestamp(ts: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ts)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| ts.to_string())
}

/// Time-aware surface query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimedSurfaceQuery {
    pub subject_id: String,
    pub time: SurfaceTimeSelector,
    pub resolved: Option<ResolvedTimeRange>,
}

impl TimedSurfaceQuery {
    pub fn new(subject_id: &str, time: SurfaceTimeSelector) -> Self {
        let now = chrono::Utc::now().timestamp_millis();
        let resolved = Some(time.resolve(now));
        Self { subject_id: subject_id.to_string(), time, resolved }
    }

    pub fn now(subject_id: &str) -> Self {
        Self::new(subject_id, SurfaceTimeSelector::Now)
    }

    pub fn at(subject_id: &str, ts: i64) -> Self {
        Self::new(subject_id, SurfaceTimeSelector::At(ts))
    }

    pub fn last(subject_id: &str, dur: SurfaceDuration) -> Self {
        Self::new(subject_id, SurfaceTimeSelector::Last(dur))
    }

    pub fn is_time_travel(&self) -> bool {
        self.resolved.map(|r| r.is_time_travel).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_selector_parse() {
        assert!(matches!(SurfaceTimeSelector::parse("now"), Some(SurfaceTimeSelector::Now)));
        assert!(matches!(SurfaceTimeSelector::parse("@1234567890"), Some(SurfaceTimeSelector::At(1234567890))));
        assert!(matches!(SurfaceTimeSelector::parse("last:5m"), Some(SurfaceTimeSelector::Last(_))));
    }

    #[test]
    fn test_duration() {
        assert_eq!(SurfaceDuration::minutes(5).to_ms(), 5 * 60 * 1000);
        assert_eq!(SurfaceDuration::hours(1).to_ms(), 60 * 60 * 1000);
    }

    #[test]
    fn test_resolve() {
        let now = 1000000;
        let sel = SurfaceTimeSelector::Last(SurfaceDuration::minutes(5));
        let resolved = sel.resolve(now);
        assert_eq!(resolved.start, now - 5 * 60 * 1000);
        assert!(resolved.is_time_travel);
    }
}
