//! Time Model — THE CORE DIFFERENTIATOR
//!
//! Time is queryable like data. Every command in Connector can operate:
//! - now
//! - in the past
//! - across a time range
//! - at a specific event point
//!
//! This is Connector's Git + Flight Recorder + Audit OS advantage.

use serde::{Deserialize, Serialize};
use std::str::FromStr;

// ═══════════════════════════════════════════════════════════════
// Time Selector — First-Class Time Navigation
// ═══════════════════════════════════════════════════════════════

/// Time selector for querying system state at any point in time.
///
/// Supports:
/// - Absolute timestamps
/// - Relative durations (last 10m)
/// - Event-based references (at/before/after event)
/// - Snapshot references
/// - Time ranges
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TimeSelector {
    /// Current time (default)
    Now,

    /// Absolute point in time
    /// `--at 2026-03-21T10:30:00Z`
    At(TimePoint),

    /// Relative past duration
    /// `--last 10m`, `--last 2h`, `--last 1d`
    Last(Duration),

    /// Rolling window
    /// `--window 5m`
    Window(Duration),

    /// Time range
    /// `--range 10:00..10:05` or `--since 10:00 --until 10:05`
    Range(TimeRange),

    /// Before a specific event
    /// `--before act_8831`
    Before(EventRef),

    /// After a specific event
    /// `--after act_8831`
    After(EventRef),

    /// At a specific snapshot
    /// `--snapshot snap_441`
    Snapshot(String),
}

impl Default for TimeSelector {
    fn default() -> Self {
        Self::Now
    }
}

impl TimeSelector {
    /// Create a selector for "now"
    pub fn now() -> Self {
        Self::Now
    }

    /// Create a selector for an absolute timestamp
    pub fn at(timestamp: i64) -> Self {
        Self::At(TimePoint::Timestamp(timestamp))
    }

    /// Create a selector for a relative duration
    pub fn last(duration: Duration) -> Self {
        Self::Last(duration)
    }

    /// Create a selector for a time range
    pub fn range(start: TimePoint, end: TimePoint) -> Self {
        Self::Range(TimeRange { start, end })
    }

    /// Create a selector for before an event
    pub fn before(event_id: impl Into<String>) -> Self {
        Self::Before(EventRef { event_id: event_id.into() })
    }

    /// Create a selector for after an event
    pub fn after(event_id: impl Into<String>) -> Self {
        Self::After(EventRef { event_id: event_id.into() })
    }

    /// Create a selector for a snapshot
    pub fn snapshot(snapshot_id: impl Into<String>) -> Self {
        Self::Snapshot(snapshot_id.into())
    }

    /// Check if this selector is for current time
    pub fn is_now(&self) -> bool {
        matches!(self, Self::Now)
    }

    /// Check if this selector is time-travel (past inspection)
    pub fn is_time_travel(&self) -> bool {
        !self.is_now()
    }

    /// Resolve to a concrete timestamp range (for queries)
    pub fn resolve(&self, now_ms: i64) -> ResolvedTimeRange {
        match self {
            Self::Now => ResolvedTimeRange::point(now_ms),
            Self::At(point) => ResolvedTimeRange::point(point.resolve(now_ms)),
            Self::Last(duration) => {
                let end = now_ms;
                let start = end - duration.as_millis();
                ResolvedTimeRange::range(start, end)
            }
            Self::Window(duration) => {
                let end = now_ms;
                let start = end - duration.as_millis();
                ResolvedTimeRange::range(start, end)
            }
            Self::Range(range) => {
                ResolvedTimeRange::range(
                    range.start.resolve(now_ms),
                    range.end.resolve(now_ms),
                )
            }
            Self::Before(event_ref) => {
                // Event resolution requires external lookup
                ResolvedTimeRange::event_relative(event_ref.event_id.clone(), -1)
            }
            Self::After(event_ref) => {
                ResolvedTimeRange::event_relative(event_ref.event_id.clone(), 1)
            }
            Self::Snapshot(snapshot_id) => {
                ResolvedTimeRange::snapshot(snapshot_id.clone())
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Time Point — A single point in time
// ═══════════════════════════════════════════════════════════════

/// A single point in time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TimePoint {
    /// Absolute timestamp (milliseconds since epoch)
    Timestamp(i64),

    /// ISO 8601 datetime string
    Iso8601(String),

    /// Time of day (HH:MM or HH:MM:SS)
    TimeOfDay(String),

    /// Event reference
    Event(String),
}

impl TimePoint {
    /// Resolve to a concrete timestamp
    pub fn resolve(&self, now_ms: i64) -> i64 {
        match self {
            Self::Timestamp(ts) => *ts,
            Self::Iso8601(s) => parse_iso8601(s).unwrap_or(now_ms),
            Self::TimeOfDay(s) => parse_time_of_day(s, now_ms).unwrap_or(now_ms),
            Self::Event(_) => now_ms, // Requires external lookup
        }
    }
}

impl From<i64> for TimePoint {
    fn from(ts: i64) -> Self {
        Self::Timestamp(ts)
    }
}

impl From<&str> for TimePoint {
    fn from(s: &str) -> Self {
        if s.contains('T') || s.contains('-') {
            Self::Iso8601(s.to_string())
        } else if s.contains(':') {
            Self::TimeOfDay(s.to_string())
        } else if let Ok(ts) = s.parse::<i64>() {
            Self::Timestamp(ts)
        } else {
            Self::Event(s.to_string())
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Time Range — A span of time
// ═══════════════════════════════════════════════════════════════

/// A range of time between two points.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: TimePoint,
    pub end: TimePoint,
}

impl TimeRange {
    pub fn new(start: TimePoint, end: TimePoint) -> Self {
        Self { start, end }
    }

    /// Parse a range string like "10:00..10:05"
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split("..").collect();
        if parts.len() == 2 {
            Some(Self {
                start: TimePoint::from(parts[0]),
                end: TimePoint::from(parts[1]),
            })
        } else {
            None
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Duration — Relative time spans
// ═══════════════════════════════════════════════════════════════

/// A duration of time (e.g., 10m, 2h, 1d).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Duration {
    pub value: u64,
    pub unit: DurationUnit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DurationUnit {
    Milliseconds,
    Seconds,
    Minutes,
    Hours,
    Days,
    Weeks,
}

impl Duration {
    pub fn milliseconds(value: u64) -> Self {
        Self { value, unit: DurationUnit::Milliseconds }
    }

    pub fn seconds(value: u64) -> Self {
        Self { value, unit: DurationUnit::Seconds }
    }

    pub fn minutes(value: u64) -> Self {
        Self { value, unit: DurationUnit::Minutes }
    }

    pub fn hours(value: u64) -> Self {
        Self { value, unit: DurationUnit::Hours }
    }

    pub fn days(value: u64) -> Self {
        Self { value, unit: DurationUnit::Days }
    }

    pub fn weeks(value: u64) -> Self {
        Self { value, unit: DurationUnit::Weeks }
    }

    /// Convert to milliseconds
    pub fn as_millis(&self) -> i64 {
        let multiplier = match self.unit {
            DurationUnit::Milliseconds => 1,
            DurationUnit::Seconds => 1_000,
            DurationUnit::Minutes => 60_000,
            DurationUnit::Hours => 3_600_000,
            DurationUnit::Days => 86_400_000,
            DurationUnit::Weeks => 604_800_000,
        };
        (self.value as i64) * multiplier
    }
}

impl FromStr for Duration {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Err("Empty duration string".into());
        }

        // Find where digits end and unit begins
        let digit_end = s.chars().take_while(|c| c.is_ascii_digit()).count();
        if digit_end == 0 {
            return Err(format!("Invalid duration: {}", s));
        }

        let value: u64 = s[..digit_end].parse()
            .map_err(|_| format!("Invalid duration value: {}", &s[..digit_end]))?;

        let unit_str = &s[digit_end..];
        let unit = match unit_str {
            "ms" => DurationUnit::Milliseconds,
            "s" => DurationUnit::Seconds,
            "m" => DurationUnit::Minutes,
            "h" => DurationUnit::Hours,
            "d" => DurationUnit::Days,
            "w" => DurationUnit::Weeks,
            "" => DurationUnit::Seconds, // Default to seconds
            _ => return Err(format!("Unknown duration unit: {}", unit_str)),
        };

        Ok(Self { value, unit })
    }
}

impl std::fmt::Display for Duration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let unit = match self.unit {
            DurationUnit::Milliseconds => "ms",
            DurationUnit::Seconds => "s",
            DurationUnit::Minutes => "m",
            DurationUnit::Hours => "h",
            DurationUnit::Days => "d",
            DurationUnit::Weeks => "w",
        };
        write!(f, "{}{}", self.value, unit)
    }
}

// ═══════════════════════════════════════════════════════════════
// Event Reference — Reference to a specific event
// ═══════════════════════════════════════════════════════════════

/// Reference to a specific event in the system.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventRef {
    pub event_id: String,
}

impl EventRef {
    pub fn new(event_id: impl Into<String>) -> Self {
        Self { event_id: event_id.into() }
    }
}

// ═══════════════════════════════════════════════════════════════
// Resolved Time Range — Concrete time bounds for queries
// ═══════════════════════════════════════════════════════════════

/// A resolved time range ready for database queries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ResolvedTimeRange {
    /// Single point in time
    Point { timestamp_ms: i64 },

    /// Range of time
    Range { start_ms: i64, end_ms: i64 },

    /// Relative to an event (requires external lookup)
    EventRelative { event_id: String, direction: i8 },

    /// At a snapshot (requires external lookup)
    Snapshot { snapshot_id: String },
}

impl ResolvedTimeRange {
    pub fn point(timestamp_ms: i64) -> Self {
        Self::Point { timestamp_ms }
    }

    pub fn range(start_ms: i64, end_ms: i64) -> Self {
        Self::Range { start_ms, end_ms }
    }

    pub fn event_relative(event_id: String, direction: i8) -> Self {
        Self::EventRelative { event_id, direction }
    }

    pub fn snapshot(snapshot_id: String) -> Self {
        Self::Snapshot { snapshot_id }
    }

    /// Check if this is a point query (vs range)
    pub fn is_point(&self) -> bool {
        matches!(self, Self::Point { .. })
    }

    /// Check if this requires external resolution
    pub fn needs_resolution(&self) -> bool {
        matches!(self, Self::EventRelative { .. } | Self::Snapshot { .. })
    }
}

// ═══════════════════════════════════════════════════════════════
// Parsing Helpers
// ═══════════════════════════════════════════════════════════════

fn parse_iso8601(s: &str) -> Option<i64> {
    // Simplified ISO 8601 parsing
    // Format: 2026-03-21T10:30:00Z
    // In production, use chrono or time crate
    if s.len() >= 19 {
        // Basic validation
        if s.contains('T') && (s.ends_with('Z') || s.contains('+') || s.contains('-')) {
            // Placeholder: return current time
            // Real implementation would parse the string
            Some(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64)
        } else {
            None
        }
    } else {
        None
    }
}

fn parse_time_of_day(s: &str, now_ms: i64) -> Option<i64> {
    // Parse HH:MM or HH:MM:SS
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() >= 2 {
        let hours: i64 = parts[0].parse().ok()?;
        let minutes: i64 = parts[1].parse().ok()?;
        let seconds: i64 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);

        // Calculate milliseconds from midnight
        let time_ms = (hours * 3600 + minutes * 60 + seconds) * 1000;

        // Get today's midnight
        let day_ms = 86_400_000i64;
        let today_midnight = (now_ms / day_ms) * day_ms;

        Some(today_midnight + time_ms)
    } else {
        None
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duration_parse() {
        assert_eq!(
            "10m".parse::<Duration>().unwrap(),
            Duration::minutes(10)
        );
        assert_eq!(
            "2h".parse::<Duration>().unwrap(),
            Duration::hours(2)
        );
        assert_eq!(
            "1d".parse::<Duration>().unwrap(),
            Duration::days(1)
        );
        assert_eq!(
            "500ms".parse::<Duration>().unwrap(),
            Duration::milliseconds(500)
        );
    }

    #[test]
    fn test_duration_as_millis() {
        assert_eq!(Duration::seconds(1).as_millis(), 1_000);
        assert_eq!(Duration::minutes(1).as_millis(), 60_000);
        assert_eq!(Duration::hours(1).as_millis(), 3_600_000);
        assert_eq!(Duration::days(1).as_millis(), 86_400_000);
    }

    #[test]
    fn test_time_range_parse() {
        let range = TimeRange::parse("10:00..10:05").unwrap();
        assert!(matches!(range.start, TimePoint::TimeOfDay(_)));
        assert!(matches!(range.end, TimePoint::TimeOfDay(_)));
    }

    #[test]
    fn test_time_selector_is_time_travel() {
        assert!(!TimeSelector::Now.is_time_travel());
        assert!(TimeSelector::at(1234567890).is_time_travel());
        assert!(TimeSelector::last(Duration::minutes(10)).is_time_travel());
        assert!(TimeSelector::before("act_001").is_time_travel());
    }

    #[test]
    fn test_time_selector_resolve() {
        let now = 1_000_000_000i64;
        
        let resolved = TimeSelector::Now.resolve(now);
        assert!(matches!(resolved, ResolvedTimeRange::Point { timestamp_ms: 1_000_000_000 }));

        let resolved = TimeSelector::last(Duration::minutes(10)).resolve(now);
        if let ResolvedTimeRange::Range { start_ms, end_ms } = resolved {
            assert_eq!(end_ms, now);
            assert_eq!(start_ms, now - 600_000);
        } else {
            panic!("Expected Range");
        }
    }
}
