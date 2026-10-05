//! Streaming Surface — Real-time output for Monitor surface
//!
//! Following Books JournalBus pattern: surfaces can stream live events.

use super::document::*;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

/// Live surface event for streaming
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceEvent {
    pub event_id: String,
    pub timestamp: i64,
    pub event_type: SurfaceEventType,
    pub subject_id: String,
    pub payload: SurfaceEventPayload,
    pub severity: Severity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SurfaceEventType {
    // Agent events
    AgentStart, AgentStop, AgentPause, AgentResume,
    // Memory events
    MemoryRead, MemoryWrite, MemoryDelete, MemoryPromote,
    // Tool events
    ToolCall, ToolResult, ToolError,
    // Decision events
    DecisionMade, DecisionBlocked, DecisionOverride,
    // Policy events
    PolicyCheck, PolicyDenied, PolicyWarning,
    // Proof events
    ReceiptCreated, ChainVerified, ChainBroken,
    // System events
    Heartbeat, Error, Warning, Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SurfaceEventPayload {
    Text(String),
    Metric { name: String, value: f64, unit: String },
    Trace { span_id: String, duration_ms: u64 },
    Evidence { cid: String, verified: bool },
    Error { code: String, message: String },
    Json(serde_json::Value),
}

impl SurfaceEvent {
    pub fn new(event_type: SurfaceEventType, subject_id: &str, payload: SurfaceEventPayload) -> Self {
        Self {
            event_id: format!("evt_{}", chrono::Utc::now().timestamp_millis()),
            timestamp: chrono::Utc::now().timestamp_millis(),
            event_type,
            subject_id: subject_id.to_string(),
            payload,
            severity: Severity::Info,
        }
    }

    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    pub fn to_timeline_event(&self) -> TimelineEvent {
        let ts = chrono::DateTime::from_timestamp_millis(self.timestamp)
            .map(|dt| dt.format("%H:%M:%S%.3f").to_string())
            .unwrap_or_else(|| self.timestamp.to_string());
        
        let message = match &self.payload {
            SurfaceEventPayload::Text(t) => t.clone(),
            SurfaceEventPayload::Metric { name, value, unit } => format!("{}: {}{}", name, value, unit),
            SurfaceEventPayload::Trace { span_id, duration_ms } => format!("{} ({}ms)", span_id, duration_ms),
            SurfaceEventPayload::Evidence { cid, verified } => format!("{} {}", cid, if *verified { "✓" } else { "?" }),
            SurfaceEventPayload::Error { code, message } => format!("{}: {}", code, message),
            SurfaceEventPayload::Json(v) => serde_json::to_string(v).unwrap_or_default(),
        };

        TimelineEvent {
            timestamp: ts,
            event_type: format!("{:?}", self.event_type),
            message,
            severity: self.severity,
            link: None,
        }
    }
}

/// Subscriber handle for receiving events
pub struct SurfaceSubscriber {
    receiver: std::sync::mpsc::Receiver<SurfaceEvent>,
}

impl SurfaceSubscriber {
    pub fn recv(&self) -> Option<SurfaceEvent> {
        self.receiver.recv().ok()
    }

    pub fn try_recv(&self) -> Option<SurfaceEvent> {
        self.receiver.try_recv().ok()
    }

    pub fn recv_timeout(&self, timeout: std::time::Duration) -> Option<SurfaceEvent> {
        self.receiver.recv_timeout(timeout).ok()
    }
}

/// Event bus for streaming surfaces
pub struct SurfaceBus {
    senders: Arc<Mutex<Vec<std::sync::mpsc::Sender<SurfaceEvent>>>>,
    buffer: Arc<Mutex<Vec<SurfaceEvent>>>,
    buffer_size: usize,
}

impl Default for SurfaceBus {
    fn default() -> Self { Self::new(1000) }
}

impl SurfaceBus {
    pub fn new(buffer_size: usize) -> Self {
        Self {
            senders: Arc::new(Mutex::new(Vec::new())),
            buffer: Arc::new(Mutex::new(Vec::new())),
            buffer_size,
        }
    }

    /// Subscribe to events
    pub fn subscribe(&self) -> SurfaceSubscriber {
        let (tx, rx) = std::sync::mpsc::channel();
        self.senders.lock().unwrap().push(tx);
        SurfaceSubscriber { receiver: rx }
    }

    /// Publish an event to all subscribers
    pub fn publish(&self, event: SurfaceEvent) {
        // Buffer event
        {
            let mut buffer = self.buffer.lock().unwrap();
            if buffer.len() >= self.buffer_size {
                buffer.remove(0);
            }
            buffer.push(event.clone());
        }

        // Send to subscribers
        let mut senders = self.senders.lock().unwrap();
        senders.retain(|tx| tx.send(event.clone()).is_ok());
    }

    /// Get buffered events
    pub fn buffered(&self) -> Vec<SurfaceEvent> {
        self.buffer.lock().unwrap().clone()
    }

    /// Get buffered events since timestamp
    pub fn since(&self, timestamp: i64) -> Vec<SurfaceEvent> {
        self.buffer.lock().unwrap()
            .iter()
            .filter(|e| e.timestamp >= timestamp)
            .cloned()
            .collect()
    }

    /// Clear buffer
    pub fn clear(&self) {
        self.buffer.lock().unwrap().clear();
    }

    /// Number of active subscribers
    pub fn subscriber_count(&self) -> usize {
        self.senders.lock().unwrap().len()
    }
}

/// Live surface that updates in real-time
#[derive(Debug, Clone)]
pub struct LiveSurface {
    pub subject_id: String,
    pub surface_type: SurfaceType,
    pub events: Vec<SurfaceEvent>,
    pub max_events: usize,
    pub started_at: i64,
}

impl LiveSurface {
    pub fn new(subject_id: &str, surface_type: SurfaceType) -> Self {
        Self {
            subject_id: subject_id.to_string(),
            surface_type,
            events: Vec::new(),
            max_events: 100,
            started_at: chrono::Utc::now().timestamp_millis(),
        }
    }

    pub fn push(&mut self, event: SurfaceEvent) {
        if self.events.len() >= self.max_events {
            self.events.remove(0);
        }
        self.events.push(event);
    }

    pub fn to_document(&self, view: SurfaceView) -> SurfaceDocument {
        let timeline_events: Vec<TimelineEvent> = self.events.iter()
            .rev()
            .take(50)
            .map(|e| e.to_timeline_event())
            .collect();

        SurfaceDocument {
            meta: SurfaceMeta {
                surface_type: self.surface_type,
                view,
                generated_at: chrono::Utc::now().timestamp_millis(),
            },
            header: SurfaceHeader {
                title: format!("LIVE: {}", self.subject_id),
                subject: SubjectIdentity::new(ResourceKind::Agent, &self.subject_id),
                state: StateVector::active_verified(),
                badges: vec![
                    SurfaceBadge { label: "Status".into(), value: "STREAMING".into(), severity: Severity::Ok },
                    SurfaceBadge { label: "Events".into(), value: self.events.len().to_string(), severity: Severity::Info },
                ],
                time_range: Some(format!("since {}", self.started_at)),
            },
            summary: Some(format!("Live stream with {} events", self.events.len())),
            sections: vec![
                SurfaceSection {
                    title: "Live Stream".into(),
                    kind: SectionKind::Timeline,
                    content: SectionContent::Timeline(timeline_events),
                    collapsed: false,
                },
            ],
            actions: vec![
                SurfaceAction {
                    label: "Pause".into(),
                    description: "Pause live stream".into(),
                    command: format!("connectorctl monitor {} --pause", self.subject_id),
                    primary: true,
                },
            ],
            footer: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_surface_event() {
        let event = SurfaceEvent::new(
            SurfaceEventType::ToolCall,
            "agent-001",
            SurfaceEventPayload::Text("icd10_lookup".into()),
        );
        assert!(event.event_id.starts_with("evt_"));
    }

    #[test]
    fn test_surface_bus() {
        let bus = SurfaceBus::new(10);
        let sub = bus.subscribe();

        bus.publish(SurfaceEvent::new(
            SurfaceEventType::Heartbeat,
            "agent-001",
            SurfaceEventPayload::Text("alive".into()),
        ));

        let event = sub.try_recv();
        assert!(event.is_some());
    }

    #[test]
    fn test_live_surface() {
        let mut live = LiveSurface::new("agent-001", SurfaceType::Monitor);
        live.push(SurfaceEvent::new(
            SurfaceEventType::ToolCall,
            "agent-001",
            SurfaceEventPayload::Text("test".into()),
        ));
        let doc = live.to_document(SurfaceView::Ops);
        assert!(doc.header.title.contains("LIVE"));
    }
}
