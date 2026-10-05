use tokio::sync::{broadcast, watch};

/// Ordered shutdown phases for supervised children.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownPhase {
    Running,
    Draining,
    Stopped,
}

/// Coordinates graceful shutdown across tasks (broadcast + last-writer-wins phase).
#[derive(Clone)]
pub struct ShutdownCoordinator {
    tx: broadcast::Sender<()>,
    phase: watch::Sender<ShutdownPhase>,
}

impl ShutdownCoordinator {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(16);
        let (phase, _) = watch::channel(ShutdownPhase::Running);
        Self { tx, phase }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.tx.subscribe()
    }

    pub fn phase_rx(&self) -> watch::Receiver<ShutdownPhase> {
        self.phase.subscribe()
    }

    pub fn current_phase(&self) -> ShutdownPhase {
        *self.phase.borrow()
    }

    /// Signal all subscribers to begin shutdown (idempotent for receivers still listening).
    pub fn signal(&self) {
        let _ = self.tx.send(());
        let _ = self.phase.send(ShutdownPhase::Draining);
    }

    pub fn mark_stopped(&self) {
        let _ = self.phase.send(ShutdownPhase::Stopped);
    }
}

impl Default for ShutdownCoordinator {
    fn default() -> Self {
        Self::new()
    }
}
