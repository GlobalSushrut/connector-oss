//! Concurrency plane — KernelHandle (Activity I/O) and per-agent IntelligenceCell (IAC).
//!
//! Rule: async HTTP handlers must not hold `kernel.lock()` across `.await`.
//! WM/VAC/RAG I/O goes through [`kernel_handle`] via `spawn_blocking`.

pub mod intelligence_cell;
pub mod kernel_handle;
pub mod session_owner;
pub mod workload_bulkhead;
