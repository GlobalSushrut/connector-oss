//! Domain-specific surface generators

pub mod agent;
pub mod audit;
pub mod compliance;
pub mod debug;
pub mod books;

pub use agent::build_agent_surface;
pub use audit::build_audit_surface;
pub use compliance::build_compliance_surface;
pub use debug::build_debug_surface;
pub use books::build_books_surface;
