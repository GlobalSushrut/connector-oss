//! Surface Adapter — SurfaceRenderable trait for domain-to-surface conversion

use super::document::{SurfaceDocument, SurfaceView};

/// Trait for types that can be rendered as a surface document
pub trait SurfaceRenderable {
    /// Convert to a surface document with the given view mode
    fn to_surface(&self, view: SurfaceView) -> SurfaceDocument;
    
    /// Get the default view for this type
    fn default_view(&self) -> SurfaceView { SurfaceView::Summary }
}

/// Adapter context for surface generation
#[derive(Debug, Clone)]
pub struct SurfaceContext {
    pub view: SurfaceView,
    pub time_range: Option<String>,
    pub namespace: Option<String>,
    pub include_raw: bool,
    pub max_items: usize,
}

impl Default for SurfaceContext {
    fn default() -> Self {
        Self { view: SurfaceView::Summary, time_range: None, namespace: None, include_raw: false, max_items: 50 }
    }
}

impl SurfaceContext {
    pub fn ops() -> Self { Self { view: SurfaceView::Ops, ..Default::default() } }
    pub fn forensic() -> Self { Self { view: SurfaceView::Forensic, include_raw: true, ..Default::default() } }
    pub fn exec() -> Self { Self { view: SurfaceView::Exec, ..Default::default() } }
}
