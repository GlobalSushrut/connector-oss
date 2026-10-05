//! Compound Surfaces — Multi-domain views for complex queries
//!
//! When a command spans multiple domains, compose surfaces together.

use super::document::*;
use serde::{Deserialize, Serialize};

/// Compound surface combining multiple domain surfaces
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompoundSurface {
    pub primary: SurfaceDocument,
    pub secondary: Vec<SurfaceDocument>,
    pub composition: CompositionStrategy,
    pub title: String,
}

/// How to compose multiple surfaces
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompositionStrategy {
    Sequential,  // Show one after another
    Tabbed,      // Show as tabs (UI)
    Embedded,    // Embed secondary in primary sections
    SideBySide,  // Show side by side (wide terminals)
}

impl CompoundSurface {
    pub fn new(primary: SurfaceDocument) -> Self {
        let title = primary.header.title.clone();
        Self { primary, secondary: vec![], composition: CompositionStrategy::Sequential, title }
    }

    pub fn with_secondary(mut self, doc: SurfaceDocument) -> Self {
        self.secondary.push(doc);
        self
    }

    pub fn composition(mut self, strategy: CompositionStrategy) -> Self {
        self.composition = strategy;
        self
    }

    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

    /// Flatten to a single document (for renderers that don't support compound)
    pub fn flatten(&self) -> SurfaceDocument {
        let mut doc = self.primary.clone();
        doc.header.title = self.title.clone();

        for secondary in &self.secondary {
            // Add a separator section
            doc.sections.push(SurfaceSection {
                title: format!("─── {} ───", secondary.header.title),
                kind: SectionKind::Narrative,
                content: SectionContent::Narrative(secondary.summary.clone().unwrap_or_default()),
                collapsed: false,
            });
            // Add all sections from secondary
            doc.sections.extend(secondary.sections.clone());
            // Merge actions
            doc.actions.extend(secondary.actions.clone());
        }

        doc
    }

    /// Get all surfaces as a list
    pub fn all_surfaces(&self) -> Vec<&SurfaceDocument> {
        let mut all = vec![&self.primary];
        all.extend(self.secondary.iter());
        all
    }
}

/// Builder for compound surfaces
pub struct CompoundBuilder {
    surfaces: Vec<SurfaceDocument>,
    composition: CompositionStrategy,
    title: Option<String>,
}

impl CompoundBuilder {
    pub fn new() -> Self {
        Self { surfaces: vec![], composition: CompositionStrategy::Sequential, title: None }
    }

    pub fn add(mut self, doc: SurfaceDocument) -> Self {
        self.surfaces.push(doc);
        self
    }

    pub fn composition(mut self, strategy: CompositionStrategy) -> Self {
        self.composition = strategy;
        self
    }

    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    pub fn build(self) -> Option<CompoundSurface> {
        if self.surfaces.is_empty() { return None; }
        let mut iter = self.surfaces.into_iter();
        let primary = iter.next()?;
        let title = self.title.unwrap_or_else(|| primary.header.title.clone());
        Some(CompoundSurface {
            title,
            primary,
            secondary: iter.collect(),
            composition: self.composition,
        })
    }
}

impl Default for CompoundBuilder {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::surface::builder::SurfaceBuilder;

    #[test]
    fn test_compound_surface() {
        let agent = SurfaceBuilder::agent("test-001").judgment_ok("OK").build();
        let audit = SurfaceBuilder::audit("test-001").judgment_ok("Verified").build();

        let compound = CompoundSurface::new(agent)
            .with_secondary(audit)
            .title("Agent + Audit View");

        assert_eq!(compound.all_surfaces().len(), 2);
        let flat = compound.flatten();
        assert!(flat.header.title.contains("Agent + Audit"));
    }
}
