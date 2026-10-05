//! Pagination, Filtering, Search — Enterprise data handling
//!
//! Handles large datasets with proper pagination, filtering, and search.

use serde::{Deserialize, Serialize};

/// Pagination request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageRequest {
    pub page: usize,
    pub page_size: usize,
    pub cursor: Option<String>,
}

impl Default for PageRequest {
    fn default() -> Self { Self { page: 1, page_size: 50, cursor: None } }
}

impl PageRequest {
    pub fn new(page: usize, page_size: usize) -> Self { Self { page, page_size, cursor: None } }
    pub fn first(size: usize) -> Self { Self { page: 1, page_size: size, cursor: None } }
    pub fn with_cursor(cursor: &str, size: usize) -> Self { Self { page: 1, page_size: size, cursor: Some(cursor.into()) } }
    pub fn offset(&self) -> usize { (self.page - 1) * self.page_size }
}

/// Pagination response metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageInfo {
    pub page: usize,
    pub page_size: usize,
    pub total_items: usize,
    pub total_pages: usize,
    pub has_next: bool,
    pub has_prev: bool,
    pub next_cursor: Option<String>,
}

impl PageInfo {
    pub fn new(page: usize, page_size: usize, total_items: usize) -> Self {
        let total_pages = (total_items + page_size - 1) / page_size;
        Self { page, page_size, total_items, total_pages, has_next: page < total_pages, has_prev: page > 1, next_cursor: None }
    }

    pub fn display(&self) -> String {
        format!("Showing {}-{} of {} items", (self.page - 1) * self.page_size + 1, ((self.page - 1) * self.page_size + self.page_size).min(self.total_items), self.total_items)
    }

    pub fn page_links(&self) -> String {
        let mut links = Vec::new();
        if self.has_prev { links.push("[Prev]".to_string()); }
        let start = 1.max(self.page.saturating_sub(2));
        let end = self.total_pages.min(self.page + 2);
        for p in start..=end {
            if p == self.page { links.push(format!("[{}]", p)); }
            else { links.push(format!("{}", p)); }
        }
        if end < self.total_pages { links.push("...".to_string()); links.push(format!("{}", self.total_pages)); }
        if self.has_next { links.push("[Next]".to_string()); }
        links.join(" ")
    }
}

/// Filter expression for querying
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Filter {
    pub field: String,
    pub op: FilterOp,
    pub value: FilterValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilterOp { Eq, Ne, Gt, Gte, Lt, Lte, Contains, StartsWith, EndsWith, In, NotIn }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilterValue {
    String(String),
    Number(f64),
    Bool(bool),
    List(Vec<String>),
}

impl Filter {
    pub fn eq(field: &str, value: &str) -> Self { Self { field: field.into(), op: FilterOp::Eq, value: FilterValue::String(value.into()) } }
    pub fn gt(field: &str, value: f64) -> Self { Self { field: field.into(), op: FilterOp::Gt, value: FilterValue::Number(value) } }
    pub fn contains(field: &str, value: &str) -> Self { Self { field: field.into(), op: FilterOp::Contains, value: FilterValue::String(value.into()) } }
    pub fn in_list(field: &str, values: Vec<&str>) -> Self { Self { field: field.into(), op: FilterOp::In, value: FilterValue::List(values.into_iter().map(|s| s.into()).collect()) } }

    /// Parse filter from CLI string like "size>1MB" or "severity=critical"
    pub fn parse(s: &str) -> Option<Self> {
        let ops = [(">=", FilterOp::Gte), ("<=", FilterOp::Lte), ("!=", FilterOp::Ne), (">", FilterOp::Gt), ("<", FilterOp::Lt), ("=", FilterOp::Eq)];
        for (op_str, op) in ops {
            if let Some(idx) = s.find(op_str) {
                let field = s[..idx].trim().to_string();
                let value = s[idx + op_str.len()..].trim().to_string();
                return Some(Self { field, op, value: FilterValue::String(value) });
            }
        }
        None
    }
}

/// Search query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchQuery {
    pub query: String,
    pub fields: Vec<String>,
    pub fuzzy: bool,
    pub highlight: bool,
}

impl SearchQuery {
    pub fn new(query: &str) -> Self { Self { query: query.into(), fields: vec![], fuzzy: false, highlight: true } }
    pub fn in_fields(mut self, fields: Vec<&str>) -> Self { self.fields = fields.into_iter().map(|s| s.into()).collect(); self }
    pub fn fuzzy(mut self) -> Self { self.fuzzy = true; self }
}

/// Sort specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sort {
    pub field: String,
    pub direction: SortDirection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SortDirection { Asc, Desc }

impl Sort {
    pub fn asc(field: &str) -> Self { Self { field: field.into(), direction: SortDirection::Asc } }
    pub fn desc(field: &str) -> Self { Self { field: field.into(), direction: SortDirection::Desc } }
}

/// Complete query specification
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Query {
    pub filters: Vec<Filter>,
    pub search: Option<SearchQuery>,
    pub sort: Vec<Sort>,
    pub page: PageRequest,
}

impl Query {
    pub fn new() -> Self { Self::default() }
    pub fn filter(mut self, f: Filter) -> Self { self.filters.push(f); self }
    pub fn search(mut self, q: SearchQuery) -> Self { self.search = Some(q); self }
    pub fn sort_by(mut self, s: Sort) -> Self { self.sort.push(s); self }
    pub fn paginate(mut self, page: usize, size: usize) -> Self { self.page = PageRequest::new(page, size); self }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_info() {
        let info = PageInfo::new(2, 50, 1247);
        assert_eq!(info.total_pages, 25);
        assert!(info.has_next);
        assert!(info.has_prev);
    }

    #[test]
    fn test_filter_parse() {
        let f = Filter::parse("size>1MB").unwrap();
        assert_eq!(f.field, "size");
        assert_eq!(f.op, FilterOp::Gt);

        let f = Filter::parse("severity=critical").unwrap();
        assert_eq!(f.field, "severity");
        assert_eq!(f.op, FilterOp::Eq);
    }
}
