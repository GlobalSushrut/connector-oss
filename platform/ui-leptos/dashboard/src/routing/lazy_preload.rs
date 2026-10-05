//! Prefetch hooks — no-op under Trunk (eager plugin routes).
//! With `cargo leptos build --split`, restore LazyRoute::preload here.

#![cfg(feature = "full-pages")]

pub fn preload_on_hover(_path: &str) {}
