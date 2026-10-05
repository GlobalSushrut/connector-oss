//! Wave 6 cutover: only auth entry + install + wizards + plugin consoles compile.
//! Demoted dashboard pages are deleted from the build (see UI_GREENFIELD_BUILD_PLAN.md).

pub mod login;
pub mod trial;
pub mod connect_landing;

#[cfg(feature = "full-pages")]
pub mod install;
#[cfg(feature = "full-pages")]
pub mod setup_wizards;
#[cfg(feature = "full-pages")]
pub mod plugins;
