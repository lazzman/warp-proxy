//! `warp-masque` — a clean-room Rust client for Cloudflare WARP over **MASQUE**
//! (CONNECT-IP / HTTP-3).
//!
//! This crate is being built bottom-up (see `DESIGN.md` and the repo plan):
//!
//! - [`keys`]     — the device's P-256 identity and its wire encodings. ✅
//! - [`config`]   — the `config.json` schema (register output / tunnel input). ✅
//! - [`register`] — the two-step device registration + enroll flow. ✅
//! - [`tunnel`]   — the MASQUE CONNECT-IP tunnel. 🚧 (Phase 0 core; see module docs)
//!
//! Nothing here copies third-party source; the Cloudflare-specific protocol
//! values are referenced from the public WARP API behaviour and documented, so
//! the provenance stays clean.

pub mod config;
mod console;
pub mod control;
pub mod doh;
pub mod error;
pub mod h2tunnel;
mod http_proxy;
pub mod keys;
pub mod netstack;
pub mod pool;
pub mod register;
mod schedule;
pub mod socks;
pub mod tls;
pub mod trace;
pub mod tunnel;
mod upstream;

pub use config::WarpConfig;
pub use error::{Error, Result};
pub use keys::DeviceKeypair;
pub use netstack::{NetHandle, ResolvePreference};
pub use pool::{parse_misfire, Misfire, Pool, PoolOptions, ProxyAuth, RestartConfig};
pub use register::{RegisterOptions, RegistrationClient};
pub use schedule::{parse_sticky, parse_strategy, Policy, StickyMode, Strategy};
pub use tunnel::{Transport, Tunnel};
pub use upstream::{UpstreamProxy, UpstreamSet};
