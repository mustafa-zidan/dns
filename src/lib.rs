//! An ad-blocking, privacy-focused forwarding DNS server.

pub mod api;
pub mod blocklist;
pub mod cache;
pub mod certs;
pub mod config;
pub mod doh;
pub mod handler;
pub mod padding;
pub mod server;
pub mod stats;
pub mod upstream;
