//! Detect other system VPNs that fight SSC for the TUN default route.
//!
//! Implementation lives in `ssc-runtime` so the instance backend can run the
//! same preflight before spawning a TUN process.

pub use ssc_runtime::foreign_vpn_conflict;
