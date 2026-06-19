//! NDN AutoConfig hub discovery.
//!
//! Two phases implemented: multicast `/localhop/ndn-autoconf/hub` probe
//! and optional NDN-FCH HTTP fallback. The NFD reference's DNS-SRV and
//! identity-name stages are not yet implemented.

pub mod client;

pub use client::{AutoConfigDiscovery, build_hub_data, build_hub_discovery_interest};
