//! Forwarder profile + connection-mode selection. ndn-dashboard manages any of
//! the three NFD-spec-compatible forwarders (`ndn-fwd`, `NFD`, `YaNFD`).
//! Selection is runtime: `--forwarder=<name>` (desktop) or
//! `?forwarder=<name>` (web); defaults to auto-detect.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Set once in `main()` before Dioxus launches; the resolution is process-static.
static SELECTED: OnceLock<(ForwarderProfile, PathBuf)> = OnceLock::new();

pub fn install_selected(profile: ForwarderProfile, socket: PathBuf) {
    let _ = SELECTED.set((profile, socket));
}

/// Falls back to `(NdnFwd, NdnFwd's default socket)` when no selection was installed.
pub fn selected() -> (ForwarderProfile, PathBuf) {
    SELECTED.get().cloned().unwrap_or_else(|| {
        (
            ForwarderProfile::NdnFwd,
            ForwarderProfile::NdnFwd.default_socket().to_path_buf(),
        )
    })
}

pub fn selected_profile() -> ForwarderProfile {
    selected().0
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwarderProfile {
    /// `ndn-fwd` — this workspace's forwarder.
    NdnFwd,
    /// `NFD` — C++ reference implementation from ndn-cxx.
    Nfd,
    /// `YaNFD` — Go forwarder from ndnd.
    YaNfd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Extension {
    DemoCa,
    WebTransport,
    WebRtcInbound,
    SharedWorkerFace,
    SafeBagExport,
    IssuancePolicy,
}

impl ForwarderProfile {
    /// Override via `--socket=/custom/path`.
    pub fn default_socket(self) -> &'static Path {
        match self {
            // ndn-fwd binds the NFD-standard socket for drop-in compatibility,
            // so its default is `/run/nfd/nfd.sock` — the same path
            // `ndn_config::ManagementConfig::default().face_socket` produces.
            // (It therefore shares YaNFD's path; `detection_order()` lists
            // NdnFwd first so auto-detect prefers the native forwarder.
            // TODO: derive this from ndn_config instead of a literal, and
            // distinguish ndn-fwd from YaNFD by capability probe, not path.)
            ForwarderProfile::NdnFwd => Path::new("/run/nfd/nfd.sock"),
            ForwarderProfile::Nfd => Path::new("/var/run/nfd.sock"),
            ForwarderProfile::YaNfd => Path::new("/run/nfd/nfd.sock"),
        }
    }

    pub fn binary_name(self) -> &'static str {
        match self {
            ForwarderProfile::NdnFwd => {
                if cfg!(windows) {
                    "ndn-fwd.exe"
                } else {
                    "ndn-fwd"
                }
            }
            ForwarderProfile::Nfd => "nfd",
            ForwarderProfile::YaNfd => "yanfd",
        }
    }

    pub fn human_label(self) -> &'static str {
        match self {
            ForwarderProfile::NdnFwd => "ndn-fwd (ndn-rs)",
            ForwarderProfile::Nfd => "NFD (ndn-cxx)",
            ForwarderProfile::YaNfd => "YaNFD (ndnd)",
        }
    }

    pub fn machine_name(self) -> &'static str {
        match self {
            ForwarderProfile::NdnFwd => "ndn-fwd",
            ForwarderProfile::Nfd => "nfd",
            ForwarderProfile::YaNfd => "yanfd",
        }
    }

    /// Accepts project name or binary name.
    pub fn from_cli(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "ndn-rs" | "ndn-fwd" | "ndnfwd" | "ndn_fwd" => Some(Self::NdnFwd),
            "ndn-cxx" | "nfd" => Some(Self::Nfd),
            "ndnd" | "yanfd" | "ya-nfd" => Some(Self::YaNfd),
            _ => None,
        }
    }

    /// Static hint of extensions present on this forwarder.
    pub fn known_extensions(self) -> &'static [Extension] {
        match self {
            ForwarderProfile::NdnFwd => &[
                Extension::DemoCa,
                Extension::WebTransport,
                Extension::WebRtcInbound,
                Extension::SharedWorkerFace,
                Extension::SafeBagExport,
                Extension::IssuancePolicy,
            ],
            ForwarderProfile::Nfd => &[Extension::SafeBagExport],
            ForwarderProfile::YaNfd => &[],
        }
    }

    pub fn detection_order() -> [ForwarderProfile; 3] {
        [
            ForwarderProfile::NdnFwd,
            ForwarderProfile::Nfd,
            ForwarderProfile::YaNfd,
        ]
    }
}

/// `Spawn`/`Attach` are desktop-only; `WebSocket`/`BrowserEngine` are web-only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionMode {
    /// Manage the binary lifecycle (Start/Stop buttons).
    Spawn {
        profile: ForwarderProfile,
        socket: PathBuf,
    },
    /// Connect to an already-running forwarder; no lifecycle controls.
    Attach {
        profile: ForwarderProfile,
        socket: PathBuf,
    },
    /// NFD-spec mgmt tunneled through WebSocket.
    WebSocket {
        profile: ForwarderProfile,
        url: String,
    },
    /// In-page `ndn_engine`; the dashboard is the forwarder.
    BrowserEngine,
}

impl ConnectionMode {
    pub fn profile(&self) -> ForwarderProfile {
        match self {
            ConnectionMode::Spawn { profile, .. }
            | ConnectionMode::Attach { profile, .. }
            | ConnectionMode::WebSocket { profile, .. } => *profile,
            ConnectionMode::BrowserEngine => ForwarderProfile::NdnFwd,
        }
    }

    pub fn supports_lifecycle(&self) -> bool {
        matches!(self, ConnectionMode::Spawn { .. })
    }
}

/// `None` when neither flag is supplied (caller should run auto-detect).
pub fn resolve_static(
    cli_forwarder: Option<&str>,
    cli_socket: Option<PathBuf>,
) -> Option<(ForwarderProfile, PathBuf)> {
    match (cli_forwarder, cli_socket) {
        (Some(p), Some(s)) => ForwarderProfile::from_cli(p).map(|p| (p, s)),
        (Some(p), None) => {
            let prof = ForwarderProfile::from_cli(p)?;
            Some((prof, prof.default_socket().to_path_buf()))
        }
        (None, Some(s)) => {
            let matched = ForwarderProfile::detection_order()
                .into_iter()
                .find(|p| p.default_socket() == s)
                .unwrap_or(ForwarderProfile::NdnFwd);
            Some((matched, s))
        }
        (None, None) => None,
    }
}

/// Path-existence probe; first matching default socket wins.
pub fn auto_detect() -> Option<(ForwarderProfile, PathBuf)> {
    for prof in ForwarderProfile::detection_order() {
        let sock = prof.default_socket();
        if sock.exists() {
            return Some((prof, sock.to_path_buf()));
        }
    }
    None
}

/// Parses `?forwarder=<name>&ws=<url>&engine=local`. `engine=local` wins.
#[cfg(target_arch = "wasm32")]
pub fn resolve_web(query: &str) -> ConnectionMode {
    let mut forwarder = None;
    let mut ws = None;
    let mut engine_local = false;
    for pair in query.trim_start_matches('?').split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            let v = urlencoding_decode(v);
            match k {
                "forwarder" => forwarder = ForwarderProfile::from_cli(&v),
                "ws" => ws = Some(v),
                "engine" if v == "local" => engine_local = true,
                _ => {}
            }
        }
    }
    if engine_local {
        return ConnectionMode::BrowserEngine;
    }
    ConnectionMode::WebSocket {
        profile: forwarder.unwrap_or(ForwarderProfile::NdnFwd),
        url: ws.unwrap_or_else(|| "ws://localhost:9696".to_string()),
    }
}

#[cfg(target_arch = "wasm32")]
fn urlencoding_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parse_accepts_project_and_binary_names() {
        assert_eq!(
            ForwarderProfile::from_cli("ndn-rs"),
            Some(ForwarderProfile::NdnFwd)
        );
        assert_eq!(
            ForwarderProfile::from_cli("ndn-fwd"),
            Some(ForwarderProfile::NdnFwd)
        );
        assert_eq!(
            ForwarderProfile::from_cli("NDN-FWD"),
            Some(ForwarderProfile::NdnFwd)
        );
        assert_eq!(
            ForwarderProfile::from_cli("ndn-cxx"),
            Some(ForwarderProfile::Nfd)
        );
        assert_eq!(
            ForwarderProfile::from_cli("nfd"),
            Some(ForwarderProfile::Nfd)
        );
        assert_eq!(
            ForwarderProfile::from_cli("ndnd"),
            Some(ForwarderProfile::YaNfd)
        );
        assert_eq!(
            ForwarderProfile::from_cli("yanfd"),
            Some(ForwarderProfile::YaNfd)
        );
        assert_eq!(
            ForwarderProfile::from_cli("ya-nfd"),
            Some(ForwarderProfile::YaNfd)
        );
        assert_eq!(ForwarderProfile::from_cli("garbage"), None);
    }

    #[test]
    fn machine_names_round_trip() {
        for prof in ForwarderProfile::detection_order() {
            assert_eq!(ForwarderProfile::from_cli(prof.machine_name()), Some(prof));
        }
    }

    #[test]
    fn resolve_static_combinations() {
        let r = resolve_static(Some("nfd"), Some(PathBuf::from("/tmp/foo.sock")));
        assert_eq!(
            r,
            Some((ForwarderProfile::Nfd, PathBuf::from("/tmp/foo.sock")))
        );

        let r = resolve_static(Some("nfd"), None).unwrap();
        assert_eq!(r.0, ForwarderProfile::Nfd);
        assert_eq!(r.1, PathBuf::from("/var/run/nfd.sock"));

        let r = resolve_static(None, Some(PathBuf::from("/var/run/nfd.sock"))).unwrap();
        assert_eq!(r.0, ForwarderProfile::Nfd);

        let r = resolve_static(None, Some(PathBuf::from("/tmp/whatever.sock"))).unwrap();
        assert_eq!(r.0, ForwarderProfile::NdnFwd);

        assert_eq!(resolve_static(None, None), None);
    }

    #[test]
    fn unique_human_labels() {
        let labels: std::collections::HashSet<_> = ForwarderProfile::detection_order()
            .iter()
            .map(|p| p.human_label())
            .collect();
        assert_eq!(labels.len(), 3);
    }

    #[test]
    fn connection_mode_profile_extraction() {
        let m = ConnectionMode::Attach {
            profile: ForwarderProfile::Nfd,
            socket: PathBuf::from("/x"),
        };
        assert_eq!(m.profile(), ForwarderProfile::Nfd);
        assert!(!m.supports_lifecycle());

        let m = ConnectionMode::Spawn {
            profile: ForwarderProfile::NdnFwd,
            socket: PathBuf::from("/x"),
        };
        assert!(m.supports_lifecycle());

        assert_eq!(
            ConnectionMode::BrowserEngine.profile(),
            ForwarderProfile::NdnFwd
        );
    }
}
