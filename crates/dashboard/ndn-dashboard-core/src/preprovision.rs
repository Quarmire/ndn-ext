//! Ergonomic forwarder pre-provisioning — turn the active operator identity
//! into the artifacts a forwarder needs to *trust* it, with no CLI.
//!
//! Establishing a forwarder's command-trust is irreducibly out-of-band (you
//! can't bootstrap it over the unauthenticated management channel by design).
//! This module makes the out-of-band step turnkey: on desktop it writes a
//! trust-anchor PIB the forwarder can point `trust_anchor_pib` at; on every
//! platform it emits the exact `[security.mgmt]` config snippet. The only
//! manual act left is "set the config and restart" — no `ndn-sec`.
//!
//! Note: the artifact is the operator's *certificate* (public) — no
//! passphrase is involved here. Key custody (and its second factor) is a
//! separate concern handled by the keyring.
#![allow(dead_code)]

/// Trust artifacts for the operator to deploy on a forwarder.
pub struct TrustArtifacts {
    /// Path of the written anchor PIB (desktop only; `None` on web).
    pub anchor_pib_path: Option<String>,
    /// `[security.mgmt]` config snippet to paste into the forwarder config.
    pub config_snippet: String,
    /// The operator certificate, base64 — for manual `ndn-sec import --anchor`
    /// when the dashboard can't write files (web).
    pub cert_b64: String,
}

/// Build the trust artifacts for `identity` from its certificate Data wire.
pub fn build(identity: &str, cert_wire: &[u8]) -> Result<TrustArtifacts, String> {
    use base64::Engine as _;
    let cert_b64 = base64::engine::general_purpose::STANDARD.encode(cert_wire);
    let anchor_pib_path = write_anchor_pib(identity, cert_wire)?;
    let path_for_config = anchor_pib_path
        .clone()
        .unwrap_or_else(|| "/etc/ndn/mgmt-pib".to_string());
    let config_snippet = format!(
        "[security.mgmt]\nrequire_signed_commands = true\ntrust_anchor_pib = \"{path_for_config}\"\n"
    );
    Ok(TrustArtifacts {
        anchor_pib_path,
        config_snippet,
        cert_b64,
    })
}

/// Sanitize an NDN identity name into a directory-safe segment.
fn sanitize(identity: &str) -> String {
    identity
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .trim_matches('_')
        .to_string()
}

#[cfg(feature = "desktop")]
fn write_anchor_pib(identity: &str, cert_wire: &[u8]) -> Result<Option<String>, String> {
    use ndn_security::{Certificate, FilePib};

    let data = ndn_packet::Data::decode(bytes::Bytes::copy_from_slice(cert_wire))
        .map_err(|e| format!("certificate decode: {e:?}"))?;
    let cert = Certificate::decode(&data).map_err(|e| format!("Certificate decode: {e}"))?;

    let dir = dirs_next::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("ndn-dashboard")
        .join("forwarder-trust")
        .join(sanitize(identity));
    let pib = FilePib::new(&dir).map_err(|e| format!("create anchor PIB: {e}"))?;
    pib.add_trust_anchor(cert.name.as_ref(), &cert)
        .map_err(|e| format!("add anchor: {e}"))?;
    Ok(Some(dir.display().to_string()))
}

#[cfg(not(feature = "desktop"))]
fn write_anchor_pib(_identity: &str, _cert_wire: &[u8]) -> Result<Option<String>, String> {
    Ok(None)
}
