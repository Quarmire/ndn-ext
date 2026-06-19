//! KeyGuardian — the second factor that seals an operator identity.
//!
//! An operator identity is always persisted as a passphrase-encrypted SafeBag.
//! The *guardian* decides where that passphrase comes from:
//!
//! - [`GuardKind::Passphrase`]: a human-typed passphrase (portable fallback).
//! - [`GuardKind::OsKeychain`]: a random secret sealed in the OS keychain
//!   (Touch ID / Windows Hello / Secret Service) — passwordless, device-bound.
//!   Releasing it is gated by the OS (login / biometric), the "second factor".
//!
//! Future variants (`WebAuthnPrf`, `RemoteSigner`) plug into this same seam.
//!
//! This module owns only the OS-keychain secret; the SafeBag crypto stays in
//! `operator_keyring`. Everything degrades gracefully: if the keychain is
//! unavailable, OS-keychain seal/release returns an error and the operator
//! falls back to a passphrase.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// Which second factor protects a persisted identity's key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum GuardKind {
    /// Human-typed passphrase (the portable default).
    #[default]
    #[serde(rename = "passphrase")]
    Passphrase,
    /// A random secret held in the OS keychain; release is OS-gated.
    #[serde(rename = "os-keychain")]
    OsKeychain,
    /// The key lives on a remote signer — a phone, another machine, a
    /// hardware token — that gates each signature there; the key never touches
    /// this host. Wired via `ndn_security::custodian::RemoteCustodian`; pairing +
    /// transport land with the signer app (see
    /// .claude/notes/remote-fob-design-2026-06-01.md).
    #[serde(rename = "remote-signer")]
    RemoteSigner,
}

impl GuardKind {
    pub fn label(self) -> &'static str {
        match self {
            GuardKind::Passphrase => "passphrase",
            GuardKind::OsKeychain => "this device",
            GuardKind::RemoteSigner => "remote signer",
        }
    }
}

/// Whether the OS keychain backend is usable on this build/platform.
pub fn os_keychain_available() -> bool {
    cfg!(feature = "desktop")
}

const KEYCHAIN_SERVICE: &str = "ndn-dashboard-operator-keyring";

/// Generate a fresh random secret, seal it in the OS keychain under
/// `fingerprint`, and return it for one-time use as the SafeBag passphrase.
/// The plaintext secret is never persisted by the dashboard — only the
/// keychain holds it.
pub fn os_keychain_seal(fingerprint: &str) -> Result<String, String> {
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).map_err(|_| "rng failure".to_string())?;
    let secret: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    keychain_set(fingerprint, &secret)?;
    Ok(secret)
}

/// Release the keychain-held secret for `fingerprint` (the OS gates this with
/// login / biometric). Returns the SafeBag passphrase.
pub fn os_keychain_release(fingerprint: &str) -> Result<String, String> {
    keychain_get(fingerprint)
}

/// Remove the keychain secret for `fingerprint` (on Forget).
pub fn os_keychain_forget(fingerprint: &str) {
    keychain_delete(fingerprint);
}

// ── macOS: Security.framework with a per-use Touch ID / passcode gate ──────
//
// The item is stored with `USER_PRESENCE` access control, so *reading* it
// (release on Unlock) triggers the system Touch ID / device-passcode prompt.
// Writing (Save) does not prompt — that's expected; the gate is on use.
#[cfg(all(feature = "desktop", target_os = "macos"))]
fn keychain_set(fingerprint: &str, secret: &str) -> Result<(), String> {
    use security_framework::passwords::set_generic_password_options;
    use security_framework::passwords_options::{AccessControlOptions, PasswordOptions};
    // Replace any prior item so the access control is applied cleanly.
    keychain_delete(fingerprint);

    // Prefer a biometric (USER_PRESENCE) item — reading it raises Touch ID /
    // passcode. This only succeeds in a *code-signed, entitled* app build;
    // unsigned/dev binaries get errSecMissingEntitlement.
    let mut bio = PasswordOptions::new_generic_password(KEYCHAIN_SERVICE, fingerprint);
    bio.set_access_control_options(AccessControlOptions::USER_PRESENCE);
    if set_generic_password_options(secret.as_bytes(), bio).is_ok() {
        return Ok(());
    }

    // Fallback: a plain login-keychain item — passwordless and device-bound,
    // but login-gated rather than per-use biometric (the cost of no signing).
    let plain = PasswordOptions::new_generic_password(KEYCHAIN_SERVICE, fingerprint);
    set_generic_password_options(secret.as_bytes(), plain)
        .map_err(|e| format!("keychain write: {e}"))
}

#[cfg(all(feature = "desktop", target_os = "macos"))]
fn keychain_get(fingerprint: &str) -> Result<String, String> {
    // Reading a USER_PRESENCE item raises the Touch ID / passcode prompt.
    let bytes = security_framework::passwords::get_generic_password(KEYCHAIN_SERVICE, fingerprint)
        .map_err(|e| format!("keychain read: {e}"))?;
    String::from_utf8(bytes).map_err(|_| "keychain secret is not UTF-8".to_string())
}

#[cfg(all(feature = "desktop", target_os = "macos"))]
fn keychain_delete(fingerprint: &str) {
    let _ = security_framework::passwords::delete_generic_password(KEYCHAIN_SERVICE, fingerprint);
}

// ── Other desktop (Windows Hello / Secret Service) via the keyring crate ───
#[cfg(all(feature = "desktop", not(target_os = "macos")))]
fn keychain_entry(fingerprint: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new(KEYCHAIN_SERVICE, fingerprint)
        .map_err(|e| format!("OS keychain unavailable: {e}"))
}

#[cfg(all(feature = "desktop", not(target_os = "macos")))]
fn keychain_set(fingerprint: &str, secret: &str) -> Result<(), String> {
    keychain_entry(fingerprint)?
        .set_password(secret)
        .map_err(|e| format!("OS keychain write failed: {e}"))
}

#[cfg(all(feature = "desktop", not(target_os = "macos")))]
fn keychain_get(fingerprint: &str) -> Result<String, String> {
    keychain_entry(fingerprint)?
        .get_password()
        .map_err(|e| format!("OS keychain read failed: {e}"))
}

#[cfg(all(feature = "desktop", not(target_os = "macos")))]
fn keychain_delete(fingerprint: &str) {
    if let Ok(entry) = keychain_entry(fingerprint) {
        let _ = entry.delete_credential();
    }
}

#[cfg(not(feature = "desktop"))]
fn keychain_set(_fingerprint: &str, _secret: &str) -> Result<(), String> {
    Err("OS keychain is only available on the desktop build".into())
}

#[cfg(not(feature = "desktop"))]
fn keychain_get(_fingerprint: &str) -> Result<String, String> {
    Err("OS keychain is only available on the desktop build".into())
}

#[cfg(not(feature = "desktop"))]
fn keychain_delete(_fingerprint: &str) {}
