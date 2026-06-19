//! Management write-capability prediction for the "acting as" identity.
//!
//! The live identity model — the operator's *portable* keyring (the set of
//! identities you hold and sign as) — lives in [`crate::operator_keyring`]
//! ([`IdentitySummary`](crate::operator_keyring::IdentitySummary)). This
//! module keeps the pure, dependency-free [`WriteCapability`] predictor that
//! the Attach bar and badges share verbatim across the native and wasm
//! builds: given the engine's auth posture and the active identity, what
//! should the operator expect — read-only or read-write?

/// What the acting-as identity can do against the attached engine's management
/// surface. Reads are always public (NFD serves `*/list` etc. unsigned); this
/// is a *prediction* of whether mutations will be accepted, from the engine's
/// auth policy plus the active identity. The engine still validates every
/// command — this only tells the operator what to expect up front instead of
/// discovering a denial by trying.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteCapability {
    /// Engine auth policy not yet known.
    Unknown,
    /// Engine accepts unsigned commands — anyone connected can mutate.
    Open,
    /// The active identity should be accepted for changes.
    ReadWrite,
    /// Mutations will be refused — no usable signing identity for this engine.
    ReadOnly,
}

impl WriteCapability {
    pub fn label(self) -> &'static str {
        match self {
            WriteCapability::Unknown => "Capability unknown",
            WriteCapability::Open => "Read-write (open)",
            WriteCapability::ReadWrite => "Read-write",
            WriteCapability::ReadOnly => "Read-only",
        }
    }

    /// Carbon badge class — green when you can change things, yellow when an
    /// open engine accepts unsigned writes (a posture worth noticing), gray
    /// for read-only/unknown.
    pub fn badge_class(self) -> &'static str {
        match self {
            WriteCapability::ReadWrite => "badge badge-green",
            WriteCapability::Open => "badge badge-yellow",
            WriteCapability::ReadOnly | WriteCapability::Unknown => "badge badge-gray",
        }
    }

    pub fn tooltip(self) -> &'static str {
        match self {
            WriteCapability::Unknown => "The engine's management auth policy hasn't been read yet.",
            WriteCapability::Open => {
                "This engine accepts unsigned management commands — any connected client can make changes. Enable signed commands in Mgmt Access to lock it down."
            }
            WriteCapability::ReadWrite => {
                "The identity you're acting as should be accepted for changes. The engine still validates each command."
            }
            WriteCapability::ReadOnly => {
                "This engine requires signed commands and the identity you're acting as won't be accepted (none / expired / ephemeral). You can observe but not change anything."
            }
        }
    }

}

/// Predict the write capability from polled state. `cert_expired` is the
/// caller's verdict on the active cert (absent-or-past-validity); kept out of
/// here so the function stays pure/testable.
pub fn write_capability(
    require_signed: Option<bool>,
    ephemeral_allowed: bool,
    has_identity: bool,
    identity_ephemeral: bool,
    cert_expired: bool,
) -> WriteCapability {
    match require_signed {
        None => WriteCapability::Unknown,
        Some(false) => WriteCapability::Open,
        Some(true) => {
            // Mutations need a usable signer: a present, non-expired identity,
            // and not an ephemeral one when the engine forbids ephemeral signers.
            let refused =
                !has_identity || (identity_ephemeral && !ephemeral_allowed) || cert_expired;
            if refused {
                WriteCapability::ReadOnly
            } else {
                WriteCapability::ReadWrite
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_open_when_unsigned_accepted() {
        assert_eq!(
            write_capability(Some(false), false, false, false, false),
            WriteCapability::Open
        );
    }

    #[test]
    fn capability_unknown_until_policy_known() {
        assert_eq!(
            write_capability(None, false, true, false, false),
            WriteCapability::Unknown
        );
    }

    #[test]
    fn capability_read_write_with_valid_identity() {
        assert_eq!(
            write_capability(Some(true), false, true, false, false),
            WriteCapability::ReadWrite
        );
    }

    #[test]
    fn capability_read_only_cases() {
        // no identity
        assert_eq!(
            write_capability(Some(true), true, false, false, false),
            WriteCapability::ReadOnly
        );
        // ephemeral when the engine forbids ephemeral signers
        assert_eq!(
            write_capability(Some(true), false, true, true, false),
            WriteCapability::ReadOnly
        );
        // expired cert
        assert_eq!(
            write_capability(Some(true), false, true, false, true),
            WriteCapability::ReadOnly
        );
        // ephemeral is fine when the engine allows it
        assert_eq!(
            write_capability(Some(true), true, true, true, false),
            WriteCapability::ReadWrite
        );
    }
}
