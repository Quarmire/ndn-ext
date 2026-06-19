//! `AuditLogChain` + `SchemaJournalChain` — typed instantiations of
//! [`crate::signed_data_chain::SignedDataChainStore`] for the audit log and
//! schema journal. Tag IDs below are wire identifiers; once shipped, never
//! reused.

#![allow(dead_code)]

use bytes::Bytes;
use ndn_packet::{Name, SignatureType};
use ndn_tlv::{TlvReader, TlvWriter};

use crate::signed_data_chain::{
    ChainEntry, ChainError, DataSigner, MemoryStore, SignedDataChainStore,
};

/// One row of the security audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditLogEntry {
    /// Unix-epoch nanoseconds — when the dashboard observed the event.
    pub ts_unix_ns: u64,
    pub outcome: AuditOutcome,
    /// Verb-ish subject identifier (e.g. `"security/policy-set"`).
    pub subject: String,
    /// Free-form detail line, ≤ 512 bytes UTF-8.
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    Accepted,
    Rejected,
    Info,
    Warning,
}

impl AuditOutcome {
    fn code(self) -> u8 {
        match self {
            Self::Accepted => 0,
            Self::Rejected => 1,
            Self::Info => 2,
            Self::Warning => 3,
        }
    }
    fn from_code(c: u8) -> Result<Self, String> {
        Ok(match c {
            0 => Self::Accepted,
            1 => Self::Rejected,
            2 => Self::Info,
            3 => Self::Warning,
            n => return Err(format!("AuditOutcome: unknown code {n}")),
        })
    }
}

pub mod audit_tag {
    pub const TS_UNIX_NS: u64 = 3;
    pub const OUTCOME: u64 = 4;
    pub const SUBJECT: u64 = 5;
    pub const DETAIL: u64 = 6;
}

impl ChainEntry for AuditLogEntry {
    const SCHEMA_VERSION: u16 = 1;

    fn encode_payload_fields(&self, w: &mut TlvWriter) {
        write_nni(w, audit_tag::TS_UNIX_NS, self.ts_unix_ns);
        w.write_tlv(audit_tag::OUTCOME, &[self.outcome.code()]);
        w.write_tlv(audit_tag::SUBJECT, self.subject.as_bytes());
        w.write_tlv(audit_tag::DETAIL, self.detail.as_bytes());
    }

    fn decode_payload_fields(reader: &mut TlvReader) -> Result<Self, ChainError> {
        let (t_ts, v_ts) = reader
            .read_tlv()
            .map_err(|e| ChainError::Decode(format!("audit ts: {e:?}")))?;
        require_tag(t_ts, audit_tag::TS_UNIX_NS, "ts_unix_ns")?;
        let ts_unix_ns = decode_nni(&v_ts).map_err(ChainError::Decode)?;

        let (t_o, v_o) = reader
            .read_tlv()
            .map_err(|e| ChainError::Decode(format!("audit outcome: {e:?}")))?;
        require_tag(t_o, audit_tag::OUTCOME, "outcome")?;
        if v_o.len() != 1 {
            return Err(ChainError::Decode(format!(
                "outcome must be 1 byte, got {}",
                v_o.len()
            )));
        }
        let outcome = AuditOutcome::from_code(v_o[0]).map_err(ChainError::Decode)?;

        let (t_s, v_s) = reader
            .read_tlv()
            .map_err(|e| ChainError::Decode(format!("audit subject: {e:?}")))?;
        require_tag(t_s, audit_tag::SUBJECT, "subject")?;
        let subject = bytes_to_string(&v_s, "subject")?;

        let (t_d, v_d) = reader
            .read_tlv()
            .map_err(|e| ChainError::Decode(format!("audit detail: {e:?}")))?;
        require_tag(t_d, audit_tag::DETAIL, "detail")?;
        let detail = bytes_to_string(&v_d, "detail")?;

        Ok(Self {
            ts_unix_ns,
            outcome,
            subject,
            detail,
        })
    }
}

pub type AuditLogChain<B> = SignedDataChainStore<AuditLogEntry, B>;

pub fn open_audit_chain_in_memory(
    chain_root: ndn_packet::Name,
) -> Result<AuditLogChain<MemoryStore>, ChainError> {
    SignedDataChainStore::open(chain_root, MemoryStore::new())
}

/// Anchor / schema-rule adds + removes with the responsible signed identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaJournalEntry {
    pub ts_unix_ns: u64,
    pub kind: SchemaJournalKind,
    /// Anchor or rule name affected.
    pub subject_name: String,
    /// Operator identity that initiated the change.
    pub initiator_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaJournalKind {
    AnchorAdd,
    AnchorRemove,
    SchemaRuleAdd,
    SchemaRuleRemove,
}

impl SchemaJournalKind {
    fn code(self) -> u8 {
        match self {
            Self::AnchorAdd => 0,
            Self::AnchorRemove => 1,
            Self::SchemaRuleAdd => 2,
            Self::SchemaRuleRemove => 3,
        }
    }
    fn from_code(c: u8) -> Result<Self, String> {
        Ok(match c {
            0 => Self::AnchorAdd,
            1 => Self::AnchorRemove,
            2 => Self::SchemaRuleAdd,
            3 => Self::SchemaRuleRemove,
            n => return Err(format!("SchemaJournalKind: unknown code {n}")),
        })
    }
}

pub mod schema_tag {
    pub const TS_UNIX_NS: u64 = 3;
    pub const KIND: u64 = 4;
    pub const SUBJECT_NAME: u64 = 5;
    pub const INITIATOR_NAME: u64 = 6;
}

impl ChainEntry for SchemaJournalEntry {
    const SCHEMA_VERSION: u16 = 1;

    fn encode_payload_fields(&self, w: &mut TlvWriter) {
        write_nni(w, schema_tag::TS_UNIX_NS, self.ts_unix_ns);
        w.write_tlv(schema_tag::KIND, &[self.kind.code()]);
        w.write_tlv(schema_tag::SUBJECT_NAME, self.subject_name.as_bytes());
        w.write_tlv(schema_tag::INITIATOR_NAME, self.initiator_name.as_bytes());
    }

    fn decode_payload_fields(reader: &mut TlvReader) -> Result<Self, ChainError> {
        let (t_ts, v_ts) = reader
            .read_tlv()
            .map_err(|e| ChainError::Decode(format!("journal ts: {e:?}")))?;
        require_tag(t_ts, schema_tag::TS_UNIX_NS, "ts_unix_ns")?;
        let ts_unix_ns = decode_nni(&v_ts).map_err(ChainError::Decode)?;

        let (t_k, v_k) = reader
            .read_tlv()
            .map_err(|e| ChainError::Decode(format!("journal kind: {e:?}")))?;
        require_tag(t_k, schema_tag::KIND, "kind")?;
        if v_k.len() != 1 {
            return Err(ChainError::Decode(format!(
                "kind must be 1 byte, got {}",
                v_k.len()
            )));
        }
        let kind = SchemaJournalKind::from_code(v_k[0]).map_err(ChainError::Decode)?;

        let (t_s, v_s) = reader
            .read_tlv()
            .map_err(|e| ChainError::Decode(format!("journal subject: {e:?}")))?;
        require_tag(t_s, schema_tag::SUBJECT_NAME, "subject_name")?;
        let subject_name = bytes_to_string(&v_s, "subject_name")?;

        let (t_i, v_i) = reader
            .read_tlv()
            .map_err(|e| ChainError::Decode(format!("journal initiator: {e:?}")))?;
        require_tag(t_i, schema_tag::INITIATOR_NAME, "initiator_name")?;
        let initiator_name = bytes_to_string(&v_i, "initiator_name")?;

        Ok(Self {
            ts_unix_ns,
            kind,
            subject_name,
            initiator_name,
        })
    }
}

pub type SchemaJournalChain<B> = SignedDataChainStore<SchemaJournalEntry, B>;

pub fn open_schema_journal_in_memory(
    chain_root: ndn_packet::Name,
) -> Result<SchemaJournalChain<MemoryStore>, ChainError> {
    SignedDataChainStore::open(chain_root, MemoryStore::new())
}

/// Process-local Ed25519 signer for dashboard-authored chain entries. The key
/// is freshly generated per process; entries from prior processes remain on
/// disk but won't re-verify against this process's key.
pub struct DashboardSigner {
    key_locator: Name,
    signing: ed25519_dalek::SigningKey,
}

impl DashboardSigner {
    /// `key_locator` identifies the audit author (e.g. the active identity name
    /// or `/local/ndn-dashboard/KEY/ephemeral`).
    pub fn new_ephemeral(key_locator: Name) -> Self {
        let mut seed = [0u8; 32];
        let _ = getrandom::getrandom(&mut seed);
        Self {
            key_locator,
            signing: ed25519_dalek::SigningKey::from_bytes(&seed),
        }
    }
}

impl DataSigner for DashboardSigner {
    fn sig_type(&self) -> SignatureType {
        SignatureType::SignatureEd25519
    }
    fn key_locator(&self) -> Option<&Name> {
        Some(&self.key_locator)
    }
    fn sign(&self, region: &[u8]) -> Result<Bytes, ChainError> {
        use ed25519_dalek::Signer as _;
        Ok(Bytes::copy_from_slice(
            &self.signing.sign(region).to_bytes(),
        ))
    }
}

/// Records a successful `policy-set` mutation. `policy_content_hash` is the
/// SHA-256 of the canonical TLV-encoded policy the operator submitted.
pub fn policy_set_audit_entry(
    ts_unix_ns: u64,
    initiator_name: &str,
    policy_content_hash: &[u8; 32],
) -> AuditLogEntry {
    let mut hex = String::with_capacity(64);
    for b in policy_content_hash {
        let _ = std::fmt::Write::write_fmt(&mut hex, format_args!("{b:02x}"));
    }
    AuditLogEntry {
        ts_unix_ns,
        outcome: AuditOutcome::Accepted,
        subject: "security/policy-set".into(),
        detail: format!("initiator={initiator_name} policy_content_hash={hex}"),
    }
}

#[cfg(feature = "desktop")]
mod audit_globals {
    use super::*;
    use crate::signed_data_chain::FileStore;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};

    pub type AuditChainBackend = FileStore;
    pub type AuditChainHandle = AuditLogChain<AuditChainBackend>;

    struct AuditState {
        signer: DashboardSigner,
        chain: Mutex<AuditChainHandle>,
    }

    static AUDIT_STATE: OnceLock<AuditState> = OnceLock::new();

    /// Idempotent; subsequent calls return the existing handle.
    pub fn init(dir: PathBuf, key_locator: Name) {
        let _ = AUDIT_STATE.get_or_init(|| {
            let chain_root = Name::root()
                .append(b"local")
                .append(b"ndn-dashboard")
                .append(b"audit");
            let backend = FileStore::new(&dir);
            let chain = match SignedDataChainStore::open(chain_root, backend) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(
                        target: "dashboard.security",
                        dir = %dir.display(),
                        error = %e,
                        "failed to open audit chain — falling back to empty in-memory chain"
                    );
                    let mem_root = Name::root()
                        .append(b"local")
                        .append(b"ndn-dashboard")
                        .append(b"audit-fallback");
                    SignedDataChainStore::open(mem_root, FileStore::new(&dir))
                        .expect("audit chain fallback open")
                }
            };
            AuditState {
                signer: DashboardSigner::new_ephemeral(key_locator),
                chain: Mutex::new(chain),
            }
        });
    }

    /// No-op (logs at WARN) if `init` hasn't been called yet or the append fails.
    pub fn append(entry: AuditLogEntry) {
        let Some(state) = AUDIT_STATE.get() else {
            tracing::warn!(
                target: "dashboard.security",
                subject = %entry.subject,
                "audit chain not initialised — dropping entry"
            );
            return;
        };
        let mut guard = match state.chain.lock() {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!(
                    target: "dashboard.security",
                    error = %e,
                    "audit chain mutex poisoned — dropping entry"
                );
                return;
            }
        };
        if let Err(e) = guard.append(entry, &state.signer) {
            tracing::warn!(
                target: "dashboard.security",
                error = %e,
                "audit chain append failed"
            );
        }
    }

    /// Returns oldest first.
    pub fn snapshot() -> Vec<AuditLogEntry> {
        let Some(state) = AUDIT_STATE.get() else {
            return Vec::new();
        };
        let guard = match state.chain.lock() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let n = guard.len();
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            match guard.decode_entry(i) {
                Ok(e) => out.push(e),
                Err(err) => {
                    tracing::warn!(
                        target: "dashboard.security",
                        seq = i,
                        error = %err,
                        "audit chain decode error — skipping"
                    );
                }
            }
        }
        out
    }
}

#[cfg(feature = "desktop")]
#[allow(unused_imports)]
pub use audit_globals::snapshot as audit_chain_snapshot;
#[cfg(feature = "desktop")]
pub use audit_globals::{append as append_audit_entry, init as init_audit_chain};

/// Wasm32 audit chain — `IdbDatabase` is `!Send`, so we use `thread_local!` +
/// `RefCell`. `init_audit_chain` stays sync but spawns the async IDB open;
/// appends before the open resolves are logged and dropped.
#[cfg(all(target_arch = "wasm32", not(feature = "desktop")))]
mod audit_globals_wasm {
    use super::*;
    use crate::signed_data_chain::IndexedDbStore;
    use std::cell::RefCell;

    pub type WasmAuditChain = AuditLogChain<IndexedDbStore>;

    struct WasmAuditState {
        signer: DashboardSigner,
        chain: WasmAuditChain,
    }

    thread_local! {
        static STATE: RefCell<Option<WasmAuditState>> = const { RefCell::new(None) };
    }

    fn install(state: WasmAuditState) {
        STATE.with(|s| {
            if s.borrow().is_some() {
                tracing::warn!(
                    target: "dashboard.security",
                    "wasm audit chain already initialised — keeping existing"
                );
                return;
            }
            *s.borrow_mut() = Some(state);
        });
    }

    pub fn init(_dir: std::path::PathBuf, key_locator: Name) {
        wasm_bindgen_futures::spawn_local(async move {
            let chain_root = Name::root()
                .append(b"local")
                .append(b"ndn-dashboard")
                .append(b"audit");
            let backend = match IndexedDbStore::open("ndn-dashboard-chains", "audit").await {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(
                        target: "dashboard.security",
                        error = %e,
                        "wasm audit chain: IDB open failed — audit log will be empty"
                    );
                    return;
                }
            };
            match SignedDataChainStore::open(chain_root, backend) {
                Ok(chain) => install(WasmAuditState {
                    signer: DashboardSigner::new_ephemeral(key_locator),
                    chain,
                }),
                Err(e) => tracing::warn!(
                    target: "dashboard.security",
                    error = %e,
                    "wasm audit chain: chain open failed"
                ),
            }
        });
    }

    pub fn append(entry: AuditLogEntry) {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(state) = guard.as_mut() else {
                tracing::warn!(
                    target: "dashboard.security",
                    subject = %entry.subject,
                    "wasm audit chain not ready (IDB still opening) — dropping entry"
                );
                return;
            };
            if let Err(e) = state.chain.append(entry, &state.signer) {
                tracing::warn!(
                    target: "dashboard.security",
                    error = %e,
                    "wasm audit chain append failed"
                );
            }
        });
    }

    pub fn snapshot() -> Vec<AuditLogEntry> {
        STATE.with(|s| match s.borrow().as_ref() {
            None => Vec::new(),
            Some(state) => {
                let n = state.chain.len();
                let mut out = Vec::with_capacity(n);
                for i in 0..n {
                    if let Ok(e) = state.chain.decode_entry(i) {
                        out.push(e);
                    }
                }
                out
            }
        })
    }
}

#[cfg(all(target_arch = "wasm32", not(feature = "desktop")))]
pub use audit_globals_wasm::{
    append as append_audit_entry, init as init_audit_chain, snapshot as audit_chain_snapshot,
};

#[cfg(all(not(target_arch = "wasm32"), not(feature = "desktop")))]
pub fn init_audit_chain(_dir: std::path::PathBuf, _key_locator: Name) {}

#[cfg(all(not(target_arch = "wasm32"), not(feature = "desktop")))]
pub fn append_audit_entry(_entry: AuditLogEntry) {}

#[cfg(all(not(target_arch = "wasm32"), not(feature = "desktop")))]
pub fn audit_chain_snapshot() -> Vec<AuditLogEntry> {
    Vec::new()
}

#[cfg(feature = "desktop")]
mod schema_globals {
    use super::*;
    use crate::signed_data_chain::FileStore;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};

    pub type SchemaChainBackend = FileStore;
    pub type SchemaChainHandle = SchemaJournalChain<SchemaChainBackend>;

    struct SchemaState {
        signer: DashboardSigner,
        chain: Mutex<SchemaChainHandle>,
    }

    static SCHEMA_STATE: OnceLock<SchemaState> = OnceLock::new();

    /// Idempotent; falls back to an empty chain if the backend can't open the dir.
    pub fn init(dir: PathBuf, key_locator: Name) {
        let _ = SCHEMA_STATE.get_or_init(|| {
            let chain_root = Name::root()
                .append(b"local")
                .append(b"ndn-dashboard")
                .append(b"schema");
            let backend = FileStore::new(&dir);
            let chain = SignedDataChainStore::open(chain_root, backend).unwrap_or_else(|e| {
                tracing::warn!(
                    target: "dashboard.security",
                    dir = %dir.display(),
                    error = %e,
                    "failed to open schema journal — using empty fallback"
                );
                let mem_root = Name::root()
                    .append(b"local")
                    .append(b"ndn-dashboard")
                    .append(b"schema-fallback");
                SignedDataChainStore::open(mem_root, FileStore::new(&dir))
                    .expect("schema journal fallback open")
            });
            SchemaState {
                signer: DashboardSigner::new_ephemeral(key_locator),
                chain: Mutex::new(chain),
            }
        });
    }

    pub fn append(entry: SchemaJournalEntry) {
        let Some(state) = SCHEMA_STATE.get() else {
            tracing::warn!(
                target: "dashboard.security",
                subject = %entry.subject_name,
                "schema journal not initialised — dropping entry"
            );
            return;
        };
        let mut guard = match state.chain.lock() {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!(
                    target: "dashboard.security",
                    error = %e,
                    "schema journal mutex poisoned — dropping entry"
                );
                return;
            }
        };
        if let Err(e) = guard.append(entry, &state.signer) {
            tracing::warn!(
                target: "dashboard.security",
                error = %e,
                "schema journal append failed"
            );
        }
    }

    pub fn snapshot() -> Vec<SchemaJournalEntry> {
        let Some(state) = SCHEMA_STATE.get() else {
            return Vec::new();
        };
        let guard = match state.chain.lock() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let n = guard.len();
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            if let Ok(e) = guard.decode_entry(i) {
                out.push(e);
            }
        }
        out
    }
}

#[cfg(feature = "desktop")]
#[allow(unused_imports)]
pub use schema_globals::snapshot as schema_journal_snapshot;
#[cfg(feature = "desktop")]
pub use schema_globals::{append as append_schema_entry, init as init_schema_journal};

#[cfg(all(target_arch = "wasm32", not(feature = "desktop")))]
mod schema_globals_wasm {
    use super::*;
    use crate::signed_data_chain::IndexedDbStore;
    use std::cell::RefCell;

    pub type WasmSchemaChain = SchemaJournalChain<IndexedDbStore>;

    struct WasmSchemaState {
        signer: DashboardSigner,
        chain: WasmSchemaChain,
    }

    thread_local! {
        static STATE: RefCell<Option<WasmSchemaState>> = const { RefCell::new(None) };
    }

    fn install(state: WasmSchemaState) {
        STATE.with(|s| {
            if s.borrow().is_some() {
                return;
            }
            *s.borrow_mut() = Some(state);
        });
    }

    pub fn init(_dir: std::path::PathBuf, key_locator: Name) {
        wasm_bindgen_futures::spawn_local(async move {
            let chain_root = Name::root()
                .append(b"local")
                .append(b"ndn-dashboard")
                .append(b"schema");
            let backend = match IndexedDbStore::open("ndn-dashboard-chains", "schema").await {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(
                        target: "dashboard.security",
                        error = %e,
                        "wasm schema journal: IDB open failed"
                    );
                    return;
                }
            };
            match SignedDataChainStore::open(chain_root, backend) {
                Ok(chain) => install(WasmSchemaState {
                    signer: DashboardSigner::new_ephemeral(key_locator),
                    chain,
                }),
                Err(e) => tracing::warn!(
                    target: "dashboard.security",
                    error = %e,
                    "wasm schema journal: chain open failed"
                ),
            }
        });
    }

    pub fn append(entry: SchemaJournalEntry) {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(state) = guard.as_mut() else {
                tracing::warn!(
                    target: "dashboard.security",
                    subject = %entry.subject_name,
                    "wasm schema journal not ready — dropping entry"
                );
                return;
            };
            if let Err(e) = state.chain.append(entry, &state.signer) {
                tracing::warn!(
                    target: "dashboard.security",
                    error = %e,
                    "wasm schema journal append failed"
                );
            }
        });
    }

    pub fn snapshot() -> Vec<SchemaJournalEntry> {
        STATE.with(|s| match s.borrow().as_ref() {
            None => Vec::new(),
            Some(state) => {
                let n = state.chain.len();
                let mut out = Vec::with_capacity(n);
                for i in 0..n {
                    if let Ok(e) = state.chain.decode_entry(i) {
                        out.push(e);
                    }
                }
                out
            }
        })
    }
}

#[cfg(all(target_arch = "wasm32", not(feature = "desktop")))]
pub use schema_globals_wasm::{
    append as append_schema_entry, init as init_schema_journal, snapshot as schema_journal_snapshot,
};

#[cfg(all(not(target_arch = "wasm32"), not(feature = "desktop")))]
pub fn init_schema_journal(_dir: std::path::PathBuf, _key_locator: Name) {}

#[cfg(all(not(target_arch = "wasm32"), not(feature = "desktop")))]
pub fn append_schema_entry(_entry: SchemaJournalEntry) {}

#[cfg(all(not(target_arch = "wasm32"), not(feature = "desktop")))]
pub fn schema_journal_snapshot() -> Vec<SchemaJournalEntry> {
    Vec::new()
}

fn require_tag(actual: u64, expected: u64, field: &str) -> Result<(), ChainError> {
    if actual != expected {
        Err(ChainError::Decode(format!(
            "{field}: expected tag {expected}, got {actual}"
        )))
    } else {
        Ok(())
    }
}

fn bytes_to_string(bytes: &Bytes, field: &str) -> Result<String, ChainError> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|e| ChainError::Decode(format!("{field}: invalid UTF-8: {e}")))
}

fn write_nni(w: &mut TlvWriter, typ: u64, value: u64) {
    w.write_tlv(typ, &encode_nni(value));
}

fn encode_nni(value: u64) -> Vec<u8> {
    if value <= u64::from(u8::MAX) {
        vec![value as u8]
    } else if value <= u64::from(u16::MAX) {
        (value as u16).to_be_bytes().to_vec()
    } else if value <= u64::from(u32::MAX) {
        (value as u32).to_be_bytes().to_vec()
    } else {
        value.to_be_bytes().to_vec()
    }
}

fn decode_nni(bytes: &[u8]) -> Result<u64, String> {
    match bytes.len() {
        1 => Ok(u64::from(bytes[0])),
        2 => Ok(u64::from(u16::from_be_bytes([bytes[0], bytes[1]]))),
        4 => Ok(u64::from(u32::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
        ]))),
        8 => Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])),
        n => Err(format!("NonNegativeInteger must be 1/2/4/8 bytes, got {n}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signed_data_chain::{DataSigner, DataVerifier};
    use bytes::Bytes;
    use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
    use ndn_packet::{Data, Name, SignatureType};

    struct TestSigner {
        key_locator: Name,
        signing: SigningKey,
    }
    impl TestSigner {
        fn from_seed(seed: [u8; 32], key_locator: Name) -> Self {
            Self {
                key_locator,
                signing: SigningKey::from_bytes(&seed),
            }
        }
        fn verifying(&self) -> VerifyingKey {
            self.signing.verifying_key()
        }
    }
    impl DataSigner for TestSigner {
        fn sig_type(&self) -> SignatureType {
            SignatureType::SignatureEd25519
        }
        fn key_locator(&self) -> Option<&Name> {
            Some(&self.key_locator)
        }
        fn sign(&self, region: &[u8]) -> Result<Bytes, ChainError> {
            Ok(Bytes::copy_from_slice(
                &self.signing.sign(region).to_bytes(),
            ))
        }
    }
    struct TestVerifier(VerifyingKey);
    impl DataVerifier for TestVerifier {
        fn verify(&self, data: &Data) -> bool {
            let sig = data.sig_value();
            let Ok(arr): Result<[u8; 64], _> = sig.try_into() else {
                return false;
            };
            self.0
                .verify(
                    data.signed_region(),
                    &ed25519_dalek::Signature::from_bytes(&arr),
                )
                .is_ok()
        }
    }

    fn ed_fixture() -> (TestSigner, TestVerifier) {
        let s = TestSigner::from_seed(
            [11u8; 32],
            Name::root()
                .append(b"lab")
                .append(b"alice")
                .append(b"KEY")
                .append(b"k1"),
        );
        let v = TestVerifier(s.verifying());
        (s, v)
    }

    #[test]
    fn audit_chain_round_trip() {
        let root = Name::root()
            .append(b"lab")
            .append(b"dashboard")
            .append(b"audit");
        let (signer, verifier) = ed_fixture();
        let mut chain = open_audit_chain_in_memory(root).unwrap();

        chain
            .append(
                AuditLogEntry {
                    ts_unix_ns: 1_700_000_000_000_000_000,
                    outcome: AuditOutcome::Accepted,
                    subject: "rib/register".into(),
                    detail: "by=/lab/alice/KEY/k1".into(),
                },
                &signer,
            )
            .unwrap();
        chain
            .append(
                AuditLogEntry {
                    ts_unix_ns: 1_700_000_000_000_000_001,
                    outcome: AuditOutcome::Rejected,
                    subject: "security/anchor-remove".into(),
                    detail: "sig invalid".into(),
                },
                &signer,
            )
            .unwrap();

        chain.verify(&verifier).expect("audit chain valid");
        assert_eq!(chain.len(), 2);

        let e0 = chain.decode_entry(0).unwrap();
        assert_eq!(e0.subject, "rib/register");
        assert_eq!(e0.outcome, AuditOutcome::Accepted);
        let e1 = chain.decode_entry(1).unwrap();
        assert_eq!(e1.outcome, AuditOutcome::Rejected);
        assert!(e1.detail.contains("sig invalid"));
    }

    #[test]
    fn schema_journal_round_trip() {
        let root = Name::root()
            .append(b"lab")
            .append(b"dashboard")
            .append(b"schema");
        let (signer, verifier) = ed_fixture();
        let mut chain = open_schema_journal_in_memory(root).unwrap();

        chain
            .append(
                SchemaJournalEntry {
                    ts_unix_ns: 1_700_000_000_000_000_000,
                    kind: SchemaJournalKind::AnchorAdd,
                    subject_name: "/lab/router-ca/KEY/k0".into(),
                    initiator_name: "/lab/alice/KEY/k1".into(),
                },
                &signer,
            )
            .unwrap();
        chain
            .append(
                SchemaJournalEntry {
                    ts_unix_ns: 1_700_000_000_000_000_001,
                    kind: SchemaJournalKind::SchemaRuleRemove,
                    subject_name: "/lab/*/photos => /lab/*/KEY/*".into(),
                    initiator_name: "/lab/admin/KEY/k1".into(),
                },
                &signer,
            )
            .unwrap();

        chain.verify(&verifier).expect("journal chain valid");
        let e1 = chain.decode_entry(1).unwrap();
        assert_eq!(e1.kind, SchemaJournalKind::SchemaRuleRemove);
        assert_eq!(e1.initiator_name, "/lab/admin/KEY/k1");
    }

    /// §11.10 audit bridge — policy-set produces an AuditLogEntry the
    /// dashboard appends to its AuditLogChain. The bridge serialises
    /// the policy's content_hash into the detail line so the policy
    /// edit history is reconstructable from the audit chain.
    #[test]
    fn policy_set_bridge_emits_audit_entry() {
        let entry =
            policy_set_audit_entry(1_700_000_000_000_000_000, "/lab/alice/KEY/k1", &[0xab; 32]);
        assert_eq!(entry.subject, "security/policy-set");
        assert_eq!(entry.outcome, AuditOutcome::Accepted);
        assert!(entry.detail.contains("initiator=/lab/alice/KEY/k1"));
        assert!(entry.detail.contains("policy_content_hash=abab"));
        assert!(entry.detail.ends_with(&"ab".repeat(32)));
    }

    /// Audit-bridge entries round-trip cleanly through the chain.
    #[test]
    fn policy_set_bridge_entry_chains_into_audit_log() {
        let root = Name::root()
            .append(b"lab")
            .append(b"dashboard")
            .append(b"audit");
        let (signer, verifier) = ed_fixture();
        let mut chain = open_audit_chain_in_memory(root).unwrap();

        let entry =
            policy_set_audit_entry(1_700_000_000_000_000_000, "/lab/alice/KEY/k1", &[0x55; 32]);
        chain.append(entry.clone(), &signer).unwrap();
        chain.verify(&verifier).expect("audit valid");
        let decoded = chain.decode_entry(0).unwrap();
        assert_eq!(decoded, entry);
    }

    //
    // Pin the `init_audit_chain` → `append_audit_entry` →
    // `audit_chain_snapshot` round-trip + the parallel schema_journal
    // helpers. These are the call sites the dashboard's run_cmd uses
    // (audit-bridge on policy-set; schema-journal on rule-add); the
    // primitive tests above cover the inner chain but not the
    // OnceLock-backed global path.
    //
    // The OnceLock is process-wide so these tests run in a child
    // process via `assert_cmd` style isolation when they need a
    // pristine global. For Phase-B-step-D scope we just smoke-test
    // append→snapshot in this process; subsequent tests see the
    // existing chain entries (harmless — we assert presence, not
    // emptiness).

    #[cfg(feature = "desktop")]
    #[test]
    fn audit_global_append_round_trips_through_snapshot() {
        // Use a unique-per-test temp dir to avoid colliding with the
        // process default.
        let dir = std::env::temp_dir().join(format!(
            "ndn-dashboard-audit-witness-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let kl = Name::root().append(b"witness").append(b"KEY").append(b"k0");
        crate::security_chains::init_audit_chain(dir.clone(), kl);
        let before = crate::security_chains::audit_chain_snapshot().len();
        let entry = AuditLogEntry {
            ts_unix_ns: 1_700_000_000_000_000_000,
            outcome: AuditOutcome::Accepted,
            subject: "security/policy-set".into(),
            detail: "initiator=/witness/op fingerprint=00".into(),
        };
        crate::security_chains::append_audit_entry(entry.clone());
        let after = crate::security_chains::audit_chain_snapshot();
        assert!(
            after.len() > before,
            "snapshot length didn't grow: before={before} after={}",
            after.len()
        );
        // The just-appended entry should be the last row (chains are
        // append-only and snapshot returns oldest-first).
        let last = after.last().expect("non-empty after append");
        assert_eq!(last.subject, "security/policy-set");
        assert!(last.detail.contains("initiator=/witness/op"));
    }

    /// Witness: §11.10 audit-bridge content_hash is deterministic
    /// across identical inputs and differs across different policies.
    /// The dashboard hashes the same JSON the operator submitted and
    /// stores the hex in `AuditLogEntry.detail`; the SHA-256 is what
    /// audit consumers cross-reference between forwarders.
    #[test]
    fn audit_bridge_hash_is_deterministic() {
        use sha2::{Digest as _, Sha256};
        let body_a = r#"{"ephemeral_allowed":false,"localhop_disabled":true,"replay_window_secs":120,"require_signed_commands":true,"validator_anchor":"/lab/ca"}"#;
        let body_b = r#"{"ephemeral_allowed":true,"localhop_disabled":true,"replay_window_secs":120,"require_signed_commands":true,"validator_anchor":"/lab/ca"}"#;

        let hash_a: [u8; 32] = Sha256::digest(body_a.as_bytes()).into();
        let hash_a2: [u8; 32] = Sha256::digest(body_a.as_bytes()).into();
        let hash_b: [u8; 32] = Sha256::digest(body_b.as_bytes()).into();
        assert_eq!(hash_a, hash_a2, "same body must hash to the same digest");
        assert_ne!(hash_a, hash_b, "different policies must hash differently");

        // Audit-bridge entry carries the hash as hex in detail.
        let entry_a = policy_set_audit_entry(1, "/witness/op", &hash_a);
        let entry_a2 = policy_set_audit_entry(1, "/witness/op", &hash_a);
        let entry_b = policy_set_audit_entry(1, "/witness/op", &hash_b);
        assert_eq!(
            entry_a.detail, entry_a2.detail,
            "deterministic hash → deterministic entry detail"
        );
        assert_ne!(entry_a.detail, entry_b.detail);
        assert!(
            entry_a
                .detail
                .contains(&format!("policy_content_hash={}", hex_lower(&hash_a)))
        );
    }

    fn hex_lower(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
        }
        out
    }

    #[cfg(feature = "desktop")]
    #[test]
    fn schema_global_append_round_trips_through_snapshot() {
        let dir = std::env::temp_dir().join(format!(
            "ndn-dashboard-schema-witness-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let kl = Name::root().append(b"witness").append(b"KEY").append(b"k0");
        crate::security_chains::init_schema_journal(dir.clone(), kl);
        let before = crate::security_chains::schema_journal_snapshot().len();
        let entry = SchemaJournalEntry {
            ts_unix_ns: 1_700_000_000_000_000_000,
            kind: SchemaJournalKind::AnchorAdd,
            subject_name: "anchor=/lab/ca/KEY/k0 fingerprint=abab".into(),
            initiator_name: "/witness/op".into(),
        };
        crate::security_chains::append_schema_entry(entry);
        let after = crate::security_chains::schema_journal_snapshot();
        assert!(after.len() > before);
        let last = after.last().expect("non-empty after append");
        assert_eq!(last.kind, SchemaJournalKind::AnchorAdd);
        assert!(last.subject_name.starts_with("anchor=/lab/ca/KEY/k0"));
    }
}
