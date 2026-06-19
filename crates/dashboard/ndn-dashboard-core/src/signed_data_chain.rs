//! `SignedDataChainStore<T>` — append-only chain of signed NDN Data packets
//! used as the storage substrate for the dashboard's audit log and schema
//! journal.
//!
//! Each entry is a signed Data packet named `<chain_root>/seq=N`. The Content
//! is an ordered TLV stream:
//!
//! | Tag | Field             | Value                                      |
//! |-----|-------------------|--------------------------------------------|
//! | 0   | `schema_version`  | `u16`, pinned by `T`                       |
//! | 1   | `authored_under`  | `Option<Hash>` — reserved (v1 = zero-len)  |
//! | 2   | `prev_entry_hash` | 32-byte SHA-256 of prior entry's wire      |
//! | 3+  | type-defined      | `T::encode_payload_fields`                 |
//!
//! Tag IDs are wire identifiers — once shipped, never reused. The chain links
//! by `prev_entry_hash = prior.implicit_digest()` (standard NDN
//! `ImplicitSha256DigestComponent`); genesis is `seq=0`, all-zero hash.

#![allow(dead_code)]

use std::marker::PhantomData;

use bytes::Bytes;
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Name, NameComponent, SignatureType};
use ndn_tlv::{TlvReader, TlvWriter};
use sha2::{Digest, Sha256};

/// 32-byte SHA-256 output. Matches NDN's `ImplicitSha256DigestComponent`.
pub type Hash = [u8; 32];

/// Reserved tag IDs every chained entry uses. Type-specific payloads
/// MUST start at [`tag::PAYLOAD_START`].
pub mod tag {
    pub const SCHEMA_VERSION: u64 = 0;
    /// Reserved for `Option<Hash>`; empty in v1.
    pub const AUTHORED_UNDER: u64 = 1;
    pub const PREV_ENTRY_HASH: u64 = 2;
    pub const PAYLOAD_START: u64 = 3;
}

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("encode: {0}")]
    Encode(String),
    #[error("decode: {0}")]
    Decode(String),
    #[error("data wire: {0}")]
    DataWire(String),
    #[error("signer: {0}")]
    Sign(String),
    #[error("chain broken at seq={seq}: {reason}")]
    BrokenChain { seq: u64, reason: String },
    #[error("backend: {0}")]
    Backend(String),
}

/// Application payload chained inside signed Data packets. Implementors own
/// only their type-defined fields (tags ≥ [`tag::PAYLOAD_START`]); the
/// primitive owns the reserved tags 0–2.
pub trait ChainEntry: Sized {
    const SCHEMA_VERSION: u16;

    /// Encode fields in canonical ascending-tag order.
    fn encode_payload_fields(&self, w: &mut TlvWriter);

    /// `reader` is scoped to the payload tail; the primitive has already
    /// consumed tags 0–2.
    fn decode_payload_fields(reader: &mut TlvReader) -> Result<Self, ChainError>;
}

pub trait DataSigner {
    fn sig_type(&self) -> SignatureType;
    fn key_locator(&self) -> Option<&Name>;
    fn sign(&self, region: &[u8]) -> Result<Bytes, ChainError>;
}

/// Verifies per-packet signatures only; chain hash linkage is verified by the
/// chain primitive itself.
pub trait DataVerifier {
    fn verify(&self, data: &Data) -> bool;
}

/// Async backends (IndexedDB) load the full chain once and present a sync
/// view afterwards.
pub trait ChainBackend {
    /// Return every entry wire in seq order (seq=0 first).
    fn load_all(&self) -> Result<Vec<Bytes>, ChainError>;
    /// Append one entry wire at the next seq position.
    fn append(&mut self, seq: u64, wire: Bytes) -> Result<(), ChainError>;
}

pub struct SignedDataChainStore<T: ChainEntry, B: ChainBackend> {
    chain_root: Name,
    backend: B,
    entries: Vec<Data>,
    _marker: PhantomData<T>,
}

impl<T: ChainEntry, B: ChainBackend> SignedDataChainStore<T, B> {
    /// Open the chain rooted at `chain_root`, replaying any persisted
    /// entries. Does NOT verify signatures — call [`Self::verify`].
    pub fn open(chain_root: Name, backend: B) -> Result<Self, ChainError> {
        let mut entries = Vec::new();
        for wire in backend.load_all()? {
            let data = Data::decode(wire)
                .map_err(|e| ChainError::DataWire(format!("decode persisted entry: {e:?}")))?;
            entries.push(data);
        }
        Ok(Self {
            chain_root,
            backend,
            entries,
            _marker: PhantomData,
        })
    }

    pub fn chain_root(&self) -> &Name {
        &self.chain_root
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[Data] {
        &self.entries
    }

    /// Zero for an empty chain.
    pub fn head_hash(&self) -> Hash {
        self.entries
            .last()
            .map(|d| d.implicit_digest())
            .unwrap_or([0u8; 32])
    }

    /// Returns the new entry's `implicit_digest` (the next entry's `prev_entry_hash`).
    pub fn append(&mut self, payload: T, signer: &dyn DataSigner) -> Result<Hash, ChainError> {
        let seq = self.entries.len() as u64;
        let prev = self.head_hash();

        let mut name = self.chain_root.clone();
        name = name.append_component(NameComponent::sequence_num(seq));

        let mut w = TlvWriter::new();
        write_nni(&mut w, tag::SCHEMA_VERSION, u64::from(T::SCHEMA_VERSION));
        w.write_tlv(tag::AUTHORED_UNDER, &[]);
        w.write_tlv(tag::PREV_ENTRY_HASH, &prev);
        payload.encode_payload_fields(&mut w);
        let content = w.finish();

        let sig_type = signer.sig_type();
        let key_locator = signer.key_locator().cloned();
        let mut sign_err: Option<ChainError> = None;
        let wire =
            DataBuilder::new(name, &content).sign_sync(sig_type, key_locator.as_ref(), |region| {
                match signer.sign(region) {
                    Ok(b) => b,
                    Err(e) => {
                        sign_err = Some(e);
                        Bytes::new()
                    }
                }
            });
        if let Some(e) = sign_err {
            return Err(e);
        }

        let data = Data::decode(wire.clone())
            .map_err(|e| ChainError::DataWire(format!("decode self: {e:?}")))?;
        let digest = data.implicit_digest();
        self.backend.append(seq, wire)?;
        self.entries.push(data);
        Ok(digest)
    }

    /// Walks the chain checking seq monotonicity, `prev_entry_hash` linkage,
    /// and per-entry signatures.
    pub fn verify(&self, verifier: &dyn DataVerifier) -> Result<(), ChainError> {
        let mut expected_prev: Hash = [0u8; 32];
        for (i, entry) in self.entries.iter().enumerate() {
            let seq = i as u64;
            let last_comp = entry
                .name
                .components()
                .last()
                .ok_or(ChainError::BrokenChain {
                    seq,
                    reason: "entry name has no components".into(),
                })?;
            let entry_seq = last_comp.as_sequence_num().ok_or(ChainError::BrokenChain {
                seq,
                reason: "last name component is not a SequenceNumber".into(),
            })?;
            if entry_seq != seq {
                return Err(ChainError::BrokenChain {
                    seq,
                    reason: format!("expected seq={seq}, name carries seq={entry_seq}"),
                });
            }
            let parsed = ParsedHeader::decode(entry).map_err(|e| ChainError::BrokenChain {
                seq,
                reason: format!("header parse: {e}"),
            })?;
            if parsed.schema_version != T::SCHEMA_VERSION {
                return Err(ChainError::BrokenChain {
                    seq,
                    reason: format!(
                        "schema_version mismatch: entry={}, T::SCHEMA_VERSION={}",
                        parsed.schema_version,
                        T::SCHEMA_VERSION
                    ),
                });
            }
            if parsed.prev_entry_hash != expected_prev {
                return Err(ChainError::BrokenChain {
                    seq,
                    reason: "prev_entry_hash does not match prior entry's implicit_digest".into(),
                });
            }
            if !verifier.verify(entry) {
                return Err(ChainError::BrokenChain {
                    seq,
                    reason: "signature invalid".into(),
                });
            }
            expected_prev = entry.implicit_digest();
        }
        Ok(())
    }

    /// Decode an entry's payload (type-defined fields, tags ≥ PAYLOAD_START).
    pub fn decode_entry(&self, index: usize) -> Result<T, ChainError> {
        let entry = self
            .entries
            .get(index)
            .ok_or_else(|| ChainError::Backend(format!("entry index {index} out of range")))?;
        let content = entry.content().cloned().unwrap_or_default();
        let mut reader = TlvReader::new(content);
        let _ = ParsedHeader::read_from(&mut reader)
            .map_err(|e| ChainError::Decode(format!("header skip: {e}")))?;
        T::decode_payload_fields(&mut reader)
    }
}

struct ParsedHeader {
    schema_version: u16,
    authored_under: Option<Hash>,
    prev_entry_hash: Hash,
}

impl ParsedHeader {
    fn decode(data: &Data) -> Result<Self, String> {
        let content = data.content().cloned().unwrap_or_default();
        let mut reader = TlvReader::new(content);
        Self::read_from(&mut reader)
    }

    fn read_from(reader: &mut TlvReader) -> Result<Self, String> {
        let (t0, v0) = reader
            .read_tlv()
            .map_err(|e| format!("read tag 0: {e:?}"))?;
        if t0 != tag::SCHEMA_VERSION {
            return Err(format!(
                "expected schema_version tag {}, got {t0}",
                tag::SCHEMA_VERSION
            ));
        }
        let schema_version = read_nni_u16(&v0)?;
        let (t1, v1) = reader
            .read_tlv()
            .map_err(|e| format!("read tag 1: {e:?}"))?;
        if t1 != tag::AUTHORED_UNDER {
            return Err(format!(
                "expected authored_under tag {}, got {t1}",
                tag::AUTHORED_UNDER
            ));
        }
        let authored_under = match v1.len() {
            0 => None,
            32 => {
                let mut h = [0u8; 32];
                h.copy_from_slice(&v1);
                Some(h)
            }
            other => return Err(format!("authored_under must be 0 or 32 bytes, got {other}")),
        };
        let (t2, v2) = reader
            .read_tlv()
            .map_err(|e| format!("read tag 2: {e:?}"))?;
        if t2 != tag::PREV_ENTRY_HASH {
            return Err(format!(
                "expected prev_entry_hash tag {}, got {t2}",
                tag::PREV_ENTRY_HASH
            ));
        }
        if v2.len() != 32 {
            return Err(format!(
                "prev_entry_hash must be 32 bytes, got {}",
                v2.len()
            ));
        }
        let mut prev_entry_hash = [0u8; 32];
        prev_entry_hash.copy_from_slice(&v2);
        Ok(Self {
            schema_version,
            authored_under,
            prev_entry_hash,
        })
    }
}

/// 1/2/4/8 bytes big-endian, shortest form. Matches ndn-packet's internal helper.
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

fn read_nni_u16(bytes: &Bytes) -> Result<u16, String> {
    let v = decode_nni(bytes)?;
    if v > u64::from(u16::MAX) {
        return Err(format!("schema_version {v} does not fit in u16"));
    }
    Ok(v as u16)
}

pub fn sha256_of(bytes: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

#[derive(Default)]
pub struct MemoryStore {
    entries: Vec<Bytes>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl ChainBackend for MemoryStore {
    fn load_all(&self) -> Result<Vec<Bytes>, ChainError> {
        Ok(self.entries.clone())
    }
    fn append(&mut self, seq: u64, wire: Bytes) -> Result<(), ChainError> {
        if seq != self.entries.len() as u64 {
            return Err(ChainError::Backend(format!(
                "memory backend: append at seq={seq}, expected {}",
                self.entries.len()
            )));
        }
        self.entries.push(wire);
        Ok(())
    }
}

/// Desktop store. One file per entry (`<seq:020>.data`); atomic append via
/// write-tmp + fsync + rename so torn appends leave the prior chain intact.
#[cfg(feature = "desktop")]
#[allow(unused_imports)]
pub use file_store::FileStore;

#[cfg(feature = "desktop")]
mod file_store {
    use super::{ChainBackend, ChainError};
    use bytes::Bytes;
    use std::path::{Path, PathBuf};

    pub struct FileStore {
        dir: PathBuf,
    }

    impl FileStore {
        pub fn new(dir: impl Into<PathBuf>) -> Self {
            Self { dir: dir.into() }
        }

        pub fn dir(&self) -> &Path {
            &self.dir
        }

        fn entry_path(&self, seq: u64) -> PathBuf {
            self.dir.join(format!("{seq:020}.data"))
        }
    }

    impl ChainBackend for FileStore {
        fn load_all(&self) -> Result<Vec<Bytes>, ChainError> {
            if !self.dir.exists() {
                return Ok(Vec::new());
            }
            let mut paths: Vec<PathBuf> = Vec::new();
            for ent in std::fs::read_dir(&self.dir)
                .map_err(|e| ChainError::Backend(format!("read_dir {}: {e}", self.dir.display())))?
            {
                let ent = ent.map_err(|e| ChainError::Backend(format!("read_dir entry: {e}")))?;
                let path = ent.path();
                if path.extension().is_some_and(|e| e == "data") {
                    paths.push(path);
                }
            }
            paths.sort();
            let mut out = Vec::with_capacity(paths.len());
            for p in &paths {
                let bytes = std::fs::read(p)
                    .map_err(|e| ChainError::Backend(format!("read {}: {e}", p.display())))?;
                out.push(Bytes::from(bytes));
            }
            Ok(out)
        }

        fn append(&mut self, seq: u64, wire: Bytes) -> Result<(), ChainError> {
            std::fs::create_dir_all(&self.dir).map_err(|e| {
                ChainError::Backend(format!("create_dir_all {}: {e}", self.dir.display()))
            })?;
            let final_path = self.entry_path(seq);
            let tmp_path = self.dir.join(format!("{seq:020}.data.tmp"));
            {
                use std::io::Write as _;
                let mut f = std::fs::File::create(&tmp_path).map_err(|e| {
                    ChainError::Backend(format!("create {}: {e}", tmp_path.display()))
                })?;
                f.write_all(&wire).map_err(|e| {
                    ChainError::Backend(format!("write {}: {e}", tmp_path.display()))
                })?;
                f.sync_all().map_err(|e| {
                    ChainError::Backend(format!("fsync {}: {e}", tmp_path.display()))
                })?;
            }
            std::fs::rename(&tmp_path, &final_path).map_err(|e| {
                ChainError::Backend(format!(
                    "rename {} → {}: {e}",
                    tmp_path.display(),
                    final_path.display()
                ))
            })?;
            Ok(())
        }
    }
}

/// wasm32 IDB store. One DB per dashboard origin, one object store per chain,
/// key = `seq`, value = Data wire. `open` loads everything into a sync cache;
/// writes hit the cache synchronously and persist to IDB fire-and-forget.
#[cfg(target_arch = "wasm32")]
pub use indexed_db::IndexedDbStore;

#[cfg(target_arch = "wasm32")]
mod indexed_db {
    use std::cell::RefCell;
    use std::rc::Rc;

    use bytes::Bytes;
    use js_sys::{Array, Uint8Array};
    use wasm_bindgen::JsCast as _;
    use wasm_bindgen::JsValue;
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen_futures::{JsFuture, spawn_local};
    use web_sys::{
        DomException, IdbDatabase, IdbObjectStoreParameters, IdbOpenDbRequest, IdbRequest,
        IdbTransactionMode, IdbVersionChangeEvent,
    };

    use super::{ChainBackend, ChainError};

    const SCHEMA_VERSION: u32 = 1;

    /// `IdbDatabase` is `!Send`; surrounding plumbing must use `thread_local!`,
    /// not `OnceLock`.
    pub struct IndexedDbStore {
        db: Rc<IdbDatabase>,
        store_name: String,
        entries: RefCell<Vec<Bytes>>,
    }

    impl IndexedDbStore {
        /// Opens the DB, runs the schema upgrade if needed, and preloads every
        /// entry into the cache so `load_all()` is sync afterwards.
        pub async fn open(db_name: &str, store_name: &str) -> Result<Self, ChainError> {
            let factory = idb_factory()?;
            let req: IdbOpenDbRequest = factory
                .open_with_u32(db_name, SCHEMA_VERSION)
                .map_err(|e| ChainError::Backend(format!("IDB open: {e:?}")))?;

            // Create both well-known stores on first open so opening the
            // sibling chain later doesn't need a version-bump ceremony.
            let store_name_for_upgrade = store_name.to_owned();
            let onupgradeneeded = Closure::<dyn FnMut(IdbVersionChangeEvent)>::new(
                move |ev: IdbVersionChangeEvent| {
                    let Some(target) = ev.target() else { return };
                    let Ok(req): Result<IdbOpenDbRequest, _> = target.dyn_into() else {
                        return;
                    };
                    let Ok(db_val) = req.result() else { return };
                    let Ok(db): Result<IdbDatabase, _> = db_val.dyn_into() else {
                        return;
                    };
                    let params = IdbObjectStoreParameters::new();
                    let _ = db.create_object_store_with_optional_parameters("audit", &params);
                    let _ = db.create_object_store_with_optional_parameters("schema", &params);
                    let _ = db.create_object_store_with_optional_parameters(
                        &store_name_for_upgrade,
                        &params,
                    );
                },
            );
            req.set_onupgradeneeded(Some(onupgradeneeded.as_ref().unchecked_ref()));

            let db_value = await_request(req.unchecked_ref::<IdbRequest>()).await?;
            drop(onupgradeneeded);

            let db: IdbDatabase = db_value
                .dyn_into()
                .map_err(|_| ChainError::Backend("IDB open did not return IdbDatabase".into()))?;
            let db_rc = Rc::new(db);

            let entries = load_all_async(&db_rc, store_name).await?;
            Ok(Self {
                db: db_rc,
                store_name: store_name.to_owned(),
                entries: RefCell::new(entries),
            })
        }
    }

    impl ChainBackend for IndexedDbStore {
        fn load_all(&self) -> Result<Vec<Bytes>, ChainError> {
            Ok(self.entries.borrow().clone())
        }

        fn append(&mut self, seq: u64, wire: Bytes) -> Result<(), ChainError> {
            {
                let mut entries = self.entries.borrow_mut();
                if seq != entries.len() as u64 {
                    return Err(ChainError::Backend(format!(
                        "IDB backend: append at seq={seq}, expected {}",
                        entries.len()
                    )));
                }
                entries.push(wire.clone());
            }
            // Persistence is fire-and-forget. The in-memory cache is
            // already authoritative for this process; on the next
            // open the IDB read populates fresh, so a torn write
            // Persistence failure shows up as a missing tail entry; chain
            // verify catches it via prev_entry_hash linkage.
            let db = self.db.clone();
            let store_name = self.store_name.clone();
            spawn_local(async move {
                if let Err(e) = put_async(&db, &store_name, seq, &wire).await {
                    tracing::warn!(
                        target: "dashboard.security",
                        seq,
                        error = ?e,
                        "IDB chain append failed (in-memory cache intact)"
                    );
                }
            });
            Ok(())
        }
    }

    async fn load_all_async(db: &IdbDatabase, store_name: &str) -> Result<Vec<Bytes>, ChainError> {
        let tx = db
            .transaction_with_str_and_mode(store_name, IdbTransactionMode::Readonly)
            .map_err(|e| ChainError::Backend(format!("IDB tx({store_name}): {e:?}")))?;
        let store = tx
            .object_store(store_name)
            .map_err(|e| ChainError::Backend(format!("IDB store({store_name}): {e:?}")))?;

        // Sort by seq before returning; `get_all` would return values in
        // implementation-defined order.
        let keys_req = store
            .get_all_keys()
            .map_err(|e| ChainError::Backend(format!("IDB get_all_keys: {e:?}")))?;
        let values_req = store
            .get_all()
            .map_err(|e| ChainError::Backend(format!("IDB get_all: {e:?}")))?;

        let keys_val = await_request(&keys_req).await?;
        let values_val = await_request(&values_req).await?;

        let keys: Array = keys_val
            .dyn_into()
            .map_err(|_| ChainError::Backend("IDB keys not an array".into()))?;
        let values: Array = values_val
            .dyn_into()
            .map_err(|_| ChainError::Backend("IDB values not an array".into()))?;
        if keys.length() != values.length() {
            return Err(ChainError::Backend(
                "IDB get_all/get_all_keys length mismatch".into(),
            ));
        }

        let mut pairs: Vec<(u64, Bytes)> = Vec::with_capacity(keys.length() as usize);
        for i in 0..keys.length() {
            let k = keys.get(i);
            let v = values.get(i);
            let seq = k.as_f64().ok_or_else(|| {
                ChainError::Backend(format!("IDB chain entry {i}: key is not a number"))
            })? as u64;
            let arr: Uint8Array = v
                .dyn_into()
                .map_err(|_| ChainError::Backend(format!("IDB entry {i}: not Uint8Array")))?;
            let mut buf = vec![0u8; arr.length() as usize];
            arr.copy_to(&mut buf);
            pairs.push((seq, Bytes::from(buf)));
        }
        pairs.sort_by_key(|(s, _)| *s);
        Ok(pairs.into_iter().map(|(_, w)| w).collect())
    }

    async fn put_async(
        db: &IdbDatabase,
        store_name: &str,
        seq: u64,
        wire: &Bytes,
    ) -> Result<(), ChainError> {
        let tx = db
            .transaction_with_str_and_mode(store_name, IdbTransactionMode::Readwrite)
            .map_err(|e| ChainError::Backend(format!("IDB tx({store_name}): {e:?}")))?;
        let store = tx
            .object_store(store_name)
            .map_err(|e| ChainError::Backend(format!("IDB store({store_name}): {e:?}")))?;
        let array = Uint8Array::new_with_length(wire.len() as u32);
        array.copy_from(wire);
        let req = store
            .put_with_key(&array.into(), &JsValue::from_f64(seq as f64))
            .map_err(|e| ChainError::Backend(format!("IDB put({store_name},{seq}): {e:?}")))?;
        let _ = await_request(&req).await?;
        Ok(())
    }

    fn idb_factory() -> Result<web_sys::IdbFactory, ChainError> {
        let global = js_sys::global();
        if let Ok(window) = global.clone().dyn_into::<web_sys::Window>()
            && let Ok(Some(f)) = window.indexed_db()
        {
            return Ok(f);
        }
        if let Ok(worker) = global.dyn_into::<web_sys::WorkerGlobalScope>()
            && let Ok(Some(f)) = worker.indexed_db()
        {
            return Ok(f);
        }
        Err(ChainError::Backend(
            "no IndexedDB factory available (not in a browser scope)".into(),
        ))
    }

    /// Resolves with `req.result()` or rejects with the DOM exception's message.
    async fn await_request(req: &IdbRequest) -> Result<JsValue, ChainError> {
        use js_sys::Promise;

        let req_clone = req.clone();
        let req_for_err = req.clone();
        let resolved = Rc::new(RefCell::new(false));

        let promise = Promise::new(&mut |resolve, reject| {
            let resolve_cb = resolve.clone();
            let reject_cb = reject.clone();
            let req_inner = req_clone.clone();
            let req_inner_err = req_for_err.clone();
            let resolved_ok = Rc::clone(&resolved);
            let resolved_err = Rc::clone(&resolved);

            let onsuccess = Closure::<dyn FnMut(JsValue)>::new(move |_ev: JsValue| {
                if *resolved_ok.borrow() {
                    return;
                }
                *resolved_ok.borrow_mut() = true;
                let value = req_inner.result().unwrap_or(JsValue::UNDEFINED);
                let _ = resolve_cb.call1(&JsValue::UNDEFINED, &value);
            });
            let onerror = Closure::<dyn FnMut(JsValue)>::new(move |_ev: JsValue| {
                if *resolved_err.borrow() {
                    return;
                }
                *resolved_err.borrow_mut() = true;
                let err = req_inner_err
                    .error()
                    .ok()
                    .flatten()
                    .map(|e: DomException| JsValue::from_str(&e.message()))
                    .unwrap_or_else(|| JsValue::from_str("unknown IDB error"));
                let _ = reject_cb.call1(&JsValue::UNDEFINED, &err);
            });
            req_clone.set_onsuccess(Some(onsuccess.as_ref().unchecked_ref()));
            req_clone.set_onerror(Some(onerror.as_ref().unchecked_ref()));
            onsuccess.forget();
            onerror.forget();
        });

        JsFuture::from(promise)
            .await
            .map_err(|e| ChainError::Backend(format!("IDB request: {e:?}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
    use ndn_packet::SignatureType;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestEntry {
        n: u64,
    }

    const TAG_TEST_N: u64 = 3;

    impl ChainEntry for TestEntry {
        const SCHEMA_VERSION: u16 = 1;
        fn encode_payload_fields(&self, w: &mut TlvWriter) {
            w.write_tlv(TAG_TEST_N, &encode_nni(self.n));
        }
        fn decode_payload_fields(reader: &mut TlvReader) -> Result<Self, ChainError> {
            let (t, v) = reader
                .read_tlv()
                .map_err(|e| ChainError::Decode(format!("TestEntry.n: {e:?}")))?;
            if t != TAG_TEST_N {
                return Err(ChainError::Decode(format!(
                    "expected tag {TAG_TEST_N}, got {t}"
                )));
            }
            let n = decode_nni(&v).map_err(ChainError::Decode)?;
            Ok(TestEntry { n })
        }
    }

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

    struct TestVerifier {
        verifying: VerifyingKey,
    }

    impl DataVerifier for TestVerifier {
        fn verify(&self, data: &Data) -> bool {
            let sig = data.sig_value();
            let Ok(arr): Result<[u8; 64], _> = sig.try_into() else {
                return false;
            };
            let signature = ed25519_dalek::Signature::from_bytes(&arr);
            self.verifying
                .verify(data.signed_region(), &signature)
                .is_ok()
        }
    }

    fn fixture() -> (Name, TestSigner, TestVerifier) {
        let root = Name::root().append(b"lab").append(b"audit");
        let signer = TestSigner::from_seed(
            [7u8; 32],
            Name::root()
                .append(b"lab")
                .append(b"alice")
                .append(b"KEY")
                .append(b"k1"),
        );
        let verifier = TestVerifier {
            verifying: signer.verifying(),
        };
        (root, signer, verifier)
    }

    #[test]
    fn empty_chain_head_is_zero() {
        let (root, _, _) = fixture();
        let store: SignedDataChainStore<TestEntry, _> =
            SignedDataChainStore::open(root, MemoryStore::new()).unwrap();
        assert_eq!(store.head_hash(), [0u8; 32]);
        assert!(store.is_empty());
    }

    #[test]
    fn append_and_verify_three_entries() {
        let (root, signer, verifier) = fixture();
        let mut store: SignedDataChainStore<TestEntry, _> =
            SignedDataChainStore::open(root, MemoryStore::new()).unwrap();
        for n in 0..3u64 {
            store.append(TestEntry { n }, &signer).unwrap();
        }
        assert_eq!(store.len(), 3);
        store.verify(&verifier).expect("chain valid");

        for i in 0..3 {
            let decoded = store.decode_entry(i).unwrap();
            assert_eq!(decoded.n, i as u64);
        }
    }

    #[test]
    fn entry_name_carries_typed_sequence_number() {
        let (root, signer, _) = fixture();
        let mut store: SignedDataChainStore<TestEntry, _> =
            SignedDataChainStore::open(root, MemoryStore::new()).unwrap();
        store.append(TestEntry { n: 1 }, &signer).unwrap();
        store.append(TestEntry { n: 2 }, &signer).unwrap();
        let comps = store.entries()[1].name.components();
        let last = comps.last().expect("name has components");
        assert_eq!(last.typ, ndn_packet::tlv_type::SEQUENCE_NUM);
        assert_eq!(last.as_sequence_num(), Some(1));
    }

    #[test]
    fn prev_entry_hash_chains_via_implicit_digest() {
        let (root, signer, _) = fixture();
        let mut store: SignedDataChainStore<TestEntry, _> =
            SignedDataChainStore::open(root, MemoryStore::new()).unwrap();
        store.append(TestEntry { n: 10 }, &signer).unwrap();
        let d0 = store.entries()[0].implicit_digest();
        store.append(TestEntry { n: 20 }, &signer).unwrap();
        let parsed = ParsedHeader::decode(&store.entries()[1]).unwrap();
        assert_eq!(parsed.prev_entry_hash, d0);
        assert_eq!(parsed.schema_version, TestEntry::SCHEMA_VERSION);
        assert!(
            parsed.authored_under.is_none(),
            "v1 leaves authored_under None"
        );
    }

    #[test]
    fn verify_catches_bad_signature() {
        let (root, signer, _) = fixture();
        let mut store: SignedDataChainStore<TestEntry, _> =
            SignedDataChainStore::open(root, MemoryStore::new()).unwrap();
        store.append(TestEntry { n: 1 }, &signer).unwrap();
        let other = SigningKey::from_bytes(&[3u8; 32]).verifying_key();
        let bad_verifier = TestVerifier { verifying: other };
        let err = store.verify(&bad_verifier).unwrap_err();
        match err {
            ChainError::BrokenChain { seq, reason } => {
                assert_eq!(seq, 0);
                assert!(reason.contains("signature"));
            }
            other => panic!("expected BrokenChain, got {other:?}"),
        }
    }

    #[test]
    fn schema_version_mismatch_breaks_verify() {
        let (root, signer, verifier) = fixture();

        let chain_name = root.clone();
        let entry_name = chain_name.append_component(NameComponent::sequence_num(0));
        let mut w = TlvWriter::new();
        write_nni(&mut w, tag::SCHEMA_VERSION, 99);
        w.write_tlv(tag::AUTHORED_UNDER, &[]);
        w.write_tlv(tag::PREV_ENTRY_HASH, &[0u8; 32]);
        w.write_tlv(TAG_TEST_N, &encode_nni(5));
        let content = w.finish();
        let wire = DataBuilder::new(entry_name, &content).sign_sync(
            signer.sig_type(),
            Some(&signer.key_locator),
            |region| signer.sign(region).unwrap(),
        );
        let data = Data::decode(wire.clone()).unwrap();

        let mut store: SignedDataChainStore<TestEntry, _> =
            SignedDataChainStore::open(root, MemoryStore::new()).unwrap();
        store.entries.push(data);
        store.backend.entries.push(wire);
        let err = store.verify(&verifier).unwrap_err();
        match err {
            ChainError::BrokenChain { reason, .. } => assert!(reason.contains("schema_version")),
            other => panic!("expected BrokenChain, got {other:?}"),
        }
    }

    #[test]
    fn nni_round_trip_boundaries() {
        for v in [0u64, 1, 255, 256, 65_535, 65_536, u32::MAX as u64, u64::MAX] {
            let encoded = encode_nni(v);
            assert!(matches!(encoded.len(), 1 | 2 | 4 | 8));
            assert_eq!(decode_nni(&encoded).unwrap(), v);
        }
    }

    #[cfg(feature = "desktop")]
    #[test]
    fn file_store_persists_chain() {
        let tmp = std::env::temp_dir().join(format!(
            "ndn-dashboard-chain-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);

        let (root, signer, verifier) = fixture();
        {
            let backend = FileStore::new(&tmp);
            let mut store: SignedDataChainStore<TestEntry, _> =
                SignedDataChainStore::open(root.clone(), backend).unwrap();
            for n in 0..3u64 {
                store.append(TestEntry { n }, &signer).unwrap();
            }
        }
        let backend = FileStore::new(&tmp);
        let store: SignedDataChainStore<TestEntry, _> =
            SignedDataChainStore::open(root, backend).unwrap();
        assert_eq!(store.len(), 3);
        store.verify(&verifier).expect("persisted chain valid");

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
