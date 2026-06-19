//! Tier-2 collaboration (service-layer §3.3): scoped sessions with confidential
//! typed topics.
//!
//! A [`Session`] is a named collaboration scope over an SVS group with a shared
//! **scope key**. Members collaborate over [`ScopedTopic<T>`]s whose payloads are
//! sealed under that key (the `confidentiality` CK primitive, §6.1) — only
//! holders of the key (members) can read the feed. This composes the Tier-2
//! pieces rather than inventing a mega-primitive: a confidential topic = a
//! [`Topic`](crate::Topic)-style feed + CK sealing, scoped under the session name.
//!
//! **Membership is the scope key.** The roster (role type `R`) is *typed* metadata
//! (roles are not string-keyed, §3.3) for app logic; role-scoped keys (per-role
//! CK/ABE so a role gates which topics it can read) are a later increment. Key
//! distribution to members (e.g. via `ndn-sealed-box` per member, or ABE by role)
//! is out of band here — a `Session` is given its scope key.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::marker::PhantomData;
use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_security::confidentiality::{ContentKey, Sealed};
use ndn_service_core::{Frame, ServiceError};
use ndn_sync::{Publication, SvsPubSub};
use tokio::sync::mpsc;

/// Build a [`ScopedTopic`] for `name` sealed under `key` (AAD = the topic name).
fn build_scoped_topic<T: Frame>(
    ps: Arc<SvsPubSub>,
    name: Name,
    key: Arc<ContentKey>,
) -> ScopedTopic<T> {
    let aad = Bytes::copy_from_slice(name.to_string().as_bytes());
    ScopedTopic {
        ps,
        name,
        key,
        aad,
        _marker: PhantomData,
    }
}

/// A scoped collaboration session. `R` is the application's role type (typed, not
/// string-keyed).
pub struct Session<R> {
    name: Name,
    ps: Arc<SvsPubSub>,
    scope_key: Arc<ContentKey>,
    roster: HashMap<Name, R>,
}

impl<R> Session<R> {
    /// A session named `name` over `ps`, confidential under `scope_key` (shared by
    /// members). Starts with an empty roster.
    pub fn new(name: Name, ps: Arc<SvsPubSub>, scope_key: ContentKey) -> Self {
        Self {
            name,
            ps,
            scope_key: Arc::new(scope_key),
            roster: HashMap::new(),
        }
    }

    /// The session scope name.
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// Admit `member` with a typed `role`.
    pub fn admit(&mut self, member: Name, role: R) {
        self.roster.insert(member, role);
    }

    /// The typed role of `member`, if a member.
    pub fn role_of(&self, member: &Name) -> Option<&R> {
        self.roster.get(member)
    }

    /// The members and their typed roles.
    pub fn members(&self) -> impl Iterator<Item = (&Name, &R)> {
        self.roster.iter()
    }

    /// A confidential typed topic `<session>/<sub>`: payloads are sealed under the
    /// session scope key, so only members (key holders) can read the feed.
    pub fn scoped_topic<T: Frame>(&self, sub: &str) -> ScopedTopic<T> {
        let name = self.name.clone().append(sub.as_bytes());
        build_scoped_topic(self.ps.clone(), name, self.scope_key.clone())
    }

    /// Named-artifact provisioning within this session — confidential objects
    /// under the session scope key (see [`ArtifactShare`]).
    pub fn artifacts(&self) -> ArtifactShare {
        ArtifactShare {
            ps: self.ps.clone(),
            base: self.name.clone().append(ARTIFACTS),
            key: self.scope_key.clone(),
        }
    }
}

/// The `artifacts` name component under which a session's artifacts live.
const ARTIFACTS: &str = "artifacts";

/// Named-artifact provisioning within a session scope: a member **provisions**
/// (publishes) a named object and others **fetch** it by name. Each artifact is a
/// one-shot confidential object sealed under the scope key — a member without the
/// key cannot open it. Large artifacts ride `SvsPubSub`'s segmentation.
///
/// An artifact is modelled as a confidential typed object of bytes
/// ([`ScopedTopic<Bytes>`]) fetched once, so it reuses the same sealing path.
pub struct ArtifactShare {
    ps: Arc<SvsPubSub>,
    base: Name,
    key: Arc<ContentKey>,
}

impl ArtifactShare {
    fn object(&self, name: &str) -> ScopedTopic<Bytes> {
        build_scoped_topic(
            self.ps.clone(),
            self.base.clone().append(name.as_bytes()),
            self.key.clone(),
        )
    }

    /// Provision (publish) the artifact `name` with `content`, sealed under the
    /// scope key. Returns the publication sequence number.
    pub async fn provision(&self, name: &str, content: &[u8]) -> Result<u64, ServiceError> {
        self.object(name).publish(&Bytes::copy_from_slice(content)).await
    }

    /// Fetch the artifact `name`: await its publication and return the opened
    /// content. `None` if the session closes before it arrives.
    pub async fn fetch(&self, name: &str) -> Option<Bytes> {
        self.object(name).subscribe().await.recv().await
    }
}

/// A confidential typed topic within a [`Session`]: a feed of `T` sealed under the
/// session scope key.
pub struct ScopedTopic<T> {
    ps: Arc<SvsPubSub>,
    name: Name,
    key: Arc<ContentKey>,
    aad: Bytes,
    _marker: PhantomData<fn() -> T>,
}

impl<T: Frame> ScopedTopic<T> {
    /// The topic name.
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// Publish `value`, sealed under the session scope key. Returns the
    /// publication sequence number.
    pub async fn publish(&self, value: &T) -> Result<u64, ServiceError> {
        let plaintext = Frame::encode(value);
        let wire = self.key.seal(&plaintext, &self.aad).to_bytes();
        self.ps
            .publish(self.name.clone(), wire.as_ref())
            .await
            .map_err(|e| ServiceError::Transport(e.to_string()))
    }

    /// Subscribe to the confidential feed.
    pub async fn subscribe(&self) -> ScopedSubscription<T> {
        ScopedSubscription {
            rx: self.ps.subscribe(self.name.clone()).await,
            key: self.key.clone(),
            aad: self.aad.clone(),
            _marker: PhantomData,
        }
    }
}

/// A live subscription to a [`ScopedTopic<T>`]: decrypted, decoded values. An
/// entry that cannot be opened with the scope key (a non-member's view, or a
/// foreign/malformed publication) is skipped — a node without the key sees no
/// plaintext.
pub struct ScopedSubscription<T> {
    rx: mpsc::Receiver<Publication>,
    key: Arc<ContentKey>,
    aad: Bytes,
    _marker: PhantomData<fn() -> T>,
}

impl<T: Frame> ScopedSubscription<T> {
    /// Await the next decrypted value. `None` once the topic closes.
    pub async fn recv(&mut self) -> Option<T> {
        while let Some(publication) = self.rx.recv().await {
            let Ok(sealed) = Sealed::from_bytes(&publication.payload) else {
                continue;
            };
            let Ok(plaintext) = self.key.open(&sealed, &self.aad) else {
                continue; // not a member (wrong/absent key) — no plaintext
            };
            if let Ok(value) = T::decode(&plaintext) {
                return Some(value);
            }
        }
        None
    }
}

// --- Role-scoped keys: per-scope confidentiality, granted by role ---

/// The scope keys a member holds. A member can participate in a topic only in a
/// scope whose key is in its keyring — so confidentiality is *per scope*, not one
/// session-wide key. Build one per role with [`RoleScopePolicy::keyring_for`].
#[derive(Clone, Default)]
pub struct ScopeKeyring {
    keys: HashMap<String, Arc<ContentKey>>,
}

impl ScopeKeyring {
    /// An empty keyring.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add the key for `scope` (builder style).
    pub fn with(mut self, scope: impl Into<String>, key: ContentKey) -> Self {
        self.keys.insert(scope.into(), Arc::new(key));
        self
    }

    /// The key for `scope`, if held.
    pub fn get(&self, scope: &str) -> Option<Arc<ContentKey>> {
        self.keys.get(scope).cloned()
    }

    /// The scopes this keyring grants access to.
    pub fn scopes(&self) -> impl Iterator<Item = &str> {
        self.keys.keys().map(String::as_str)
    }
}

/// The ABE attribute prefix for a confidentiality scope. A scope key is wrapped
/// under `scope:<name>` and a role's KP-ABE key-policy references the same.
pub const SCOPE_ATTR: &str = "scope:";

/// Which scopes each role may access — the role→scope access policy. A member's
/// keyring is **derived from its role**: [`keyring_for`](Self::keyring_for) hands
/// out exactly the keys for the scopes the role is granted (role-scoped keys), so
/// a role gates which topics a member can read.
pub struct RoleScopePolicy<R> {
    grants: HashMap<R, HashSet<String>>,
}

impl<R> Default for RoleScopePolicy<R> {
    fn default() -> Self {
        Self {
            grants: HashMap::new(),
        }
    }
}

impl<R: Eq + Hash + Clone> RoleScopePolicy<R> {
    /// An empty policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Grant `role` access to `scope` (builder style).
    pub fn grant(mut self, role: R, scope: impl Into<String>) -> Self {
        self.grants.entry(role).or_default().insert(scope.into());
        self
    }

    /// The scopes `role` may access.
    pub fn scopes_for(&self, role: &R) -> Option<&HashSet<String>> {
        self.grants.get(role)
    }

    /// The KP-ABE key-policy expression for `role`: the OR of its granted scope
    /// attributes, e.g. `scope:control OR scope:telemetry`. A member issued a
    /// KP-ABE key for this policy can ABE-decrypt exactly those scopes' wrapped
    /// keys (see `key_dist`/`abe_dist`). `None` if the role grants nothing.
    pub fn key_policy_for(&self, role: &R) -> Option<String> {
        let scopes = self.grants.get(role)?;
        if scopes.is_empty() {
            return None;
        }
        let mut attrs: Vec<String> = scopes.iter().map(|s| format!("{SCOPE_ATTR}{s}")).collect();
        attrs.sort(); // deterministic
        Some(attrs.join(" OR "))
    }

    /// Derive the keyring for `role` from the full set of scope keys `all`: the
    /// keys for exactly the scopes this role is granted. A member is provisioned
    /// with the result; how the keys reach the member (sealed-box / ABE by role)
    /// is the key-distribution concern, separate from this access derivation.
    pub fn keyring_for(&self, role: &R, all: &ScopeKeyring) -> ScopeKeyring {
        let mut keyring = ScopeKeyring::new();
        if let Some(scopes) = self.grants.get(role) {
            for scope in scopes {
                if let Some(key) = all.keys.get(scope) {
                    keyring.keys.insert(scope.clone(), key.clone());
                }
            }
        }
        keyring
    }
}

/// A collaboration session keyed **per scope** (role-scoped keys): a member holds
/// only the scope keys its role grants, so it can participate only in topics
/// within those scopes. A topic in a scope the member's keyring lacks is
/// unavailable ([`topic`](Self::topic) returns `None`) — the role gate is enforced
/// by key possession (a capability), backed by the per-scope sealing.
pub struct ScopedSession {
    name: Name,
    ps: Arc<SvsPubSub>,
    keyring: ScopeKeyring,
}

impl ScopedSession {
    /// A session named `name` over `ps`, with the member's per-scope `keyring`.
    pub fn new(name: Name, ps: Arc<SvsPubSub>, keyring: ScopeKeyring) -> Self {
        Self { name, ps, keyring }
    }

    /// The session name.
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// A confidential topic `<session>/<scope>/<sub>`, sealed under the `scope`
    /// key. `None` if this member's keyring lacks `scope` — i.e. its role does not
    /// grant the scope, so it cannot publish to or read the topic.
    pub fn topic<T: Frame>(&self, scope: &str, sub: &str) -> Option<ScopedTopic<T>> {
        let key = self.keyring.get(scope)?;
        let name = self.name.clone().append(scope.as_bytes()).append(sub.as_bytes());
        Some(build_scoped_topic(self.ps.clone(), name, key))
    }

    /// Named-artifact provisioning within `scope` (confidential under the scope
    /// key). `None` if this member's keyring lacks `scope` — the role gate.
    pub fn artifacts(&self, scope: &str) -> Option<ArtifactShare> {
        let key = self.keyring.get(scope)?;
        Some(ArtifactShare {
            ps: self.ps.clone(),
            base: self.name.clone().append(scope.as_bytes()).append(ARTIFACTS),
            key,
        })
    }
}
