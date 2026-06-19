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

use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_security::confidentiality::{ContentKey, Sealed};
use ndn_service_core::{Frame, ServiceError};
use ndn_sync::{Publication, SvsPubSub};
use tokio::sync::mpsc;

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
        let aad = Bytes::copy_from_slice(name.to_string().as_bytes());
        ScopedTopic {
            ps: self.ps.clone(),
            key: self.scope_key.clone(),
            aad,
            name,
            _marker: PhantomData,
        }
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
