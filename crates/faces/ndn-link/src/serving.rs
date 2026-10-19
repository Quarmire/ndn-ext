//! Whom this device serves as a relay: its serving policy and the quotas
//! of the devices it serves for other namespaces.
//!
//! A link nobody asked for — no [`PeerSpec`](crate::PeerSpec) dialled it,
//! expects its key or names its device — is admitted by the serving policy
//! ([`ServePolicy`]), which the deployer chooses:
//!
//! - **own** (the default): devices of the namespaces this device holds a
//!   certificate in (its link key's, or a membership's). A device of a
//!   namespace it holds the trust context of but no certificate in, or of
//!   one it does not hold, is refused ([`CloseReason::NotServed`]).
//! - **listed**: also devices of the namespaces whose root key fingerprint
//!   the deployer listed. When this device holds that namespace's trust
//!   context the device is checked as any of its devices (revocations, link
//!   policy); otherwise its certificate chain is checked offline against
//!   the self-signed root certificate its hello carries, whose key must be
//!   the listed one. Without the trust context nothing can be revoked: a
//!   revoked device of such a namespace keeps linking until its certificate
//!   expires, and the namespace's link policy is not known, so it is not
//!   applied (every role is served).
//! - **open**: devices of any namespace whose hello chain ends in a
//!   self-signed root certificate that validates the device's certificate,
//!   checked offline as for listed ones, under [`Quotas`].
//!
//! The namespace of a device served this way is named by its root
//! certificate (`/<ns>/KEY/<id>`), its device by its certificate
//! (`/<ns>/<role>/<device>`); the relay routes that device name over the
//! link. One root serves a namespace name at a time among the live served
//! links: a device of another root claiming the same name — or the name of,
//! or a name under, a namespace this device holds — is refused, since the
//! relay cannot route both. Its own namespaces are never under quota.

use std::collections::HashMap;
use std::sync::Arc;

use ndn_face_quic::{CloseReason, KeyFingerprint, RateLimit, SharedRate};
use ndn_packet::Name;
use parking_lot::Mutex;

use crate::admission::{Identity, Judge, Refusal, list};

/// Whom this device serves on links nobody asked for. Expected keys and
/// devices of [`PeerSpec`](crate::PeerSpec)s are admitted whatever it is.
#[derive(Clone, Debug, Default)]
pub enum ServePolicy {
    /// Devices of the namespaces this device holds a certificate in.
    #[default]
    Own,
    /// Those, and devices of the namespaces whose root (anchor) key has
    /// one of these fingerprints; `quotas` bound the listed ones.
    Listed {
        roots: Vec<KeyFingerprint>,
        quotas: Option<Quotas>,
    },
    /// Devices of any namespace whose chain validates to the self-signed
    /// root certificate its hello carries, under `quotas` (its own
    /// namespaces excepted).
    Open { quotas: Quotas },
}

impl ServePolicy {
    /// One line for status: `own namespaces`, `own namespaces + 2 listed
    /// (quotas: …)`, `open (quotas: …)`.
    pub fn describe(&self) -> String {
        match self {
            Self::Own => "own namespaces".into(),
            Self::Listed { roots, quotas } => {
                let quotas = quotas.map(|q| format!(" (quotas: {})", q.describe())).unwrap_or_default();
                format!("own namespaces + {} listed{quotas}", roots.len())
            }
            Self::Open { quotas } => format!("open (quotas: {})", quotas.describe()),
        }
    }
}

/// Bounds on the devices a relay serves for namespaces other than its own.
/// Interest rates are per second, with bursts.
#[derive(Clone, Copy, Debug)]
pub struct Quotas {
    /// Served links at once, all namespaces together.
    pub links_total: usize,
    /// Served links at once of one namespace (one root key).
    pub links_per_namespace: usize,
    /// Packets one served device may send.
    pub interests_per_key: RateLimit,
    /// Packets all served devices of one namespace may send together.
    pub interests_per_namespace: RateLimit,
}

impl Default for Quotas {
    /// 256 links, 32 per namespace; 100/s per key (burst 200), 400/s per
    /// namespace (burst 800): a household's devices browsing and syncing
    /// through a small server, without one namespace starving the others.
    fn default() -> Self {
        Self {
            links_total: 256,
            links_per_namespace: 32,
            interests_per_key: RateLimit {
                burst: 200,
                per_sec: 100,
            },
            interests_per_namespace: RateLimit {
                burst: 800,
                per_sec: 400,
            },
        }
    }
}

impl Quotas {
    /// `256 links, 32 per namespace, 100/s per key, 400/s per namespace`.
    pub fn describe(&self) -> String {
        format!(
            "{} links, {} per namespace, {}/s per key, {}/s per namespace",
            self.links_total,
            self.links_per_namespace,
            self.interests_per_key.per_sec,
            self.interests_per_namespace.per_sec
        )
    }
}

/// The links served for other namespaces now: how many per root, which root
/// each namespace name is bound to, and each root's shared rate.
#[derive(Default)]
pub(crate) struct QuotaState {
    live: Arc<Mutex<Live>>,
}

#[derive(Default)]
struct Live {
    total: usize,
    roots: HashMap<KeyFingerprint, RootLive>,
    /// Namespace name → the root serving it, and its live links.
    names: HashMap<Name, (KeyFingerprint, usize)>,
}

struct RootLive {
    links: usize,
    rate: Option<Arc<SharedRate>>,
}

/// One served link's place among the quotas; dropping it gives it back.
pub(crate) struct QuotaSlot {
    live: Arc<Mutex<Live>>,
    pub(crate) namespace: Name,
    root: KeyFingerprint,
    /// The per-key rate and the namespace's shared one, under quotas.
    pub(crate) limits: Option<(RateLimit, Arc<SharedRate>)>,
}

impl Drop for QuotaSlot {
    fn drop(&mut self) {
        let mut live = self.live.lock();
        live.total -= 1;
        if let Some(root) = live.roots.get_mut(&self.root) {
            root.links -= 1;
            if root.links == 0 {
                live.roots.remove(&self.root);
            }
        }
        if let Some((_, links)) = live.names.get_mut(&self.namespace) {
            *links -= 1;
            if *links == 0 {
                live.names.remove(&self.namespace);
            }
        }
    }
}

impl QuotaState {
    /// A slot for a link of `namespace`, whose root key is `root`, under
    /// `quotas` (none: only the one-root-per-name rule).
    pub(crate) fn take(&self, namespace: &Name, root: KeyFingerprint, quotas: Option<&Quotas>) -> Result<QuotaSlot, Refusal> {
        let mut live = self.live.lock();
        if let Some((bound, _)) = live.names.get(namespace)
            && *bound != root
        {
            return Err(Refusal::new(
                CloseReason::NotServed,
                format!(
                    "this relay serves {namespace} for the devices of another root key ({bound}) now, \
                     and yours is {root}: the names collide, and the relay cannot route both. Use a \
                     relay that does not serve the other {namespace}, or name your namespace apart"
                ),
            ));
        }
        let root_links = live.roots.get(&root).map_or(0, |r| r.links);
        if let Some(q) = quotas {
            if root_links >= q.links_per_namespace {
                return Err(Refusal::new(
                    CloseReason::Busy,
                    format!(
                        "this relay serves at most {} links of a namespace at once, and {namespace} has \
                         {root_links} here now: close another of its devices' links to this relay, try \
                         again later, or use another relay",
                        q.links_per_namespace
                    ),
                ));
            }
            if live.total >= q.links_total {
                return Err(Refusal::new(
                    CloseReason::Busy,
                    format!(
                        "this relay serves at most {} links of other namespaces at once and has {} now: \
                         try again later, or use another relay",
                        q.links_total, live.total
                    ),
                ));
            }
        }
        live.total += 1;
        let entry = live.roots.entry(root).or_insert_with(|| RootLive {
            links: 0,
            rate: quotas.map(|q| Arc::new(SharedRate::new(q.interests_per_namespace))),
        });
        entry.links += 1;
        let limits = quotas.zip(entry.rate.clone()).map(|(q, rate)| (q.interests_per_key, rate));
        live.names.entry(namespace.clone()).or_insert((root, 0)).1 += 1;
        Ok(QuotaSlot {
            live: Arc::clone(&self.live),
            namespace: namespace.clone(),
            root,
            limits,
        })
    }
}

impl Judge<'_> {
    /// The held namespaces this device holds a certificate in.
    pub(crate) fn own_namespaces(&self) -> Vec<Name> {
        self.trust
            .keyring()
            .contexts()
            .iter()
            .map(|c| c.namespace().clone())
            .filter(|ns| !ns.is_empty() && self.own_role_in(ns).is_some())
            .collect()
    }

    /// Whether the serving policy serves `id`, a device linking unasked,
    /// and its quota slot when it is served for a namespace other than this
    /// device's own.
    pub(crate) fn serves(&self, id: &Identity) -> Result<Option<QuotaSlot>, Refusal> {
        let own = self.own_namespaces();
        let own_text = if own.is_empty() {
            "this relay holds no certificate, so it serves no namespace of its own".to_string()
        } else {
            format!("this relay serves devices of its own namespaces ({})", list(&own))
        };
        let root = match id.served {
            Some(root) => root,
            None => {
                if own.contains(&id.namespace) {
                    return Ok(None);
                }
                let anchors = self.held_roots(&id.namespace);
                if let ServePolicy::Listed { roots, quotas } = self.serve
                    && let Some(root) = anchors.iter().find(|a| roots.contains(a))
                {
                    return self.quotas.take(&id.namespace, *root, quotas.as_ref()).map(Some);
                }
                let listed = match self.serve {
                    ServePolicy::Listed { roots, .. } => format!(
                        " and of {} namespaces listed by root key fingerprint, which {}'s ({}) is not",
                        roots.len(),
                        id.namespace,
                        anchors.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
                    ),
                    _ => String::new(),
                };
                return Err(Refusal::new(
                    CloseReason::NotServed,
                    format!(
                        "{own_text}{listed}; you are {} of {}, whose trust context it holds but which it \
                         holds no certificate in. Its operator can serve other namespaces by their root \
                         key fingerprint, or use a relay that serves yours",
                        id.device, id.namespace
                    ),
                ));
            }
        };
        match self.serve {
            ServePolicy::Listed { roots, quotas } if roots.contains(&root) => {
                self.quotas.take(&id.namespace, root, quotas.as_ref()).map(Some)
            }
            ServePolicy::Open { quotas } => self.quotas.take(&id.namespace, root, Some(quotas)).map(Some),
            ServePolicy::Listed { roots, .. } => Err(Refusal::new(
                CloseReason::NotServed,
                format!(
                    "{own_text} and of {} namespaces listed by root key fingerprint; you are {} of {}, \
                     whose root key {root} is not listed. Its operator can list it, or use a relay that \
                     serves yours",
                    roots.len(),
                    id.device,
                    id.namespace
                ),
            )),
            ServePolicy::Own => Err(Refusal::new(
                CloseReason::NotServed,
                format!(
                    "{own_text}; you are {} of {} (root key {root}). Its operator can serve other \
                     namespaces by their root key fingerprint, or use a relay that serves yours",
                    id.device, id.namespace
                ),
            )),
        }
    }

    /// The fingerprints of the anchor keys of the held namespace `ns`.
    fn held_roots(&self, ns: &Name) -> Vec<KeyFingerprint> {
        self.trust
            .keyring()
            .contexts()
            .iter()
            .filter(|c| c.namespace() == ns)
            .flat_map(|c| {
                c.anchors()
                    .iter()
                    .map(|a| KeyFingerprint::of_ndn_key(&a.value().public_key))
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}
