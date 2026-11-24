//! Admitting a run header (signals.md §8.1 step 8; ndn-heap spec §11.3).
//!
//! The node says who a header's signer is — a member by the entries held, offline
//! ([`NodeHandle::signal_sender`]) — and gives the validator that judges the signer's person
//! ([`NodeHandle::signal_view`]). What a header costs the network is decided here: it is verified
//! by that view under the **live** rule (its certificates valid now, a revoked key refused), the
//! certificates held first; one not held is fetched only within a budget, so a stranger's headers
//! cost no fetch and a member's cost a bounded one:
//!
//! - fewer than [`FETCHES_PER_NAMESPACE`] headers of the signer's person wait for certificates at
//!   once;
//! - none for a device whose last fetch brought none within [`FETCH_BACKOFF`], whatever key id
//!   its next header names;
//! - at most [`CHAIN_FETCHES`] certificates for one header.
//!
//! Past any of them the header is `Unverified`: its sender sends it again when it rides again.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ndn_foundation_types::Name;
use ndn_heap::host::NodeHandle;
use ndn_heap::{SignalRefusal, SignalSender};
use ndn_packet::Data;
use ndn_security::safe_data::TrustPath;
use ndn_security::{ValidationResult, Validator};
use tokio::time::Instant;

/// Run headers of one sender namespace that may wait for certificates at once.
const FETCHES_PER_NAMESPACE: usize = 2;

/// How long no certificate is fetched for a device's run headers again once a fetch for one of
/// them brought none.
const FETCH_BACKOFF: Duration = Duration::from_secs(30);

/// Certificates fetched for one run header at most: one chain.
const CHAIN_FETCHES: usize = 4;

/// Size at which devices past their back-off are swept.
const BACKOFF_PRUNE_AT: usize = 1024;

/// How many places of each key are taken.
#[derive(Default)]
struct Counts(Mutex<HashMap<Name, usize>>);

/// One place of a key, given back when dropped.
struct Place<'a> {
    counts: &'a Counts,
    key: Name,
}

impl Counts {
    /// A place for `key`, unless `max` are taken for it already.
    fn take(&self, key: &Name, max: usize) -> Option<Place<'_>> {
        let mut by = self.0.lock().expect("signal fetch budget lock");
        let taken = by.entry(key.clone()).or_default();
        if *taken >= max {
            return None;
        }
        *taken += 1;
        Some(Place {
            counts: self,
            key: key.clone(),
        })
    }
}

impl Drop for Place<'_> {
    fn drop(&mut self) {
        let mut by = self.counts.0.lock().expect("signal fetch budget lock");
        if let Some(taken) = by.get_mut(&self.key) {
            *taken -= 1;
            if *taken == 0 {
                by.remove(&self.key);
            }
        }
    }
}

/// What the transport keeps between run headers: the certificate fetches they wait for.
#[derive(Default)]
pub(super) struct Gate {
    /// Run headers waiting for certificates, per sender namespace.
    waiting: Counts,
    /// Devices no certificate is fetched for until then.
    backoff: Mutex<HashMap<Name, Instant>>,
}

impl Gate {
    /// Admit another device's run header for `scope`: its signer is a member
    /// ([`NodeHandle::signal_sender`], asked first, so a stranger's header costs nothing more),
    /// the header verifies by the node's view of its signer ([`Self::verify`]), and its signer
    /// is a member still once it verified (a removal or a revocation held while the chain was
    /// fetched ends the admission). The header is not kept, served nor counted.
    pub(super) async fn admit(
        &self,
        node: &NodeHandle,
        scope: &Name,
        header: &Data,
    ) -> Result<SignalSender, SignalRefusal> {
        let sender = node.signal_sender(scope, header)?;
        let view = node.signal_view(scope, header)?;
        self.verify(&view, &sender, header).await?;
        node.signal_sender(scope, header)
    }

    /// A place for `sender`'s header among those waiting for certificates: refused while its
    /// device backs off, or while its namespace has [`FETCHES_PER_NAMESPACE`] waiting.
    fn fetch_slot(&self, sender: &SignalSender) -> Result<Place<'_>, SignalRefusal> {
        let unverified = |why: String| SignalRefusal::Unverified {
            key: sender.key.clone(),
            why,
        };
        let backing_off = self
            .backoff
            .lock()
            .expect("signal fetch backoff lock")
            .get(&sender.device)
            .is_some_and(|&until| Instant::now() < until);
        if backing_off {
            return Err(unverified(format!(
                "a certificate a header of {} needed could not be had a moment ago, and none is \
                 fetched for that device for {} s after",
                sender.device,
                FETCH_BACKOFF.as_secs()
            )));
        }
        self.waiting
            .take(&sender.namespace, FETCHES_PER_NAMESPACE)
            .ok_or_else(|| {
                unverified(format!(
                    "{FETCHES_PER_NAMESPACE} run headers of {} wait for certificates here \
                     already",
                    sender.namespace
                ))
            })
    }

    /// A fetch for a header of `device` brought no certificate: none is fetched for it for
    /// [`FETCH_BACKOFF`].
    fn backoff(&self, device: &Name) {
        let mut backoff = self.backoff.lock().expect("signal fetch backoff lock");
        let now = Instant::now();
        if backoff.len() >= BACKOFF_PRUNE_AT {
            backoff.retain(|_, until| now < *until);
        }
        backoff.insert(device.clone(), now + FETCH_BACKOFF);
    }

    /// Verify `sender`'s run header by `view`, the live rule: the certificates held first; one
    /// missing fetched within the sender namespace's place among the headers waiting for
    /// certificates, at most [`CHAIN_FETCHES`] of them.
    async fn verify(
        &self,
        view: &Arc<Validator>,
        sender: &SignalSender,
        header: &Data,
    ) -> Result<(), SignalRefusal> {
        let key = &sender.key;
        let unverified = |why: String| SignalRefusal::Unverified {
            key: key.clone(),
            why,
        };
        let mut slot = None;
        for _ in 0..=CHAIN_FETCHES {
            let missing = match view.validate_chain_cached(header).await {
                (ValidationResult::Valid(safe), _)
                    if !matches!(safe.trust_path(), TrustPath::DigestSha256) =>
                {
                    return Ok(());
                }
                (ValidationResult::Pending, Some(missing)) => missing,
                (other, _) => {
                    tracing::debug!(
                        target: "ndn_surface::signal",
                        name = %header.name, %key, "signal run header refused: {other:?}"
                    );
                    return Err(SignalRefusal::BadSignature { key: key.clone() });
                }
            };
            let Some(fetcher) = view.cert_fetcher() else {
                return Err(unverified(format!(
                    "the certificate {missing} its chain needs is not held here, and this device \
                     fetches none"
                )));
            };
            if slot.is_none() {
                slot = Some(self.fetch_slot(sender)?);
            }
            if let Err(e) = fetcher.fetch_missing(&missing, None).await {
                self.backoff(&sender.device);
                let held = match view.cert_cache().all(&missing).is_empty() {
                    false => {
                        "only an expired certificate of it is held here, so its device renews \
                         its certificate; "
                    }
                    true => "",
                };
                return Err(unverified(format!(
                    "no current certificate {missing} its chain needs could be had ({e}); {held}\
                     none is fetched for {} for {} s",
                    sender.device,
                    FETCH_BACKOFF.as_secs()
                )));
            }
        }
        Err(unverified(format!(
            "its chain needs more than {CHAIN_FETCHES} certificates not held here"
        )))
    }
}

#[cfg(test)]
mod tests;
