//! A data-layer device's link hint and dial over [`Links`] (feature
//! `introductions`; ndn-rs data-layer.md §19.2, §19.3).
//!
//! The data layer cannot depend on this crate, so a host gives its
//! `ndn_data::Introducer` the three halves it asks of it —
//! `link_hint`, `dial` and `undial` — by forwarding to a [`LinkHints`].

use std::sync::Arc;
use std::time::Duration;

use ndn_data::IntroductionSurface;
use ndn_data::intro::{Dialing, HintCandidate, HintKind, LinkHint, introduction_prefixes};
use ndn_face_quic::KeyFingerprint;
use ndn_packet::Name;

use crate::introduce::Introductions;
use crate::links::Links;

impl Introductions for IntroductionSurface {
    fn open(&self) -> bool {
        IntroductionSurface::open(self)
    }

    fn carries(&self, name: &Name) -> bool {
        IntroductionSurface::carries(self, name)
    }
}

/// What a data-layer device does over its [`Links`] for an introduction
/// code's link hint.
#[derive(Clone)]
pub struct LinkHints {
    links: Arc<Links>,
}

impl LinkHints {
    pub fn new(links: Arc<Links>) -> Self {
        Self { links }
    }

    /// The inviter's half: take introduction links for the device's
    /// introductions (its offer fetches and asks), from devices this one
    /// does not know, while one of its offers is open and carrying only what
    /// `surface` (the device's [`introductions`](ndn_data::Device::introductions))
    /// carries. Call it once, on the device that makes offers.
    pub fn serve(&self, surface: IntroductionSurface) {
        self.links.set_introductions(Arc::new(surface));
    }

    /// The hint to put into an offer's code: this device's link key and the
    /// candidate addresses of its listening socket, most promising first.
    /// `None` when it does not listen or has no usable key.
    pub fn hint(&self) -> Option<LinkHint> {
        let key = self.links.key_fingerprint()?;
        let candidates: Vec<HintCandidate> = self
            .links
            .hint_candidates()
            .into_iter()
            .filter_map(|c| {
                Some(HintCandidate {
                    kind: HintKind::from_code(c.kind.code())?,
                    addr: c.addr,
                })
            })
            .collect();
        (!candidates.is_empty()).then_some(LinkHint {
            key: key.0,
            candidates,
        })
    }

    /// The joiner's half: dial `inviter` by `hint`, every candidate at once,
    /// within `within` ([`Links::dial_by_key`]). `Ok` once the link to the
    /// device holding the hint's key is up; until that device is identified
    /// the link routes only `inviter`'s introduction prefixes, not the
    /// names the code claims for it.
    pub fn dial<'a>(
        &'a self,
        hint: &'a LinkHint,
        inviter: &'a Name,
        within: Duration,
    ) -> Dialing<'a> {
        Box::pin(async move {
            let addrs = hint.candidates.iter().map(|c| c.addr).collect();
            self.links
                .dial_by_key(
                    KeyFingerprint(hint.key),
                    inviter.clone(),
                    addrs,
                    within,
                    introduction_prefixes(inviter).into(),
                )
                .await
                .map_err(|detail| detail.text)
        })
    }

    /// The join that dialled `hint` failed: take down the link it made, if
    /// it is still one that carries only the introduction
    /// ([`Links::undial_by_key`]).
    pub fn undial(&self, hint: &LinkHint, inviter: &Name) {
        self.links.undial_by_key(
            KeyFingerprint(hint.key),
            &format!("the join that dialled {inviter} by its code's hint failed"),
        );
    }
}
