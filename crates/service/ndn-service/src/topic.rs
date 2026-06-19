//! Tier-2 typed pub/sub: [`Topic<T>`] (service-layer §3.3, §12.2).
//!
//! A topic is the **feed** primitive, distinct from a service operation (the
//! **call** primitive): a publisher emits values of type `T` over time and any
//! number of subscribers receive the stream — one-to-many, push, no reply. Both
//! use the same typed-payload machinery ([`Frame`]); the difference is the shape
//! of interaction, which is exactly why topics are a *separate* primitive rather
//! than a streaming variant of `#[ndn_service]` (the unary-only boundary, §12.2).
//!
//! ```no_run
//! # use ndn_service::topic::Topic;
//! # use ndn_sync::SvsPubSub;
//! # use std::sync::Arc;
//! # async fn demo(ps: Arc<SvsPubSub>) {
//! let temps: Topic<u64> = Topic::new(ps, "/fleet/telemetry".parse().unwrap());
//! let mut feed = temps.subscribe().await;
//! temps.publish(&21).await.unwrap();
//! while let Some(reading) = feed.recv().await { /* … */ break }
//! # }
//! ```
//!
//! `Topic<T>` carries values under the topic name in an SVS group; subscribers
//! match the topic prefix and decode each publication as `T`. It builds on
//! `ndn-sync`'s `SvsPubSub`, so a topic and a four-phase service can share one
//! group/engine.

use std::marker::PhantomData;
use std::sync::Arc;

use ndn_packet::Name;
use ndn_service_core::{Frame, ServiceError};
use ndn_sync::{Publication, SvsPubSub};
use tokio::sync::mpsc;

/// A typed pub/sub topic: publish and subscribe to a feed of `T` over an SVS
/// group. Clone-free sharing is via the `Arc<SvsPubSub>` it holds (so the same
/// node can host several topics and services over one group).
pub struct Topic<T> {
    ps: Arc<SvsPubSub>,
    name: Name,
    _marker: PhantomData<fn() -> T>,
}

impl<T: Frame> Topic<T> {
    /// A topic named `name` over the pub/sub `ps`.
    pub fn new(ps: Arc<SvsPubSub>, name: Name) -> Self {
        Self {
            ps,
            name,
            _marker: PhantomData,
        }
    }

    /// The topic name (its prefix in the group).
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// Publish `value` to the topic. Returns the publication sequence number.
    pub async fn publish(&self, value: &T) -> Result<u64, ServiceError> {
        let blob = Frame::encode(value);
        self.ps
            .publish(self.name.clone(), blob.as_ref())
            .await
            .map_err(|e| ServiceError::Transport(e.to_string()))
    }

    /// Subscribe to the topic, returning a [`Subscription`] that yields each
    /// published `T` as it arrives.
    pub async fn subscribe(&self) -> Subscription<T> {
        Subscription {
            rx: self.ps.subscribe(self.name.clone()).await,
            _marker: PhantomData,
        }
    }
}

/// A live subscription to a [`Topic<T>`]: a stream of decoded values.
pub struct Subscription<T> {
    rx: mpsc::Receiver<Publication>,
    _marker: PhantomData<fn() -> T>,
}

impl<T: Frame> Subscription<T> {
    /// Await the next published value. `None` once the topic closes. A
    /// publication whose payload does not decode as `T` (malformed or from a
    /// foreign publisher sharing the prefix) is skipped, not surfaced as an
    /// error — a bad message does not break the feed.
    pub async fn recv(&mut self) -> Option<T> {
        while let Some(publication) = self.rx.recv().await {
            if let Ok(value) = T::decode(&publication.payload) {
                return Some(value);
            }
        }
        None
    }
}
