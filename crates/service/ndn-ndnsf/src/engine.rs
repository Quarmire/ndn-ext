//! Bind an `SvsPubSub` group — and thus the [`NdnsfCarrier`] over it — to a real
//! `ndn-engine` forwarder/face (feature `engine`).
//!
//! The four-phase driver runs over an `SvsPubSub`, whose transport is a pair of
//! raw `mpsc<Bytes>` channels. Off a real engine those channels are otherwise
//! pumped into a face by hand; [`over_face`] makes that first-class. It mints an
//! app face on `engine`, routes the group prefix and this node's SVS **data**
//! prefix to it, installs the **multicast** strategy on the group (so every
//! member sees each Sync Interest), and shuttles packets between the face and the
//! `SvsPubSub`. The result forwards over the same engine as any other app — so an
//! `NdnsfCarrier` and an `ndn-rpc` `FaceRpcCarrier` can be compared apples-to-
//! apples on one forwarder, instead of the pub/sub running over a private
//! in-memory channel mesh.

use std::sync::Arc;

use bytes::Bytes;
use ndn_app::EngineAppExt;
use ndn_engine::ForwarderEngine;
use ndn_packet::Name;
use ndn_strategy::{ErasedStrategy, MulticastStrategy};
use ndn_sync::{SvSyncConfig, SvsPubSub};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::carrier::NdnsfCarrier;

/// Channel / face buffer depth for the engine binding.
const BIND_BUFFER: usize = 256;

/// Bind a fresh `SvsPubSub` for `node` in `group` to `engine`, ready to hand to
/// [`NdnsfCarrier::new`] (or any four-phase role). A new app face is minted on
/// `engine`; the group prefix (peers' Sync Interests) and this node's SVS data
/// prefix (peers' fetch Interests) are routed to it; the group runs the multicast
/// strategy; and two pumps shuttle packets between the face and the pub/sub until
/// `cancel` fires (or the returned `SvsPubSub` is dropped).
pub async fn over_face(
    engine: &ForwarderEngine,
    node: Name,
    group: Name,
    config: SvSyncConfig,
    cancel: CancellationToken,
) -> SvsPubSub {
    // SVS is a broadcast protocol: every member must see each Sync Interest, so the
    // group prefix forwards on all nexthops but the incoming one (multicast).
    engine
        .strategy_table()
        .insert(&group, Arc::new(MulticastStrategy::new()) as Arc<dyn ErasedStrategy>);

    let (net_out_tx, mut net_out_rx) = mpsc::channel::<Bytes>(BIND_BUFFER);
    let (net_in_tx, net_in_rx) = mpsc::channel::<Bytes>(BIND_BUFFER);
    let ps = SvsPubSub::join(group.clone(), node, net_out_tx, net_in_rx, config);

    // A raw face on the engine; route the group and this node's data prefix to it
    // so the forwarder delivers peers' Sync Interests and fetch Interests here.
    let face = engine.app_face(cancel.child_token());
    let _ = face.register_prefix(&group).await;
    let _ = face.register_prefix(ps.data_prefix()).await;

    // Pump SvsPubSub → face: outbound Sync Interests / Data onto the wire.
    let out_face = Arc::clone(&face);
    tokio::spawn(async move {
        while let Some(pkt) = net_out_rx.recv().await {
            if out_face.send(pkt).await.is_err() {
                break;
            }
        }
    });
    // Pump face → SvsPubSub: inbound packets into the sync loop, until cancelled.
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                pkt = face.recv() => match pkt {
                    Some(p) => {
                        if net_in_tx.send(p).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                },
            }
        }
    });

    ps
}

impl NdnsfCarrier {
    /// Construct a four-phase carrier whose SVS group runs over `engine` (a real
    /// forwarder/face) rather than raw channels — see [`over_face`]. Uses the
    /// default [`SvSyncConfig`]; for an explicit config, build the `SvsPubSub`
    /// with [`over_face`] and pass it to [`new`](Self::new).
    pub async fn over_face(
        engine: &ForwarderEngine,
        node: Name,
        group: Name,
        cancel: CancellationToken,
    ) -> Self {
        let ps = over_face(
            engine,
            node.clone(),
            group.clone(),
            SvSyncConfig::default(),
            cancel,
        )
        .await;
        Self::new(ps, node, group)
    }
}
