//! `/localhost/nfd/pipes/list` — a read-only PIPES introspection module
//! (ndn-rs extension, not an NFD-canonical module), mirroring the shape of
//! `compute/list`: an NFD-compatible [`MgmtModule`] whose `list` verb returns a
//! text dataset of the producer's live pipes and their remaining PUIs.
//!
//! The module carries its own state — a [`PipeRegistry`] handle shared with the
//! [`PipeProducer`](crate::PipeProducer)'s serve loop — and ignores the engine
//! [`MgmtContext`], so it can be registered into any [`MgmtRouter`].

use async_trait::async_trait;
use ndn_config::{ControlParameters, ControlResponse, control_response::status, nfd_command::verb};
use ndn_mgmt::module::{MgmtContext, MgmtModule};
use ndn_mgmt::MgmtResponse;

use crate::registry::{PipeInfo, PipeRegistry};

/// The `pipes` management module over a producer's live-pipe [`PipeRegistry`].
pub struct PipesModule {
    registry: PipeRegistry,
}

impl PipesModule {
    /// Build the module from a producer's [`registry`](crate::PipeProducer::registry).
    pub fn new(registry: PipeRegistry) -> Self {
        Self { registry }
    }
}

/// Render the `list` dataset: a count header followed by one indented row per
/// live pipe (id + remaining PUI), matching the other read-only modules' shape.
pub fn render_list(rows: &[PipeInfo]) -> String {
    let mut text = format!("{} pipes\n", rows.len());
    for r in rows {
        text.push_str(&format!("  {}  pui_remaining={}ms\n", r.id_hex, r.remaining_ms));
    }
    text
}

#[async_trait]
impl MgmtModule for PipesModule {
    fn name(&self) -> &'static [u8] {
        b"pipes"
    }

    async fn dispatch(
        &self,
        verb: &[u8],
        _params: ControlParameters,
        _ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        match verb {
            v if v == verb::LIST => {
                ControlResponse::ok_empty(render_list(&self.registry.list())).into()
            }
            _ => ControlResponse::error(status::NOT_FOUND, "unknown pipes verb").into(),
        }
    }
}
