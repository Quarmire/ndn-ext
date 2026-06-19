use smallvec::SmallVec;

use ndn_engine::pipeline::ForwardingAction;
use ndn_strategy::{FibNexthop, StrategyContext};
use ndn_transport::FaceId;

/// Per-invocation host state passed to the WASM guest. Host reads come from
/// imported functions (`get_in_face`, `get_nexthop`, …) and host writes are
/// pushed into `actions` by `forward`/`nack`/`suppress`.
///
/// WASM ABI uses `u32` face ids; the host truncates from the engine's `u64`
/// `FaceId`. The monotonic id space takes ~71 min at 1 M faces/sec to
/// overflow `u32::MAX`; widen the ABI if a deployment can outlast that.
pub(crate) struct HostState {
    pub in_face: u32,
    pub nexthops: Vec<FibNexthop>,
    pub actions: SmallVec<[ForwardingAction; 2]>,
    pub rtt_ns: Vec<(u32, f64)>,
    pub rssi: Vec<(u32, i32)>,
    pub satisfaction: Vec<(u32, f32)>,
}

impl HostState {
    pub fn from_context(ctx: &StrategyContext<'_>) -> Self {
        let nexthops = ctx
            .fib_entry
            .map(|e| e.nexthops.clone())
            .unwrap_or_default();

        let mut rtt_ns = Vec::new();
        let mut rssi = Vec::new();
        let satisfaction = Vec::new();

        // Cross-layer link signals for the in-face and each candidate nexthop,
        // read from the SignalView (pushed by signal sources).
        let faces = std::iter::once(ctx.in_face).chain(nexthops.iter().map(|n| n.face_id));
        for face in faces {
            if let Some(link) = ctx.signals.link(face) {
                if let Some(r) = link.rssi_dbm {
                    rssi.push((face.0 as u32, r as i32));
                }
                if let Some(rtt) = link.observed_rtt_ms {
                    rtt_ns.push((face.0 as u32, f64::from(rtt) * 1_000_000.0));
                }
            }
        }

        Self {
            in_face: ctx.in_face.0 as u32,
            nexthops,
            actions: SmallVec::new(),
            rtt_ns,
            rssi,
            satisfaction,
        }
    }

    pub fn take_actions(self) -> SmallVec<[ForwardingAction; 2]> {
        self.actions
    }
}

/// Register the `ndn::*` import surface available to WASM strategies.
pub(crate) fn add_host_functions(linker: &mut wasmtime::Linker<HostState>) -> anyhow::Result<()> {
    linker.func_wrap(
        "ndn",
        "get_in_face",
        |caller: wasmtime::Caller<'_, HostState>| -> u32 { caller.data().in_face },
    )?;

    linker.func_wrap(
        "ndn",
        "get_nexthop_count",
        |caller: wasmtime::Caller<'_, HostState>| -> u32 { caller.data().nexthops.len() as u32 },
    )?;

    // `get_nexthop(index, out_face_ptr, out_cost_ptr) -> u32` —
    // returns 0 on success, 1 on out-of-bounds or bad pointer.
    linker.func_wrap(
        "ndn",
        "get_nexthop",
        |mut caller: wasmtime::Caller<'_, HostState>,
         index: u32,
         out_face: u32,
         out_cost: u32|
         -> u32 {
            let nh = match caller.data().nexthops.get(index as usize) {
                Some(nh) => *nh,
                None => return 1,
            };
            let mem = match caller.get_export("memory") {
                Some(wasmtime::Extern::Memory(m)) => m,
                _ => return 1,
            };
            let data = mem.data_mut(&mut caller);
            // Truncating cast — see `HostState` doc on `u32` face ABI.
            let face_bytes = (nh.face_id.0 as u32).to_le_bytes();
            let cost_bytes = nh.cost.to_le_bytes();
            let f = out_face as usize;
            let c = out_cost as usize;
            if f + 4 > data.len() || c + 4 > data.len() {
                return 1;
            }
            data[f..f + 4].copy_from_slice(&face_bytes);
            data[c..c + 4].copy_from_slice(&cost_bytes);
            0
        },
    )?;

    // `get_rtt_ns(face_id) -> f64`; -1.0 when unknown.
    linker.func_wrap(
        "ndn",
        "get_rtt_ns",
        |caller: wasmtime::Caller<'_, HostState>, face_id: u32| -> f64 {
            caller
                .data()
                .rtt_ns
                .iter()
                .find(|(fid, _)| *fid == face_id)
                .map_or(-1.0, |(_, rtt)| *rtt)
        },
    )?;

    // `get_rssi(face_id) -> i32` dBm; -128 when unknown.
    linker.func_wrap(
        "ndn",
        "get_rssi",
        |caller: wasmtime::Caller<'_, HostState>, face_id: u32| -> i32 {
            caller
                .data()
                .rssi
                .iter()
                .find(|(fid, _)| *fid == face_id)
                .map_or(-128, |(_, rssi)| *rssi)
        },
    )?;

    // `get_satisfaction(face_id) -> f32` in `0.0..=1.0`; -1.0 when unknown.
    linker.func_wrap(
        "ndn",
        "get_satisfaction",
        |caller: wasmtime::Caller<'_, HostState>, face_id: u32| -> f32 {
            caller
                .data()
                .satisfaction
                .iter()
                .find(|(fid, _)| *fid == face_id)
                .map_or(-1.0, |(_, sat)| *sat)
        },
    )?;

    // `forward(face_ids_ptr, count)` — reads `count` u32 face IDs from guest memory.
    linker.func_wrap(
        "ndn",
        "forward",
        |mut caller: wasmtime::Caller<'_, HostState>, ptr: u32, count: u32| {
            let mem = match caller.get_export("memory") {
                Some(wasmtime::Extern::Memory(m)) => m,
                _ => return,
            };
            let data = mem.data(&caller);
            let start = ptr as usize;
            let end = start + (count as usize) * 4;
            if end > data.len() {
                return;
            }

            let mut faces = SmallVec::<[FaceId; 4]>::new();
            for i in 0..count as usize {
                let offset = start + i * 4;
                let fid = u32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);
                faces.push(FaceId(fid as u64));
            }
            caller
                .data_mut()
                .actions
                .push(ForwardingAction::Forward(faces));
        },
    )?;

    linker.func_wrap(
        "ndn",
        "nack",
        |mut caller: wasmtime::Caller<'_, HostState>, reason: u32| {
            let nr = match reason {
                0 => ndn_engine::pipeline::NackReason::NoRoute,
                1 => ndn_engine::pipeline::NackReason::Duplicate,
                2 => ndn_engine::pipeline::NackReason::Congestion,
                3 => ndn_engine::pipeline::NackReason::NotYet,
                _ => ndn_engine::pipeline::NackReason::NoRoute,
            };
            caller.data_mut().actions.push(ForwardingAction::Nack(nr));
        },
    )?;

    linker.func_wrap(
        "ndn",
        "suppress",
        |mut caller: wasmtime::Caller<'_, HostState>| {
            caller.data_mut().actions.push(ForwardingAction::Suppress);
        },
    )?;

    Ok(())
}
