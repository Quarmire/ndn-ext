use std::path::Path;

use anyhow::Result;
use smallvec::{SmallVec, smallvec};
use tracing::warn;

use ndn_engine::pipeline::{ForwardingAction, NackReason};
use ndn_packet::Name;
use ndn_strategy::StrategyContext;

use ndn_engine::stages::ErasedStrategy;

use crate::host::{HostState, add_host_functions};

/// Forwarding strategy loaded from a WASM module exporting `on_interest`
/// (and optionally `on_nack`). Each invocation runs in a fresh `Store`
/// with a fuel limit; trap or exhaustion yields `Suppress`.
pub struct WasmStrategy {
    name: Name,
    engine: wasmtime::Engine,
    module: wasmtime::Module,
    linker: wasmtime::Linker<HostState>,
    fuel: u64,
}

impl WasmStrategy {
    pub fn from_file(name: Name, path: impl AsRef<Path>, fuel: u64) -> Result<Self> {
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true);
        let engine = wasmtime::Engine::new(&config)?;
        let module = wasmtime::Module::from_file(&engine, path)?;
        let mut linker = wasmtime::Linker::new(&engine);
        add_host_functions(&mut linker)?;
        Ok(Self {
            name,
            engine,
            module,
            linker,
            fuel,
        })
    }

    pub fn from_bytes(name: Name, wasm: &[u8], fuel: u64) -> Result<Self> {
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true);
        let engine = wasmtime::Engine::new(&config)?;
        let module = wasmtime::Module::new(&engine, wasm)?;
        let mut linker = wasmtime::Linker::new(&engine);
        add_host_functions(&mut linker)?;
        Ok(Self {
            name,
            engine,
            module,
            linker,
            fuel,
        })
    }

    fn run_wasm(&self, ctx: &StrategyContext<'_>, entry: &str) -> SmallVec<[ForwardingAction; 2]> {
        let state = HostState::from_context(ctx);
        let mut store = wasmtime::Store::new(&self.engine, state);
        if store.set_fuel(self.fuel).is_err() {
            warn!(strategy=%self.name, "failed to set fuel");
            return smallvec![ForwardingAction::Suppress];
        }

        let instance = match self.linker.instantiate(&mut store, &self.module) {
            Ok(i) => i,
            Err(e) => {
                warn!(strategy=%self.name, error=%e, "WASM instantiation failed");
                return smallvec![ForwardingAction::Suppress];
            }
        };

        let func = match instance.get_typed_func::<(), ()>(&mut store, entry) {
            Ok(f) => f,
            Err(e) => {
                warn!(strategy=%self.name, entry, error=%e, "WASM export not found");
                return smallvec![ForwardingAction::Suppress];
            }
        };

        match func.call(&mut store, ()) {
            Ok(()) => store.into_data().take_actions(),
            Err(e) => {
                warn!(strategy=%self.name, entry, error=%e, "WASM execution failed");
                smallvec![ForwardingAction::Suppress]
            }
        }
    }
}

impl ErasedStrategy for WasmStrategy {
    fn name(&self) -> &Name {
        &self.name
    }

    fn decide_sync(&self, ctx: &StrategyContext<'_>) -> Option<SmallVec<[ForwardingAction; 2]>> {
        Some(self.run_wasm(ctx, "on_interest"))
    }

    fn after_receive_interest_erased(
        &self,
        ctx: &StrategyContext<'_>,
    ) -> SmallVec<[ForwardingAction; 2]> {
        self.run_wasm(ctx, "on_interest")
    }

    fn on_nack_erased(&self, ctx: &StrategyContext<'_>, _reason: NackReason) -> ForwardingAction {
        self.run_wasm(ctx, "on_nack")
            .into_iter()
            .next()
            .unwrap_or(ForwardingAction::Suppress)
    }
}
