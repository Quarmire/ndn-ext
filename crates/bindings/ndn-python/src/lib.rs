//! Python bindings exposing blocking `Consumer` / `Producer` classes backed
//! by `ndn-app`'s internal Tokio runtime; no `asyncio` required.
//!
//! Build with `maturin develop` (editable) or `maturin build --release`.
//!
//! ```python
//! from ndn_rs import Consumer, Producer
//! Consumer("/run/nfd/nfd.sock").get("/ndn/sensor/temperature")
//! ```

// PyO3 #[pymethods] macro emits unsafe-internal calls and PyErr `.into()`
// shims that trip these lints — false positives from the macro expansion.
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(clippy::useless_conversion)]

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

use ndn_app::AppError;
use ndn_app::blocking::{BlockingConsumer, BlockingProducer};

fn py_err(e: AppError) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

/// NDN Data packet (`name`, `content`) returned by :class:`Consumer`.
#[pyclass]
struct Data {
    name: String,
    content: Vec<u8>,
}

#[pymethods]
impl Data {
    #[getter]
    fn name(&self) -> &str {
        &self.name
    }

    #[getter]
    fn content(&self) -> &[u8] {
        &self.content
    }

    fn __repr__(&self) -> String {
        format!(
            "Data(name={:?}, content_len={})",
            self.name,
            self.content.len()
        )
    }
}

impl Data {
    fn from_packet(data: ndn_packet::Data) -> Self {
        Self {
            name: data.name.to_string(),
            content: data.content().map(|b| b.to_vec()).unwrap_or_default(),
        }
    }
}

/// Blocking NDN consumer over an `ndn-fwd` Unix socket. Holds the GIL for
/// up to the Interest lifetime (default 4.5 s); use `asyncio.to_thread` or
/// one consumer per thread for concurrency.
#[pyclass]
struct Consumer {
    inner: BlockingConsumer,
}

#[pymethods]
impl Consumer {
    #[new]
    fn new(socket: &str) -> PyResult<Self> {
        BlockingConsumer::connect(socket)
            .map(|inner| Self { inner })
            .map_err(py_err)
    }

    /// Fetch content bytes for `name`; raises `RuntimeError` on timeout/Nack.
    fn get(&mut self, name: &str) -> PyResult<Vec<u8>> {
        self.inner.get(name).map(|b| b.to_vec()).map_err(py_err)
    }

    /// Like :meth:`get` but returns a full :class:`Data` object (name + content).
    fn fetch(&mut self, name: &str) -> PyResult<Data> {
        self.inner
            .fetch(name)
            .map(Data::from_packet)
            .map_err(py_err)
    }
}

/// Blocking NDN producer; registers `prefix` and dispatches Interests to a
/// Python callback.
#[pyclass]
struct Producer {
    inner: BlockingProducer,
}

#[pymethods]
impl Producer {
    #[new]
    fn new(socket: &str, prefix: &str) -> PyResult<Self> {
        BlockingProducer::connect(socket, prefix)
            .map(|inner| Self { inner })
            .map_err(py_err)
    }

    /// Blocks running `handler(name: str) -> bytes | None` for each Interest;
    /// returning `None` drops the Interest silently. The GIL is released
    /// while waiting and re-acquired only inside `handler`.
    fn serve(&mut self, py: Python<'_>, handler: PyObject) -> PyResult<()> {
        // `Arc<Mutex<_>>` adds `Send + Sync` to satisfy `BlockingProducer::serve`.
        let handler = Arc::new(Mutex::new(handler));

        py.allow_threads(|| {
            self.inner.serve(move |interest| {
                let name_str = interest.name.to_string();
                let h = Arc::clone(&handler);

                Python::with_gil(|py| -> Option<Bytes> {
                    let locked = h.lock().ok()?;
                    let result = locked.bind(py).call1((name_str,)).ok()?;
                    if result.is_none() {
                        return None;
                    }
                    let raw: Vec<u8> = result.extract().ok()?;
                    Some(Bytes::from(raw))
                })
            })
        })
        .map_err(py_err)
    }
}

// --- Service-layer scripting front-end (§11 mode 3) ---
//
// The dynamic counterpart to the typed `#[ndn_service]` macro: a Python developer
// registers `bytes -> bytes` handlers by op name (the untyped `ScriptDispatch`
// seam) and calls ops by name. Carriers and op-dispatch carry over from Rust; the
// compile-time typing does not (Python is dynamic). A `ServiceNode` shares one
// Tier-0 carrier between a provider and a client in-process — real cross-process
// networking awaits the face-backed carrier (the registry here is in-process).

use std::collections::HashMap;

use ndn_packet::Name;
use ndn_rpc::{RpcCarrier, RpcRegistry};
use ndn_service_core::{Carrier, OpId, ScriptDispatch, ScriptHandler, ServiceError, ServiceId};
use pyo3::exceptions::PyValueError;
use pyo3::types::PyBytes;

fn parse_service(service: &str) -> PyResult<Name> {
    service
        .parse::<Name>()
        .map_err(|_| PyValueError::new_err(format!("invalid service name: {service}")))
}

fn svc_err(e: ServiceError) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

/// A node sharing one Tier-0 carrier between its providers and clients. Build it,
/// then vend a :class:`ServiceProvider` and/or :class:`ServiceClient`.
#[pyclass]
struct ServiceNode {
    registry: Arc<RpcRegistry>,
    rt: Arc<tokio::runtime::Runtime>,
}

#[pymethods]
impl ServiceNode {
    #[new]
    fn new() -> PyResult<Self> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(Self {
            registry: Arc::new(RpcRegistry::new()),
            rt: Arc::new(rt),
        })
    }

    /// A provider for `service` (register handlers, then :meth:`ServiceProvider.serve`).
    fn provider(&self, service: &str) -> PyResult<ServiceProvider> {
        Ok(ServiceProvider {
            registry: Arc::clone(&self.registry),
            rt: Arc::clone(&self.rt),
            service: parse_service(service)?,
            handlers: HashMap::new(),
        })
    }

    /// A client for `service` (call ops by name).
    fn client(&self, service: &str) -> PyResult<ServiceClient> {
        Ok(ServiceClient {
            registry: Arc::clone(&self.registry),
            rt: Arc::clone(&self.rt),
            service: parse_service(service)?,
        })
    }
}

/// Serves a set of `bytes -> bytes` op handlers for one service.
#[pyclass]
struct ServiceProvider {
    registry: Arc<RpcRegistry>,
    rt: Arc<tokio::runtime::Runtime>,
    service: Name,
    handlers: HashMap<String, Py<PyAny>>,
}

#[pymethods]
impl ServiceProvider {
    /// Register `func(req: bytes) -> bytes` as the handler for operation `op`.
    fn handler(&mut self, op: &str, func: Py<PyAny>) {
        self.handlers.insert(op.to_string(), func);
    }

    /// Mount the registered handlers on the shared carrier. (In-process; returns
    /// once mounted — a face-backed carrier would run a serve loop instead.)
    fn serve(&self, py: Python<'_>) -> PyResult<()> {
        let mut dispatch = ScriptDispatch::new();
        for (op, func) in &self.handlers {
            let func = func.clone_ref(py);
            let handler: ScriptHandler = Arc::new(move |req: Bytes| {
                Python::with_gil(|py| {
                    let arg = PyBytes::new_bound(py, &req);
                    let result = func
                        .bind(py)
                        .call1((arg,))
                        .map_err(|e| ServiceError::Handler(e.to_string()))?;
                    let out: Vec<u8> = result
                        .extract()
                        .map_err(|e| ServiceError::Decode(e.to_string()))?;
                    Ok(Bytes::from(out))
                })
            });
            dispatch.on(op.clone(), handler);
        }

        let svc = ServiceId::new(self.service.clone());
        let registry = Arc::clone(&self.registry);
        let rt = Arc::clone(&self.rt);
        py.allow_threads(|| {
            let carrier = RpcCarrier::with_registry(registry);
            rt.block_on(carrier.serve(&svc, Arc::new(dispatch)))
        })
        .map_err(svc_err)
    }
}

/// Invokes service operations by name (`bytes -> bytes`).
#[pyclass]
struct ServiceClient {
    registry: Arc<RpcRegistry>,
    rt: Arc<tokio::runtime::Runtime>,
    service: Name,
}

#[pymethods]
impl ServiceClient {
    /// Call operation `op` with `request` bytes; returns the response bytes.
    /// Raises `RuntimeError` if the op is unknown or the handler failed.
    fn call(&self, py: Python<'_>, op: &str, request: &[u8]) -> PyResult<Vec<u8>> {
        let svc = ServiceId::new(self.service.clone());
        let op = OpId::new(op);
        let req = Bytes::copy_from_slice(request);
        let registry = Arc::clone(&self.registry);
        let rt = Arc::clone(&self.rt);
        let response = py
            .allow_threads(|| {
                let carrier = RpcCarrier::with_registry(registry);
                rt.block_on(carrier.invoke(&svc, &op, req))
            })
            .map_err(svc_err)?;
        Ok(response.payload.to_vec())
    }
}

#[pymodule]
fn ndn_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Data>()?;
    m.add_class::<Consumer>()?;
    m.add_class::<Producer>()?;
    m.add_class::<ServiceNode>()?;
    m.add_class::<ServiceProvider>()?;
    m.add_class::<ServiceClient>()?;
    Ok(())
}
