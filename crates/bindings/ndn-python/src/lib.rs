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

#[pymodule]
fn ndn_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Data>()?;
    m.add_class::<Consumer>()?;
    m.add_class::<Producer>()?;
    Ok(())
}
