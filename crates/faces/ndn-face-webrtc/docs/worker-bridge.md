# WebRTC ↔ SharedWorker tab-side bridge

`RTCPeerConnection` is not exposed in `WorkerGlobalScope` (W3C —
the WebRTC API is window-scoped on every shipping browser).  A
`SharedWorker` therefore cannot own a `WebRtcFace` directly.

The practical pattern is a **bridge tab** that owns the WebRTC
peer connection in window scope and proxies bytes into the
per-origin SharedWorker via the existing `SharedWorkerProxyFace`.
From the worker's perspective, the bridge tab is just another
`WorkerPortFace` — the engine's FIB / strategy / pipeline route
to it like any other face, and the bridge tab takes care of
moving bytes onto the wire.

```text
   peer browser                bridge tab                     SharedWorker
   ────────────                ──────────                     ────────────
   RTCPeerConnection  ──────▶  WebRtcFace                     WorkerPortFace
   (window context)             │  ↑                          │  ↑
                                │  │                          │  │
                                └──┘  Face-trait byte pump    └──┘
                                       (this crate's helper)
                                                              ┌─────────────┐
                                                              │ engine      │
                                                              │ pipeline,   │
                                                              │ FIB, CS …   │
                                                              └─────────────┘
```

## Bridge body

A handful of lines, both directions, no special framing — the
NDNLPv2 packets on either face are opaque bytes:

```rust,ignore
use std::sync::Arc;
use ndn_face_webrtc::WebRtcFace;
use ndn_face_shared_worker::SharedWorkerProxyFace;
use ndn_transport::Face;

#[wasm_bindgen]
pub async fn bridge_main(rtc_signal_url: String, worker_url: String) -> Result<(), JsValue> {
    let runtime = ndn_runtime::default_runtime();

    // 1. Dial the peer (signaling URL → completed RTCDataChannel).
    let rtc: Arc<WebRtcFace> = Arc::new(
        WebRtcFace::dial(FaceId(1), &rtc_signal_url, Arc::clone(&runtime))
            .await
            .map_err(|e| JsValue::from_str(&format!("rtc: {e}")))?,
    );

    // 2. Connect to the per-origin SharedWorker (any name; the bridge
    //    just needs a Face into the engine).
    let sw: Arc<SharedWorkerProxyFace> = Arc::new(
        SharedWorkerProxyFace::connect(FaceId(2), &worker_url, None, Arc::clone(&runtime))
            .map_err(|e| JsValue::from_str(&format!("worker: {e}")))?,
    );

    // 3. Pump bytes both directions.  Either drop terminates the bridge.
    let r = Arc::clone(&rtc);
    let s = Arc::clone(&sw);
    runtime.spawn(Box::pin(async move {
        while let Ok(buf) = Face::recv(&*r).await {
            if Face::send(&*s, buf).await.is_err() {
                break;
            }
        }
    }));
    while let Ok(buf) = Face::recv(&*sw).await {
        if Face::send(&*rtc, buf).await.is_err() {
            break;
        }
    }
    Ok(())
}
```

## Why the engine doesn't see two faces

The bridge tab doesn't run an `EngineInner` — it's just a pump.
The worker sees exactly one new `WorkerPortFace` (face #N) when
the bridge tab connects.  When the engine forwards an Interest
out face #N, the bridge tab receives it via `Face::recv` on
`SharedWorkerProxyFace` and sends it via `Face::send` on
`WebRtcFace`.  The peer's reply travels the reverse path.

## What the worker sees

A standard inbound face.  No new code in the worker's face graph.
The bridge tab can also register prefixes via management
(`/localhost/nfd/rib/register` Interest → mgmt mounts it against
the bridge's `WorkerPortFace`), so the worker can route to the
bridged peer by name.

## Why a `WebRtcFace` *inside* the worker would be redundant

Even if the W3C spec extended `RTCPeerConnection` to
`SharedWorkerGlobalScope` tomorrow, the bridge pattern would
still be the cleanest separation: the tab handles user
permission prompts (camera/mic prompts are window-scoped on
some browsers), the worker holds the long-lived NDN state.
Optimising the byte path through the worker isn't load-bearing
for the typical browser-NDN use case.
