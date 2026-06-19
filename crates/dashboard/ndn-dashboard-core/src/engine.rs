//! `DashboardEngine` — the headless poll/command core.
//!
//! Holds a [`ManagementClient`] and a [`DashboardState`], polls a forwarder's
//! read datasets, and reports which views changed. UI-framework-free: the
//! Dioxus dashboard copies `DashboardState` into Signals, a native UI reads it
//! over FFI. This is the read/poll half of the generic-send-cmd unification;
//! command dispatch is the next slice.
//!
//! The mapping from wire datasets (`ndn_config::nfd_dataset`,
//! `ndn_mgmt_wire`) to the dashboard's view models lives here, so every UI
//! shares one parse layer instead of duplicating the closures `app.rs` /
//! `app_web.rs` grew independently.

use crate::mgmt::{ManagementClient, MgmtResponse};
use crate::types::{
    AnchorInfo, CsInfo, FaceInfo, FibEntry, ForwarderStatus, SecurityKeyInfo, StrategyEntry,
};
use ndn_config::{ControlParameters, nfd_dataset};
use ndn_packet::Name;

/// Headless snapshot of a forwarder's forwarding-plane state. Plain data owned
/// by the engine and mutated under `&mut self`; a UI reads snapshots from it.
#[derive(Debug, Default, Clone)]
pub struct DashboardState {
    pub status: Option<ForwarderStatus>,
    pub faces: Vec<FaceInfo>,
    pub routes: Vec<FibEntry>,
    pub cs: Option<CsInfo>,
    pub strategies: Vec<StrategyEntry>,
}

/// Which view a poll refreshed, so a UI re-renders only what changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateUpdate {
    Status,
    Faces,
    Routes,
    Cs,
    Strategies,
    Approvals,
    Identities,
    Anchors,
}

/// Headless snapshot of a forwarder's identity/trust plane — polled separately
/// from the forwarding plane (it's an operator-opens-the-view axis, not a
/// hot-path refresh): the CA pending-approval queue plus the trust posture
/// (local identities/keys and the configured trust anchors).
#[derive(Debug, Clone, Default)]
pub struct IdentityState {
    /// Device-approval requests awaiting an operator decision
    /// (`/localhost/nfd/ca/list-approvals`).
    pub approvals: Vec<ndn_mgmt_wire::PendingApproval>,
    /// Local identity keys and their certificate expiry
    /// (`/localhost/nfd/security/identity-list`).
    pub identities: Vec<SecurityKeyInfo>,
    /// Configured trust anchors and which store each lives in
    /// (`/localhost/nfd/security/anchor-list`).
    pub anchors: Vec<AnchorInfo>,
}

/// Drives a forwarder over any [`ManagementClient`] transport (web WebSocket,
/// desktop Unix socket, mobile IPC face).
pub struct DashboardEngine<M: ManagementClient> {
    client: M,
    state: DashboardState,
    identity: IdentityState,
}

impl<M: ManagementClient> DashboardEngine<M> {
    pub fn new(client: M) -> Self {
        Self {
            client,
            state: DashboardState::default(),
            identity: IdentityState::default(),
        }
    }

    /// The current state snapshot.
    pub fn state(&self) -> &DashboardState {
        &self.state
    }

    /// The current identity/trust-plane snapshot.
    pub fn identity_state(&self) -> &IdentityState {
        &self.identity
    }

    /// The underlying client — e.g. for command dispatch by a UI adapter.
    pub fn client_mut(&mut self) -> &mut M {
        &mut self.client
    }

    /// Shared access to the underlying client, for transport-specific reads a
    /// UI still drives directly (datasets the engine doesn't model yet).
    pub fn client(&self) -> &M {
        &self.client
    }

    /// Poll the forwarding-plane read datasets once. Updates `state` in place
    /// and returns which views changed. Each block is best-effort: a forwarder
    /// missing a verb (older / cross-impl) degrades to "no data" without
    /// failing the whole poll.
    pub async fn poll_forwarding(&mut self) -> Vec<StateUpdate> {
        let mut changed = Vec::new();

        if let Ok(resp) = self.client.send_cmd("status", "general", None).await
            && let Ok(gs) = ndn_mgmt_wire::GeneralStatus::decode(resp.body.clone())
        {
            self.state.status = Some(ForwarderStatus::from_general(&gs));
            changed.push(StateUpdate::Status);
        }

        if let Ok(resp) = self.client.send_cmd("faces", "list", None).await
            && resp.is_ok()
        {
            self.state.faces = nfd_dataset::FaceStatus::decode_all(&resp.body)
                .into_iter()
                .map(FaceInfo::from)
                .collect();
            changed.push(StateUpdate::Faces);
        }

        if let Ok(resp) = self.client.send_cmd("fib", "list", None).await
            && resp.is_ok()
        {
            self.state.routes = nfd_dataset::FibEntry::decode_all(&resp.body)
                .into_iter()
                .map(FibEntry::from)
                .collect();
            changed.push(StateUpdate::Routes);
        }

        if let Ok(resp) = self.client.send_cmd("cs", "info", None).await
            && resp.is_ok()
        {
            self.state.cs = CsInfo::parse(&resp.status_text);
            changed.push(StateUpdate::Cs);
        }

        if let Ok(resp) = self.client.send_cmd("strategy-choice", "list", None).await
            && resp.is_ok()
        {
            self.state.strategies = nfd_dataset::StrategyChoice::decode_all(&resp.body)
                .into_iter()
                .map(StrategyEntry::from)
                .collect();
            changed.push(StateUpdate::Strategies);
        }

        changed
    }

    // ── command dispatch (forwarding plane) ─────────────────────────────
    //
    // Typed builders construct the `ControlParameters` for a verb and send it,
    // so a UI calls `engine.route_register(prefix, face, cost)` instead of
    // hand-rolling parameters — the logic the Dioxus `run_cmd` arms duplicated
    // now lives once, reusable from a native UI. UI-side effects (audit
    // journaling, error toasts, re-poll) stay in the caller. Security / schema
    // / CA verbs (which carry audit side-effects) are a follow-up slice; the
    // generic `command` escape hatch covers them in the meantime.

    /// Generic command escape hatch — send any `/localhost/nfd/<module>/<verb>`
    /// with optional parameters.
    pub async fn command(
        &mut self,
        module: &str,
        verb: &str,
        params: Option<&ControlParameters>,
    ) -> Result<MgmtResponse, String> {
        self.client.send_cmd(module, verb, params).await
    }

    pub async fn face_create(&mut self, uri: String) -> Result<MgmtResponse, String> {
        let params = ControlParameters {
            uri: Some(uri),
            ..Default::default()
        };
        self.client.send_cmd("faces", "create", Some(&params)).await
    }

    pub async fn face_destroy(&mut self, face_id: u64) -> Result<MgmtResponse, String> {
        let params = ControlParameters {
            face_id: Some(face_id),
            ..Default::default()
        };
        self.client.send_cmd("faces", "destroy", Some(&params)).await
    }

    pub async fn route_register(
        &mut self,
        prefix: &str,
        face_id: u64,
        cost: u64,
    ) -> Result<MgmtResponse, String> {
        let name = parse_name(prefix, "prefix")?;
        let params = ControlParameters {
            name: Some(name),
            // face_id == 0 means "use the requesting face" — leave it unset so
            // the forwarder resolves it from the PIT.
            face_id: (face_id != 0).then_some(face_id),
            cost: Some(cost),
            ..Default::default()
        };
        self.client.send_cmd("rib", "register", Some(&params)).await
    }

    pub async fn route_unregister(
        &mut self,
        prefix: &str,
        face_id: u64,
    ) -> Result<MgmtResponse, String> {
        let name = parse_name(prefix, "prefix")?;
        let params = ControlParameters {
            name: Some(name),
            face_id: (face_id != 0).then_some(face_id),
            ..Default::default()
        };
        self.client.send_cmd("rib", "unregister", Some(&params)).await
    }

    pub async fn strategy_set(
        &mut self,
        prefix: &str,
        strategy: &str,
    ) -> Result<MgmtResponse, String> {
        let name = parse_name(prefix, "prefix")?;
        let strategy_name = parse_name(strategy, "strategy")?;
        let params = ControlParameters {
            name: Some(name),
            strategy: Some(strategy_name),
            ..Default::default()
        };
        self.client
            .send_cmd("strategy-choice", "set", Some(&params))
            .await
    }

    pub async fn strategy_unset(&mut self, prefix: &str) -> Result<MgmtResponse, String> {
        let name = parse_name(prefix, "prefix")?;
        let params = ControlParameters {
            name: Some(name),
            ..Default::default()
        };
        self.client
            .send_cmd("strategy-choice", "unset", Some(&params))
            .await
    }

    pub async fn cs_capacity(&mut self, capacity: u64) -> Result<MgmtResponse, String> {
        let params = ControlParameters {
            capacity: Some(capacity),
            ..Default::default()
        };
        self.client.send_cmd("cs", "config", Some(&params)).await
    }

    pub async fn cs_erase(&mut self, prefix: &str) -> Result<MgmtResponse, String> {
        let name = parse_name(prefix, "prefix")?;
        let params = ControlParameters {
            name: Some(name),
            ..Default::default()
        };
        self.client.send_cmd("cs", "erase", Some(&params)).await
    }

    pub async fn shutdown(&mut self) -> Result<MgmtResponse, String> {
        self.client.send_cmd("status", "shutdown", None).await
    }

    // ── identity / trust plane ──────────────────────────────────────────
    //
    // Polled and mutated separately from the forwarding plane. The
    // pending-approval queue decodes through the shared `ndn_mgmt_wire`
    // codec; approve/deny are signed commands (the forwarder gates them —
    // the signer's identity authorises the decision).

    /// Refresh the identity/trust plane: the CA pending-approval queue, the
    /// local identity keys, and the configured trust anchors. Each dataset is
    /// independent — a failed query leaves that axis's prior value in place.
    /// Returns the `StateUpdate`s that changed. The `security/*` datasets are
    /// ndn-rs extensions; a cross-impl forwarder (NFD/YaNFD) 404s them and they
    /// simply don't refresh.
    pub async fn poll_identity(&mut self) -> Vec<StateUpdate> {
        let mut changed = Vec::new();
        if let Ok(resp) = self.client.send_cmd("ca", "list-approvals", None).await
            && resp.is_ok()
        {
            self.identity.approvals = ndn_mgmt_wire::PendingApproval::decode_all(&resp.body);
            changed.push(StateUpdate::Approvals);
        }
        if let Ok(resp) = self.client.send_cmd("security", "identity-list", None).await
            && resp.is_ok()
        {
            self.identity.identities = SecurityKeyInfo::parse_list(&resp.status_text);
            changed.push(StateUpdate::Identities);
        }
        if let Ok(resp) = self.client.send_cmd("security", "anchor-list", None).await
            && resp.is_ok()
        {
            self.identity.anchors = AnchorInfo::parse_list(&resp.status_text);
            changed.push(StateUpdate::Anchors);
        }
        changed
    }

    /// Remove a trust anchor by its certificate key name — stops the forwarder
    /// trusting it (local trust withdrawal, not a network revocation). Signed
    /// command.
    pub async fn anchor_remove(&mut self, key_name: &str) -> Result<MgmtResponse, String> {
        let name = parse_name(key_name, "key_name")?;
        let params = ControlParameters {
            name: Some(name),
            ..Default::default()
        };
        self.client
            .send_cmd("security", "anchor-remove", Some(&params))
            .await
    }

    /// Add a trust anchor from a certificate's wire bytes. `key_name` must
    /// equal the certificate's own name — the forwarder cross-checks and
    /// rejects a mismatch. Signed command.
    pub async fn anchor_add(
        &mut self,
        key_name: &str,
        cert_wire: &[u8],
    ) -> Result<MgmtResponse, String> {
        let name = parse_name(key_name, "key_name")?;
        let params = ControlParameters {
            name: Some(name),
            uri: Some(to_hex(cert_wire)),
            ..Default::default()
        };
        self.client
            .send_cmd("security", "anchor-add", Some(&params))
            .await
    }

    /// Import an ndn-cxx-compatible SafeBag (encrypted private key + cert) into
    /// the PIB, making it a usable signing identity. `key_name` is the key the
    /// bag carries; `passphrase` decrypts the wrapped PKCS#8. Both blobs are
    /// hex-encoded into the `<safebag>:<passphrase>` parameter the forwarder
    /// expects. Signed command. The passphrase never appears in a log line.
    pub async fn safebag_import(
        &mut self,
        key_name: &str,
        safebag_wire: &[u8],
        passphrase: &[u8],
    ) -> Result<MgmtResponse, String> {
        let name = parse_name(key_name, "key_name")?;
        let uri = format!("{}:{}", to_hex(safebag_wire), to_hex(passphrase));
        let params = ControlParameters {
            name: Some(name),
            uri: Some(uri),
            ..Default::default()
        };
        self.client
            .send_cmd("security", "safebag-import", Some(&params))
            .await
    }

    /// Approve a pending device-approval request by id. Signed command.
    pub async fn ca_approve(&mut self, request_id: &str) -> Result<MgmtResponse, String> {
        let params = ControlParameters {
            uri: Some(request_id.to_owned()),
            ..Default::default()
        };
        self.client.send_cmd("ca", "approve", Some(&params)).await
    }

    /// Deny a pending request by id. An empty `reason` records the default
    /// denial detail. Signed command. The id/reason are joined as
    /// `id:reason` to match the forwarder's `ca/deny` parameter shape.
    pub async fn ca_deny(&mut self, request_id: &str, reason: &str) -> Result<MgmtResponse, String> {
        let uri = if reason.is_empty() {
            request_id.to_owned()
        } else {
            format!("{request_id}:{reason}")
        };
        let params = ControlParameters {
            uri: Some(uri),
            ..Default::default()
        };
        self.client.send_cmd("ca", "deny", Some(&params)).await
    }
}

/// Parse an NDN name argument, turning a parse failure into a UI-displayable
/// error (`what` names the field, e.g. "prefix" / "strategy").
fn parse_name(s: &str, what: &str) -> Result<Name, String> {
    s.parse::<Name>()
        .map_err(|e| format!("invalid {what} '{s}': {e:?}"))
}

/// Lowercase hex, matching the `{:02x}` convention the management wire uses for
/// byte-blob parameters (cert wire, SafeBag, passphrase).
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mgmt::MgmtResponse;
    use async_trait::async_trait;
    use bytes::Bytes;
    use ndn_config::ControlParameters;

    /// Canned forwarder: a real `GeneralStatus` wire for `status/general`,
    /// empty (but `is_ok`) datasets for the lists — exercises the engine's
    /// poll choreography + parse layer without a live socket.
    struct MockClient {
        general: Bytes,
    }

    #[async_trait(?Send)]
    impl ManagementClient for MockClient {
        async fn send_cmd(
            &mut self,
            module: &str,
            verb: &str,
            _params: Option<&ControlParameters>,
        ) -> Result<MgmtResponse, String> {
            let ok = |body: Bytes| {
                Ok(MgmtResponse {
                    status_code: 200,
                    status_text: "OK".to_string(),
                    body,
                })
            };
            match (module, verb) {
                ("status", "general") => ok(self.general.clone()),
                ("faces", "list") | ("fib", "list") | ("strategy-choice", "list") => {
                    ok(Bytes::new())
                }
                ("cs", "info") => ok(Bytes::new()),
                other => Err(format!("unexpected verb: {other:?}")),
            }
        }
    }

    /// Records every command so a builder's `(module, verb, params)` can be
    /// asserted without a live forwarder.
    #[derive(Default)]
    struct RecordingClient {
        calls: Vec<(String, String, Option<ControlParameters>)>,
    }

    #[async_trait(?Send)]
    impl ManagementClient for RecordingClient {
        async fn send_cmd(
            &mut self,
            module: &str,
            verb: &str,
            params: Option<&ControlParameters>,
        ) -> Result<MgmtResponse, String> {
            self.calls
                .push((module.to_string(), verb.to_string(), params.cloned()));
            Ok(MgmtResponse {
                status_code: 200,
                status_text: "OK".to_string(),
                body: Bytes::new(),
            })
        }
    }

    #[tokio::test]
    async fn command_builders_construct_expected_params() {
        let mut engine = DashboardEngine::new(RecordingClient::default());

        engine.route_register("/demo/app", 5, 100).await.unwrap();
        engine.strategy_set("/demo", "/strat/bmf").await.unwrap();
        engine.face_destroy(7).await.unwrap();

        let calls = &engine.client_mut().calls;
        assert_eq!(calls.len(), 3);

        let (m, v, p) = &calls[0];
        assert_eq!((m.as_str(), v.as_str()), ("rib", "register"));
        let p = p.as_ref().unwrap();
        assert_eq!(p.name.as_ref().unwrap().to_string(), "/demo/app");
        assert_eq!(p.face_id, Some(5));
        assert_eq!(p.cost, Some(100));

        let (m, v, p) = &calls[1];
        assert_eq!((m.as_str(), v.as_str()), ("strategy-choice", "set"));
        let p = p.as_ref().unwrap();
        assert_eq!(p.strategy.as_ref().unwrap().to_string(), "/strat/bmf");

        let (m, v, p) = &calls[2];
        assert_eq!((m.as_str(), v.as_str()), ("faces", "destroy"));
        assert_eq!(p.as_ref().unwrap().face_id, Some(7));
    }

    /// face_id == 0 is "the requesting face" — must be left unset, not sent.
    #[tokio::test]
    async fn route_register_omits_zero_face_id() {
        let mut engine = DashboardEngine::new(RecordingClient::default());
        engine.route_register("/x", 0, 0).await.unwrap();
        let (_, _, p) = &engine.client_mut().calls[0];
        assert_eq!(p.as_ref().unwrap().face_id, None);
    }

    #[tokio::test]
    async fn poll_forwarding_parses_status_and_reports_changes() {
        let gs = ndn_mgmt_wire::GeneralStatus {
            nfd_version: "test-fwd".to_string(),
            n_pit_entries: 7,
            n_fib_entries: 3,
            ..Default::default()
        };
        let mut engine = DashboardEngine::new(MockClient {
            general: gs.encode(),
        });

        let updates = engine.poll_forwarding().await;

        // Every read block ran and reported a change.
        assert!(updates.contains(&StateUpdate::Status));
        assert!(updates.contains(&StateUpdate::Faces));
        assert!(updates.contains(&StateUpdate::Routes));
        assert!(updates.contains(&StateUpdate::Strategies));

        // The status dataset parsed into the view model.
        let st = engine.state();
        let status = st.status.as_ref().expect("status parsed");
        assert_eq!(status.nfd_version, "test-fwd");
        assert_eq!(status.n_pit, 7);
        assert_eq!(status.n_fib, 3);

        // Empty datasets parse to empty collections, not errors.
        assert!(st.faces.is_empty());
        assert!(st.routes.is_empty());
        assert!(st.strategies.is_empty());
    }

    #[tokio::test]
    async fn poll_identity_populates_all_three_axes() {
        // Canned identity plane: an approval queue (TLV body) plus the two
        // text-line security datasets the trust posture parses.
        struct IdMock(Bytes);
        #[async_trait(?Send)]
        impl ManagementClient for IdMock {
            async fn send_cmd(
                &mut self,
                module: &str,
                verb: &str,
                _params: Option<&ControlParameters>,
            ) -> Result<MgmtResponse, String> {
                let ok_text = |t: &str| {
                    Ok(MgmtResponse {
                        status_code: 200,
                        status_text: t.to_string(),
                        body: Bytes::new(),
                    })
                };
                match (module, verb) {
                    ("ca", "list-approvals") => Ok(MgmtResponse {
                        status_code: 200,
                        status_text: "OK".to_string(),
                        body: self.0.clone(),
                    }),
                    ("security", "identity-list") => {
                        ok_text("name=/lab/alice has_cert=true valid_until=never")
                    }
                    ("security", "anchor-list") => {
                        ok_text("name=/lab/router-ca/KEY/k0 source=mgmt")
                    }
                    other => Err(format!("unexpected verb: {other:?}")),
                }
            }
        }

        let wire = ndn_mgmt_wire::PendingApproval::encode_all(&[ndn_mgmt_wire::PendingApproval {
            request_id: "req-1".into(),
            cert_name: "/lab/alice/devices/laptop".into(),
            description: "laptop".into(),
        }]);
        let mut engine = DashboardEngine::new(IdMock(wire));

        let changed = engine.poll_identity().await;
        assert_eq!(
            changed,
            vec![
                StateUpdate::Approvals,
                StateUpdate::Identities,
                StateUpdate::Anchors
            ]
        );

        let id = engine.identity_state();
        assert_eq!(id.approvals.len(), 1);
        assert_eq!(id.approvals[0].request_id, "req-1");
        assert_eq!(id.identities.len(), 1);
        assert_eq!(id.identities[0].name, "/lab/alice");
        assert!(id.identities[0].has_cert);
        assert_eq!(id.anchors.len(), 1);
        assert_eq!(id.anchors[0].name, "/lab/router-ca/KEY/k0");
        assert_eq!(id.anchors[0].source.as_deref(), Some("mgmt"));
    }

    #[tokio::test]
    async fn ca_and_anchor_commands_build_expected_params() {
        let mut engine = DashboardEngine::new(RecordingClient::default());
        engine.ca_approve("req-1").await.unwrap();
        engine.ca_deny("req-2", "expired").await.unwrap();
        engine.ca_deny("req-3", "").await.unwrap();
        engine.anchor_remove("/lab/router-ca/KEY/k0").await.unwrap();

        let calls = &engine.client().calls;
        assert_eq!(calls[0].0, "ca");
        assert_eq!(calls[0].1, "approve");
        assert_eq!(calls[0].2.as_ref().unwrap().uri.as_deref(), Some("req-1"));

        // Reason is appended as `id:reason`…
        assert_eq!(calls[1].1, "deny");
        assert_eq!(
            calls[1].2.as_ref().unwrap().uri.as_deref(),
            Some("req-2:expired")
        );
        // …and an empty reason sends the bare id.
        assert_eq!(calls[2].2.as_ref().unwrap().uri.as_deref(), Some("req-3"));

        // anchor-remove carries the key name, not a uri.
        assert_eq!((calls[3].0.as_str(), calls[3].1.as_str()), ("security", "anchor-remove"));
        assert_eq!(
            calls[3].2.as_ref().unwrap().name.as_ref().map(|n| n.to_string()),
            Some("/lab/router-ca/KEY/k0".to_string())
        );
    }

    #[tokio::test]
    async fn anchor_add_and_safebag_import_hex_encode_blobs() {
        let mut engine = DashboardEngine::new(RecordingClient::default());
        engine
            .anchor_add("/lab/ca/KEY/k0", &[0xde, 0xad, 0xbe, 0xef])
            .await
            .unwrap();
        engine
            .safebag_import("/lab/me/KEY/k1", &[0x01, 0x02], b"pw")
            .await
            .unwrap();

        let calls = &engine.client().calls;

        // anchor-add: name = cert key name, uri = cert wire as lowercase hex.
        assert_eq!((calls[0].0.as_str(), calls[0].1.as_str()), ("security", "anchor-add"));
        let p0 = calls[0].2.as_ref().unwrap();
        assert_eq!(p0.name.as_ref().map(|n| n.to_string()), Some("/lab/ca/KEY/k0".into()));
        assert_eq!(p0.uri.as_deref(), Some("deadbeef"));

        // safebag-import: uri = `<safebag_hex>:<passphrase_hex>` ("pw" = 70 77).
        assert_eq!(calls[1].1, "safebag-import");
        assert_eq!(calls[1].2.as_ref().unwrap().uri.as_deref(), Some("0102:7077"));
    }
}
