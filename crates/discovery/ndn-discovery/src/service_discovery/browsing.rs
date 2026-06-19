//! Browse / body / peer-list Interest handling.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_packet::encode::{DataBuilder, encode_interest};
use ndn_packet::{Data, Name, SignatureType};
use ndn_tlv::TlvWriter;
use ndn_transport::FaceId;
use tokio::sync::oneshot;
use tracing::{debug, trace, warn};

use crate::config::VerifyVerdict;
use crate::context::DiscoveryContext;
use crate::prefix_announce::ServiceRecord;
use crate::scope::{peers_prefix, sd_service_info_under, sd_services_under};
use crate::wire::{parse_raw_data, parse_raw_interest, write_name_tlv};

use super::ServiceDiscoveryProtocol;
use super::records::prefix_hash_hex;

const T_PEER_ENTRY: u64 = 0xE0;

impl ServiceDiscoveryProtocol {
    /// Build a Data signed by the configured [`RecordSigner`]
    /// (default DigestSha256). Replaces the former all-zero stub.
    fn signed_data(&self, name: &Name, content: &[u8], freshness_ms: u64) -> Bytes {
        let (sig_code, key_locator) = self.config.record_signer.signing_info();
        DataBuilder::new(name.clone(), content)
            .freshness(std::time::Duration::from_millis(freshness_ms))
            .sign_sync(
                SignatureType::from_code(sig_code),
                key_locator.as_ref(),
                |region| self.config.record_signer.sign(region).unwrap_or_default(),
            )
    }

    /// Verify an inbound SD Data per the configured verifier. `None`
    /// verifier ⇒ `Untrusted` (fail-closed: stored for browsing, never
    /// auto-FIB). Returns the verified identity when trusted.
    fn verify_data(&self, raw: &Bytes) -> (bool, Option<Name>) {
        match &self.config.record_verifier {
            Some(v) => match Data::decode(raw.clone()) {
                Ok(data) => match v.verify(&data) {
                    VerifyVerdict::Verified { identity } => (true, Some(identity)),
                    _ => (false, None),
                },
                Err(_) => (false, None),
            },
            None => (false, None),
        }
    }
    pub(super) fn handle_sd_interest(
        &self,
        raw: &Bytes,
        incoming_face: FaceId,
        ctx: &dyn DiscoveryContext,
    ) -> bool {
        let parsed = match parse_raw_interest(raw) {
            Some(p) => p,
            None => return false,
        };

        let name = &parsed.name;
        let services = sd_services_under(&self.root);
        let service_info = sd_service_info_under(&self.root);

        if name.has_prefix(&service_info) {
            return self.handle_body_interest(&parsed.name, incoming_face, ctx);
        }

        if !name.has_prefix(&services) {
            return false;
        }

        let records = self.local_records.lock().unwrap();
        let mut responded = false;
        for entry in records.iter() {
            let pkt = entry
                .record
                .build_data_signed(entry.published_at_ms, &*self.config.record_signer);
            ctx.send_on(incoming_face, pkt);
            responded = true;
        }
        if responded {
            debug!(
                "ServiceDiscovery: answered browse Interest with {} records",
                records.len()
            );
        }
        true
    }

    fn handle_body_interest(
        &self,
        interest_name: &Name,
        incoming_face: FaceId,
        ctx: &dyn DiscoveryContext,
    ) -> bool {
        // Map `<root>/service-info/<hash>/<node...>/v=<ts>` to the
        // body_store key `(hash_hex, node_name_string)`. Minimum
        // component count: root + "service-info" + hash + node + version.
        let root_len = self.root.components().len();
        let comps = interest_name.components();
        if comps.len() < root_len + 4 {
            return true;
        }
        let hash_comp = &comps[root_len + 1];
        let hash_hex = String::from_utf8_lossy(&hash_comp.value).into_owned();

        let node_comps = &comps[root_len + 2..comps.len() - 1];
        let mut node_uri = String::new();
        for c in node_comps {
            node_uri.push('/');
            for b in c.value.iter() {
                if b.is_ascii_alphanumeric() || b"-.~_".contains(b) {
                    node_uri.push(*b as char);
                } else {
                    node_uri.push_str(&format!("%{b:02X}"));
                }
            }
        }
        if node_uri.is_empty() {
            node_uri.push('/');
        }

        let key = (hash_hex, node_uri);
        let body = self.body_store.lock().unwrap().get(&key).cloned();
        if let Some(body_bytes) = body {
            let pkt = self.signed_data(interest_name, &body_bytes, 30_000);
            ctx.send_on(incoming_face, pkt);
            debug!("ServiceDiscovery: served body for {:?}", interest_name);
        } else {
            debug!("ServiceDiscovery: no body found for {:?}", interest_name);
        }
        true
    }

    /// Receiver resolves when body Data arrives via `handle_sd_data`.
    pub fn fetch_service_info(
        &self,
        body_name: Name,
        ctx: &dyn DiscoveryContext,
    ) -> oneshot::Receiver<Bytes> {
        let (tx, rx) = oneshot::channel();
        let name_str = body_name.to_string();
        let send_at = std::time::Instant::now();
        {
            let mut pf = self.pending_fetches.lock().unwrap();
            let entry = pf.entry(name_str).or_insert_with(|| (send_at, Vec::new()));
            entry.1.push(tx);
        }

        use ndn_packet::encode::InterestBuilder;
        let interest = InterestBuilder::new(body_name)
            .must_be_fresh()
            .lifetime(std::time::Duration::from_secs(4))
            .build();
        let faces: Vec<FaceId> = ctx
            .neighbors()
            .all()
            .into_iter()
            .filter(|e| e.is_reachable())
            .flat_map(|e| e.faces.iter().map(|(fid, _, _)| *fid).collect::<Vec<_>>())
            .collect();
        for face_id in faces {
            ctx.send_on(face_id, interest.clone());
        }
        rx
    }

    pub(super) fn handle_sd_data(
        &self,
        raw: &Bytes,
        incoming_face: FaceId,
        ctx: &dyn DiscoveryContext,
    ) -> bool {
        let parsed = match parse_raw_data(raw) {
            Some(d) => d,
            None => return false,
        };

        let services = sd_services_under(&self.root);
        let service_info = sd_service_info_under(&self.root);

        if parsed.name.has_prefix(&service_info) {
            // Authenticate the body when a verifier is configured (audit
            // #8); with no verifier, bodies are accepted (browse-only).
            if self.config.record_verifier.is_some() && !self.verify_data(raw).0 {
                warn!(name=%parsed.name, "ServiceDiscovery: dropping unverified body Data");
                return true;
            }
            return self.handle_body_data(&parsed.name, parsed.content.as_deref(), ctx);
        }

        if !parsed.name.has_prefix(&services) {
            return false;
        }

        let content = match parsed.content {
            Some(c) => c,
            None => return true,
        };

        let record = match ServiceRecord::decode(&content) {
            Some(r) => r,
            None => {
                debug!("ServiceDiscovery: could not decode ServiceRecord");
                return true;
            }
        };

        // Authenticate (audit #1). `None` verifier ⇒ not verified ⇒
        // fail-closed: the record is still browseable below, but never
        // auto-installs a FIB route. Scope filtering is the explicit
        // prefix allow-list (the old `is_in_scope` no-op was removed, #6).
        let (verified, identity) = self.verify_data(raw);
        let rate_key = identity.clone().unwrap_or_else(|| record.node_name.clone());

        if !self.config.auto_populate_prefix_filter.is_empty() {
            let allowed = self
                .config
                .auto_populate_prefix_filter
                .iter()
                .any(|f| record.announced_prefix.has_prefix(f));
            if !allowed {
                return true;
            }
        }

        if !self.check_rate_limit(&rate_key, ctx.now()) {
            debug!("ServiceDiscovery: rate-limiting {:?}", rate_key);
            return true;
        }

        {
            let mut peer_recs = self.peer_records.lock().unwrap();
            if let Some(idx) = peer_recs.iter().position(|r| {
                r.announced_prefix == record.announced_prefix && r.node_name == record.node_name
            }) {
                // Anti-rollback (audit #4): reject a record that isn't
                // strictly newer than the one we hold (skip when the held
                // record is unversioned/legacy).
                if peer_recs[idx].version != 0 && record.version <= peer_recs[idx].version {
                    debug!(
                        "ServiceDiscovery: dropping stale record v{} <= v{} for {:?}",
                        record.version, peer_recs[idx].version, record.announced_prefix
                    );
                    return true;
                }
                peer_recs[idx] = record.clone();
            } else {
                // Cap the table (audit #5): FIFO-evict the oldest entry.
                let cap = self.config.max_records_per_scope.max(1);
                while peer_recs.len() >= cap {
                    peer_recs.remove(0);
                }
                peer_recs.push(record.clone());
            }
        }

        if self.config.auto_populate_fib && verified {
            self.auto_populate_fib(&record, incoming_face, ctx);
        }

        if self.config.relay_records {
            let relay_faces: Vec<FaceId> = ctx
                .neighbors()
                .all()
                .into_iter()
                .filter(|e| e.is_reachable())
                .flat_map(|e| e.faces.iter().map(|(fid, _, _)| *fid).collect::<Vec<_>>())
                .filter(|fid| *fid != incoming_face)
                .collect();
            let relay_count = relay_faces.len();
            for face_id in relay_faces {
                ctx.send_on(face_id, raw.clone());
            }
            if relay_count > 0 {
                debug!(
                    "ServiceDiscovery: relayed record {:?} to {relay_count} peers",
                    record.announced_prefix
                );
            }
        }

        true
    }

    pub(super) fn handle_peers_interest(
        &self,
        raw: &Bytes,
        incoming_face: FaceId,
        ctx: &dyn DiscoveryContext,
    ) -> bool {
        let parsed = match parse_raw_interest(raw) {
            Some(p) => p,
            None => return false,
        };

        if !parsed.name.has_prefix(peers_prefix()) {
            return false;
        }

        let peers_depth = peers_prefix().components().len();
        let extra_comps = parsed.name.components().len().saturating_sub(peers_depth);

        let peer_list = if extra_comps > 0 {
            // Single-peer query: `/ndn/local/nd/peers/<node-name>`.
            let comps = parsed.name.components();
            let node_name_comps = &comps[peers_depth..];
            let mut uri = String::new();
            for comp in node_name_comps {
                uri.push('/');
                for byte in comp.value.iter() {
                    if byte.is_ascii_alphanumeric() || b"-.~_".contains(byte) {
                        uri.push(*byte as char);
                    } else {
                        uri.push_str(&format!("%{byte:02X}"));
                    }
                }
            }
            if uri.is_empty() {
                uri.push('/');
            }
            let target = match std::str::FromStr::from_str(&uri) {
                Ok(n) => n,
                Err(_) => return true,
            };
            let entry = ctx.neighbors().get(&target);
            let mut w = TlvWriter::new();
            if let Some(e) = entry
                && e.is_reachable()
            {
                w.write_nested(T_PEER_ENTRY, |w: &mut TlvWriter| {
                    write_name_tlv(w, &e.node_name);
                });
            }
            let content = w.finish();
            debug!(
                "ServiceDiscovery: answered single-peer query for {:?}",
                target
            );
            content
        } else {
            // Full peer list: `/ndn/local/nd/peers`.
            let neighbors = ctx.neighbors().all();
            let mut w = TlvWriter::new();
            for entry in &neighbors {
                if entry.is_reachable() {
                    w.write_nested(T_PEER_ENTRY, |w: &mut TlvWriter| {
                        write_name_tlv(w, &entry.node_name);
                    });
                }
            }
            debug!(
                "ServiceDiscovery: answered peers query with {} neighbors",
                neighbors.len()
            );
            w.finish()
        };

        // 1s freshness — the peer list changes frequently.
        let pkt = self.signed_data(&parsed.name, &peer_list, 1000);
        ctx.send_on(incoming_face, pkt);
        true
    }

    fn handle_body_data(
        &self,
        data_name: &Name,
        content: Option<&[u8]>,
        ctx: &dyn DiscoveryContext,
    ) -> bool {
        let name_str = data_name.to_string();
        let recv_at = ctx.now();
        let (send_at, senders) = self
            .pending_fetches
            .lock()
            .unwrap()
            .remove(&name_str)
            .unwrap_or_else(|| (recv_at, Vec::new()));
        let rtt = recv_at.saturating_duration_since(send_at);

        if let Some(body_raw) = content {
            // Look up the rendezvous record by deriving its key from the
            // body Data name components.
            let root_len = self.root.components().len();
            let comps = data_name.components();
            let record_opt: Option<ServiceRecord> = if comps.len() >= root_len + 4 {
                let hash_comp = &comps[root_len + 1];
                let hash_hex = String::from_utf8_lossy(&hash_comp.value).into_owned();
                let node_comps = &comps[root_len + 2..comps.len() - 1];
                let mut node_uri = String::new();
                for c in node_comps {
                    node_uri.push('/');
                    for b in c.value.iter() {
                        if b.is_ascii_alphanumeric() || b"-.~_".contains(b) {
                            node_uri.push(*b as char);
                        } else {
                            node_uri.push_str(&format!("%{b:02X}"));
                        }
                    }
                }
                if node_uri.is_empty() {
                    node_uri.push('/');
                }
                self.peer_records
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|r| {
                        prefix_hash_hex(&r.announced_prefix) == hash_hex
                            && r.node_name.to_string() == node_uri
                    })
                    .cloned()
            } else {
                None
            };

            let body_bytes = match record_opt.as_ref() {
                Some(rec) => match self.config.encryption_hook.unwrap(body_raw, rec) {
                    Ok(b) => b,
                    Err(e) => {
                        warn!(error=%e, name=%name_str, "body decryption failed, dropping");
                        if let Some(rec) = record_opt {
                            let k = (prefix_hash_hex(&rec.announced_prefix), rec.node_name.to_string());
                            self.has_body_map.lock().unwrap().insert(k, false);
                        }
                        return true;
                    }
                },
                None => bytes::Bytes::copy_from_slice(body_raw),
            };

            if let Some(rec) = record_opt.as_ref() {
                let k = (prefix_hash_hex(&rec.announced_prefix), rec.node_name.to_string());
                self.has_body_map.lock().unwrap().insert(k, true);
                self.measurements.lock().unwrap().record_rtt(
                    &rec.announced_prefix,
                    &rec.node_name,
                    rtt,
                    recv_at,
                );
            }

            debug!(name=%name_str, "ServiceDiscovery: received body Data, resolving {} waiter(s)", senders.len());
            for tx in senders {
                let _ = tx.send(body_bytes.clone());
            }
        } else {
            // Empty body Data — record a timeout for the matching
            // provider if we can recover it from the name components.
            debug!(name=%name_str, "ServiceDiscovery: received empty body Data");
            let root_len = self.root.components().len();
            let comps = data_name.components();
            if comps.len() >= root_len + 4 {
                let hash_hex = String::from_utf8_lossy(&comps[root_len + 1].value).into_owned();
                let node_comps = &comps[root_len + 2..comps.len() - 1];
                let mut node_uri = String::new();
                for c in node_comps {
                    node_uri.push('/');
                    for b in c.value.iter() {
                        if b.is_ascii_alphanumeric() || b"-.~_".contains(b) {
                            node_uri.push(*b as char);
                        } else {
                            node_uri.push_str(&format!("%{b:02X}"));
                        }
                    }
                }
                if node_uri.is_empty() {
                    node_uri.push('/');
                }
                if let Some(rec) = self
                    .peer_records
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|r| {
                        prefix_hash_hex(&r.announced_prefix) == hash_hex
                            && r.node_name.to_string() == node_uri
                    })
                    .cloned()
                {
                    self.has_body_map.lock().unwrap().insert(
                        (prefix_hash_hex(&rec.announced_prefix), rec.node_name.to_string()),
                        false,
                    );
                    self.measurements.lock().unwrap().record_timeout(
                        &rec.announced_prefix,
                        &rec.node_name,
                        recv_at,
                    );
                }
            }
        }
        true
    }

    pub(super) fn send_browse_interest(&self, face_id: FaceId, ctx: &dyn DiscoveryContext) {
        let services = sd_services_under(&self.root);
        let interest = encode_interest(&services, None);
        ctx.send_on(face_id, interest);
        trace!(face = ?face_id, "ServiceDiscovery: sent browse Interest");
    }

    pub(super) fn browse_neighbors(
        &self,
        now: Instant,
        browse_interval: Duration,
        ctx: &dyn DiscoveryContext,
    ) {
        let neighbors = ctx.neighbors().all();
        let mut seen = self.browsed_neighbors.lock().unwrap();
        let periodic_due = self
            .last_browse
            .lock()
            .unwrap()
            .is_none_or(|t| now.duration_since(t) >= browse_interval);

        let mut new_count = 0usize;
        let mut refresh_count = 0usize;

        for entry in &neighbors {
            if !entry.is_reachable() {
                continue;
            }
            let is_new = seen.insert(entry.node_name.clone());
            if is_new {
                for (face_id, _, _) in &entry.faces {
                    self.send_browse_interest(*face_id, ctx);
                }
                new_count += 1;
            } else if periodic_due {
                for (face_id, _, _) in &entry.faces {
                    self.send_browse_interest(*face_id, ctx);
                }
                refresh_count += 1;
            }
        }

        if periodic_due {
            *self.last_browse.lock().unwrap() = Some(now);
        }
        if new_count > 0 {
            debug!(
                peers = new_count,
                "ServiceDiscovery: initial browse sent to new neighbors"
            );
        }
        if refresh_count > 0 {
            debug!(
                peers = refresh_count,
                "ServiceDiscovery: periodic browse refresh sent"
            );
        }

        let active: HashSet<Name> = neighbors
            .iter()
            .filter(|e| e.is_reachable())
            .map(|e| e.node_name.clone())
            .collect();
        seen.retain(|n| active.contains(n));
    }
}

pub fn decode_peer_list(content: &[u8]) -> Vec<Name> {
    let mut peers = Vec::new();
    let mut pos = 0;
    while pos < content.len() {
        let Some((typ, len, hl)) = read_tlv_header(content, pos) else {
            break;
        };
        let val = &content[pos + hl..pos + hl + len];
        if typ == T_PEER_ENTRY as u32
            && let Some(name) = decode_name_tlv(val)
        {
            peers.push(name);
        }
        pos += hl + len;
    }
    peers
}

fn read_tlv_header(b: &[u8], pos: usize) -> Option<(u32, usize, usize)> {
    if pos >= b.len() {
        return None;
    }
    let (typ, t_len) = read_varnumber(b, pos)?;
    let (len, l_len) = read_varnumber(b, pos + t_len)?;
    Some((typ as u32, len as usize, t_len + l_len))
}

fn read_varnumber(b: &[u8], pos: usize) -> Option<(u64, usize)> {
    let first = *b.get(pos)?;
    match first {
        0xFD => {
            let hi = *b.get(pos + 1)? as u64;
            let lo = *b.get(pos + 2)? as u64;
            Some(((hi << 8) | lo, 3))
        }
        0xFE => {
            let v = u32::from_be_bytes(b[pos + 1..pos + 5].try_into().ok()?);
            Some((v as u64, 5))
        }
        0xFF => {
            let v = u64::from_be_bytes(b[pos + 1..pos + 9].try_into().ok()?);
            Some((v, 9))
        }
        _ => Some((first as u64, 1)),
    }
}

fn decode_name_tlv(b: &[u8]) -> Option<Name> {
    if b.is_empty() || b[0] != 0x07 {
        return None;
    }
    use ndn_packet::NameComponent;
    let (_, len, hl) = read_tlv_header(b, 0)?;
    let comps_bytes = &b[hl..hl + len];
    let mut comps = Vec::new();
    let mut pos = 0;
    while pos < comps_bytes.len() {
        let (typ, clen, chl) = read_tlv_header(comps_bytes, pos)?;
        let val = comps_bytes[pos + chl..pos + chl + clen].to_vec();
        comps.push(NameComponent {
            typ: typ as u64,
            value: val.into(),
        });
        pos += chl + clen;
    }
    if comps.is_empty() {
        return Some(Name::root());
    }
    let mut uri = String::new();
    for comp in &comps {
        uri.push('/');
        for byte in comp.value.iter() {
            if byte.is_ascii_alphanumeric() || b"-.~_".contains(byte) {
                uri.push(*byte as char);
            } else {
                uri.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    if uri.is_empty() {
        uri.push('/');
    }
    use std::str::FromStr;
    Name::from_str(&uri).ok()
}
