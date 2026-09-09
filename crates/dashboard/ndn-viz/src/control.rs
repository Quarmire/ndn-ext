//! Control-surface ingest: the generic `/localhost/nfd/ext/list` model plus the
//! typed projections the operator views render.
//!
//! `ndn-fwd` serves every registered `ControlSurface` through one dataset,
//! `/localhost/nfd/ext/list`, as a `ControlResponse` whose `status_text` is a
//! flat INI-ish document:
//!
//! ```text
//! [named-radio]
//! subsystem=named-radio-cognition
//! strategy=rule-calibrated
//! readonly=true
//! stat.strategy=rule-calibrated
//! stat.managed_objects=1
//! stat.radio.0.channel=36
//! stat.radio.0.mcs=7
//! ```
//!
//! The consumer decodes the `ControlResponse` (that needs `ndn-mgmt-wire`, which
//! this crate deliberately avoids) and hands the `status_text` here. Everything
//! below is pure text → model, so it stays wasm-clean and dependency-free.
//!
//! **One ingest, many views.** [`parse_ext_list`] yields the generic
//! [`ControlSurfaces`]; the typed projections ([`RadioCognition`],
//! [`HardwareInventory`], [`Monitors`]) read whichever subsystem/objects they
//! care about. New subsystems (time, coding, …) need no parser change — only a
//! new projection.

use std::collections::BTreeMap;

/// Every control subsystem the forwarder advertises, from one `ext/list` read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ControlSurfaces {
    pub subsystems: Vec<Subsystem>,
}

impl ControlSurfaces {
    /// The subsystem with this `[name]`, if present.
    pub fn subsystem(&self, name: &str) -> Option<&Subsystem> {
        self.subsystems.iter().find(|s| s.name == name)
    }
}

/// One `[name]` section: free-form `key=value` info, flat `stat.*` counters, and
/// per-object `stat.<kind>.<id>.<field>` groups.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Subsystem {
    pub name: String,
    /// Non-`stat.` lines (e.g. `subsystem=`, `strategy=`, `actuation=`, `readonly=`).
    pub info: BTreeMap<String, String>,
    /// Flat `stat.<field>` counters (the `stat.` prefix stripped), excluding the
    /// per-object ones which land in [`Subsystem::objects`].
    pub stats: BTreeMap<String, String>,
    /// Per-object stats, keyed `"<kind>/<id>"` (e.g. `"radio/0"`).
    pub objects: BTreeMap<String, ObjectStats>,
}

impl Subsystem {
    pub fn stat(&self, key: &str) -> Option<&str> {
        self.stats.get(key).map(String::as_str)
    }

    pub fn info_of(&self, key: &str) -> Option<&str> {
        self.info.get(key).map(String::as_str)
    }

    /// All objects of a given `kind` (e.g. `"radio"`), ordered by id.
    pub fn objects_of(&self, kind: &str) -> Vec<&ObjectStats> {
        self.objects.values().filter(|o| o.kind == kind).collect()
    }
}

/// One managed object's fields (e.g. radio 0's decided plan + health).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObjectStats {
    pub kind: String,
    pub id: String,
    pub fields: BTreeMap<String, String>,
}

impl ObjectStats {
    pub fn field(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }
}

/// Parse a `ControlResponse.status_text` into the generic surface model.
///
/// Per-object convention: a `stat.` key with **three or more** dotted parts is an
/// object stat — `stat.<kind>.<id>.<field...>`. One or two parts is a flat stat.
pub fn parse_ext_list(text: &str) -> ControlSurfaces {
    let mut out = ControlSurfaces::default();
    let mut current: Option<Subsystem> = None;

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            if let Some(done) = current.take() {
                out.subsystems.push(done);
            }
            current = Some(Subsystem {
                name: name.to_string(),
                ..Default::default()
            });
            continue;
        }
        let Some(sub) = current.as_mut() else {
            continue; // stray line before any [section]
        };
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());

        let Some(rest) = key.strip_prefix("stat.") else {
            sub.info.insert(key.to_string(), value.to_string());
            continue;
        };
        let parts: Vec<&str> = rest.split('.').collect();
        if parts.len() >= 3 {
            let kind = parts[0].to_string();
            let id = parts[1].to_string();
            let field = parts[2..].join(".");
            let obj = sub
                .objects
                .entry(format!("{kind}/{id}"))
                .or_insert_with(|| ObjectStats {
                    kind: kind.clone(),
                    id: id.clone(),
                    ..Default::default()
                });
            obj.fields.insert(field, value.to_string());
        } else {
            sub.stats.insert(rest.to_string(), value.to_string());
        }
    }
    if let Some(done) = current.take() {
        out.subsystems.push(done);
    }
    out
}

// ─────────────────────────── typed projections ───────────────────────────

/// The named-radio subsystem name in `ext/list`.
pub const RADIO_SUBSYSTEM: &str = "named-radio";

/// One radio's DECIDED plan — read-only observation of what cognition actuated.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RadioRow {
    pub id: String,
    pub channel: String,
    pub mcs: String,
    pub nss: String,
    pub bw: String,
    pub he: String,
    pub tx_power: String,
    pub link_fec: String,
    /// Whether this node's policy claims the shared medium without deferring
    /// (EDCCA ignore). Empty when the producer does not emit it.
    pub edcca_ignore: String,
    /// EDCCA defer threshold in dBm, `"l2h/h2l"` (e.g. `"-72/-62"`), `"-"` when
    /// not set, empty when the producer does not emit it.
    pub defer_threshold_dbm: String,
    pub suppress: String,
    pub relay: String,
    pub objective: String,
}

/// Aggregate + per-radio cognition snapshot (the "Cognition" view model).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RadioCognition {
    /// Whether a `[named-radio]` subsystem was present at all.
    pub present: bool,
    pub strategy: String,
    pub managed_objects: String,
    pub suppressed: String,
    pub objective: String,
    /// Actuator-side contention ledger (what actually reached silicon),
    /// cumulative since boot. Empty when the producer does not emit it.
    pub contention_edcca_ignored: String,
    pub contention_defer_threshold_clamped: String,
    pub contention_fec_parity_over_generation: String,
    pub radios: Vec<RadioRow>,
}

impl RadioCognition {
    /// Project the `[named-radio]` subsystem out of a parsed surface set.
    pub fn from_surfaces(surfaces: &ControlSurfaces) -> Self {
        let Some(sub) = surfaces.subsystem(RADIO_SUBSYSTEM) else {
            return Self::default();
        };
        let mut radios: Vec<RadioRow> = sub
            .objects_of("radio")
            .into_iter()
            .map(|o| RadioRow {
                id: o.id.clone(),
                channel: o.field("channel").unwrap_or_default().to_string(),
                mcs: o.field("mcs").unwrap_or_default().to_string(),
                nss: o.field("nss").unwrap_or_default().to_string(),
                bw: o.field("bw").unwrap_or_default().to_string(),
                he: o.field("he").unwrap_or_default().to_string(),
                tx_power: o.field("tx_power").unwrap_or_default().to_string(),
                link_fec: o.field("link_fec").unwrap_or_default().to_string(),
                edcca_ignore: o.field("edcca_ignore").unwrap_or_default().to_string(),
                defer_threshold_dbm: o
                    .field("defer_threshold_dbm")
                    .unwrap_or_default()
                    .to_string(),
                suppress: o.field("suppress").unwrap_or_default().to_string(),
                relay: o.field("relay").unwrap_or_default().to_string(),
                objective: o.field("objective").unwrap_or_default().to_string(),
            })
            .collect();
        radios.sort_by(|a, b| a.id.cmp(&b.id));
        Self {
            present: true,
            strategy: sub.stat("strategy").unwrap_or_default().to_string(),
            managed_objects: sub.stat("managed_objects").unwrap_or_default().to_string(),
            suppressed: sub.stat("suppressed").unwrap_or_default().to_string(),
            objective: sub.stat("objective").unwrap_or_default().to_string(),
            contention_edcca_ignored: sub
                .stat("contention.edcca_ignored")
                .unwrap_or_default()
                .to_string(),
            contention_defer_threshold_clamped: sub
                .stat("contention.defer_threshold_clamped")
                .unwrap_or_default()
                .to_string(),
            contention_fec_parity_over_generation: sub
                .stat("contention.fec_parity_over_generation")
                .unwrap_or_default()
                .to_string(),
            radios,
        }
    }

    /// Convenience: parse `ext/list` text straight into the cognition view.
    pub fn parse(status_text: &str) -> Self {
        Self::from_surfaces(&parse_ext_list(status_text))
    }
}

/// The physical substrate behind one radio — device identity, capability, and
/// live PHY health. Every field is `Option` because the surface reports what it
/// can; a field is `None` until the forwarder-side surface advertises that key.
/// This is the *ground truth cognition acts on*, distinct from [`RadioRow`]'s
/// *decisions*.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RadioDevice {
    pub id: String,
    // identity / addressing
    pub chip: Option<String>,
    pub driver: Option<String>,
    pub address: Option<String>,
    // capability
    pub band: Option<String>,
    pub max_mcs: Option<String>,
    pub rx_chains: Option<String>,
    pub dbm_max: Option<String>,
    pub he_cap: Option<String>,
    pub duty_max: Option<String>,
    pub rx_only: Option<String>,
    pub tsf: Option<String>,
    // live PHY health
    pub link: Option<String>,
    pub rssi_dbm: Option<String>,
    pub occupancy_pct: Option<String>,
    pub tx_frames: Option<String>,
    pub rx_frames: Option<String>,
    pub brownout: Option<String>,
}

impl RadioDevice {
    /// True once any substrate field is reported (so the view can say "not yet
    /// advertised" rather than showing an empty shell).
    pub fn has_substrate(&self) -> bool {
        [
            &self.chip,
            &self.driver,
            &self.address,
            &self.band,
            &self.max_mcs,
            &self.rx_chains,
            &self.dbm_max,
            &self.he_cap,
            &self.duty_max,
            &self.rx_only,
            &self.tsf,
            &self.link,
            &self.rssi_dbm,
            &self.occupancy_pct,
            &self.tx_frames,
            &self.rx_frames,
            &self.brownout,
        ]
        .iter()
        .any(|f| f.is_some())
    }
}

/// The hardware substrate for all radios, projected from `[named-radio]` objects.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HardwareInventory {
    pub radios: Vec<RadioDevice>,
}

impl HardwareInventory {
    pub fn from_surfaces(surfaces: &ControlSurfaces) -> Self {
        let Some(sub) = surfaces.subsystem(RADIO_SUBSYSTEM) else {
            return Self::default();
        };
        let field = |o: &ObjectStats, k: &str| o.field(k).map(str::to_string);
        let mut radios: Vec<RadioDevice> = sub
            .objects_of("radio")
            .into_iter()
            .map(|o| RadioDevice {
                id: o.id.clone(),
                chip: field(o, "chip"),
                driver: field(o, "driver"),
                address: field(o, "address"),
                band: field(o, "band"),
                max_mcs: field(o, "max_mcs"),
                rx_chains: field(o, "rx_chains"),
                dbm_max: field(o, "dbm_max"),
                he_cap: field(o, "he_cap"),
                duty_max: field(o, "duty_max"),
                rx_only: field(o, "rx_only"),
                tsf: field(o, "tsf"),
                link: field(o, "link"),
                rssi_dbm: field(o, "rssi_dbm"),
                occupancy_pct: field(o, "occupancy_pct"),
                tx_frames: field(o, "tx_frames"),
                rx_frames: field(o, "rx_frames"),
                brownout: field(o, "brownout"),
            })
            .collect();
        radios.sort_by(|a, b| a.id.cmp(&b.id));
        Self { radios }
    }

    pub fn parse(status_text: &str) -> Self {
        Self::from_surfaces(&parse_ext_list(status_text))
    }

    /// Whether any radio has reported substrate detail yet.
    pub fn any_substrate(&self) -> bool {
        self.radios.iter().any(RadioDevice::has_substrate)
    }
}

/// The monitors subsystem name in `ext/list`.
pub const MONITORS_SUBSYSTEM: &str = "monitors";

/// One long-running watcher (soak run, uptime/health watchdog, link-quality
/// probe, threshold alert) as reported by a `[monitors]` control surface.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Monitor {
    pub id: String,
    pub kind: String,
    pub status: String,
    pub detail: String,
    pub duration_s: String,
    pub ok: String,
    pub fail: String,
}

/// All monitors, projected from the `[monitors]` subsystem's `monitor` objects.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Monitors {
    pub present: bool,
    pub monitors: Vec<Monitor>,
}

impl Monitors {
    pub fn from_surfaces(surfaces: &ControlSurfaces) -> Self {
        let Some(sub) = surfaces.subsystem(MONITORS_SUBSYSTEM) else {
            return Self::default();
        };
        let mut monitors: Vec<Monitor> = sub
            .objects_of("monitor")
            .into_iter()
            .map(|o| Monitor {
                id: o.id.clone(),
                kind: o.field("kind").unwrap_or_default().to_string(),
                status: o.field("status").unwrap_or_default().to_string(),
                detail: o.field("detail").unwrap_or_default().to_string(),
                duration_s: o.field("duration_s").unwrap_or_default().to_string(),
                ok: o.field("ok").unwrap_or_default().to_string(),
                fail: o.field("fail").unwrap_or_default().to_string(),
            })
            .collect();
        monitors.sort_by(|a, b| a.id.cmp(&b.id));
        Self {
            present: true,
            monitors,
        }
    }

    pub fn parse(status_text: &str) -> Self {
        Self::from_surfaces(&parse_ext_list(status_text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
[named-radio]
subsystem=named-radio-cognition
strategy=rule-calibrated
actuation=rate+channel+power+fec
readonly=true
stat.strategy=rule-calibrated
stat.managed_objects=2
stat.suppressed=0
stat.objective=0.4200
stat.learned_thresholds=3
stat.radio.0.channel=36
stat.radio.0.mcs=7
stat.radio.0.nss=1
stat.radio.0.bw=20
stat.radio.0.he=false
stat.radio.0.tx_power=15
stat.radio.0.link_fec=0
stat.radio.0.edcca_ignore=false
stat.radio.0.defer_threshold_dbm=-72/-62
stat.radio.0.suppress=false
stat.contention.edcca_ignored=0
stat.contention.defer_threshold_clamped=1
stat.contention.fec_parity_over_generation=0
stat.radio.0.relay=true
stat.radio.0.objective=0.5100
stat.radio.0.chip=WifiMonitor
stat.radio.0.band=Band5GHz
stat.radio.0.max_mcs=9
stat.radio.0.rx_chains=2
stat.radio.0.he_cap=true
stat.radio.0.dbm_max=20
stat.radio.0.duty_max=1.00
stat.radio.0.rx_only=false
stat.radio.0.rssi_dbm=-58
stat.radio.0.occupancy_pct=22
stat.radio.1.channel=149
stat.radio.1.mcs=9
";

    #[test]
    fn parses_generic_sections_stats_and_objects() {
        let s = parse_ext_list(SAMPLE);
        let radio = s.subsystem("named-radio").expect("named-radio present");
        assert_eq!(radio.info_of("subsystem"), Some("named-radio-cognition"));
        assert_eq!(radio.info_of("readonly"), Some("true"));
        // flat stat, not an object (learned_thresholds has no id)
        assert_eq!(radio.stat("learned_thresholds"), Some("3"));
        assert_eq!(radio.stat("managed_objects"), Some("2"));
        // two radio objects
        let radios = radio.objects_of("radio");
        assert_eq!(radios.len(), 2);
        let r0 = &radio.objects["radio/0"];
        assert_eq!(r0.field("channel"), Some("36"));
        assert_eq!(r0.field("chip"), Some("WifiMonitor"));
    }

    #[test]
    fn unknown_section_before_any_bracket_is_ignored() {
        let s = parse_ext_list("stray=1\n[x]\nstat.a=2\n");
        assert!(s.subsystem("x").is_some());
        assert_eq!(s.subsystem("x").unwrap().stat("a"), Some("2"));
    }

    #[test]
    fn radio_cognition_projection() {
        let cog = RadioCognition::parse(SAMPLE);
        assert!(cog.present);
        assert_eq!(cog.strategy, "rule-calibrated");
        assert_eq!(cog.managed_objects, "2");
        assert_eq!(cog.radios.len(), 2);
        // sorted by id
        assert_eq!(cog.radios[0].id, "0");
        assert_eq!(cog.radios[0].channel, "36");
        assert_eq!(cog.radios[0].relay, "true");
        assert_eq!(cog.radios[1].id, "1");
        assert_eq!(cog.radios[1].mcs, "9");
        // shared-medium claims + actuator-side ledger (producer contract)
        assert_eq!(cog.radios[0].edcca_ignore, "false");
        assert_eq!(cog.radios[0].defer_threshold_dbm, "-72/-62");
        assert_eq!(cog.radios[1].edcca_ignore, "");
        assert_eq!(cog.contention_edcca_ignored, "0");
        assert_eq!(cog.contention_defer_threshold_clamped, "1");
        assert_eq!(cog.contention_fec_parity_over_generation, "0");
    }

    #[test]
    fn radio_cognition_absent_when_no_section() {
        let cog = RadioCognition::parse("[other]\nstat.x=1\n");
        assert!(!cog.present);
        assert!(cog.radios.is_empty());
    }

    #[test]
    fn hardware_projection_reads_substrate_when_present() {
        let hw = HardwareInventory::parse(SAMPLE);
        assert_eq!(hw.radios.len(), 2);
        assert!(hw.any_substrate());
        // Exactly the keys the ndn-phy-wifi producer emits (control_surface.rs).
        let r0 = &hw.radios[0];
        assert_eq!(r0.chip.as_deref(), Some("WifiMonitor"));
        assert_eq!(r0.band.as_deref(), Some("Band5GHz"));
        assert_eq!(r0.max_mcs.as_deref(), Some("9"));
        assert_eq!(r0.rx_chains.as_deref(), Some("2"));
        assert_eq!(r0.he_cap.as_deref(), Some("true"));
        assert_eq!(r0.dbm_max.as_deref(), Some("20"));
        assert_eq!(r0.rssi_dbm.as_deref(), Some("-58"));
        assert_eq!(r0.occupancy_pct.as_deref(), Some("22"));
        // Not reachable from the control plane yet → not emitted → None.
        assert_eq!(r0.driver, None);
        assert_eq!(r0.address, None);
        assert!(r0.has_substrate());
        // radio 1 advertised only decided plan → no substrate yet
        assert!(!hw.radios[1].has_substrate());
    }

    #[test]
    fn hardware_projection_empty_without_keys() {
        // decided-plan-only surface (today's producer): no substrate reported.
        let hw = HardwareInventory::parse(
            "[named-radio]\nstat.radio.0.channel=36\nstat.radio.0.mcs=7\n",
        );
        assert_eq!(hw.radios.len(), 1);
        assert!(!hw.any_substrate());
    }

    #[test]
    fn monitors_projection() {
        let text = "\
[monitors]
subsystem=soak
stat.count=1
stat.monitor.overnight.kind=soak
stat.monitor.overnight.status=running
stat.monitor.overnight.duration_s=46800
stat.monitor.overnight.ok=8
stat.monitor.overnight.fail=0
stat.monitor.overnight.detail=router relay stable
";
        let m = Monitors::parse(text);
        assert!(m.present);
        assert_eq!(m.monitors.len(), 1);
        let mon = &m.monitors[0];
        assert_eq!(mon.id, "overnight");
        assert_eq!(mon.kind, "soak");
        assert_eq!(mon.status, "running");
        assert_eq!(mon.duration_s, "46800");
        assert_eq!(mon.fail, "0");
    }

    #[test]
    fn monitors_absent_when_no_section() {
        assert!(!Monitors::parse(SAMPLE).present);
    }
}
