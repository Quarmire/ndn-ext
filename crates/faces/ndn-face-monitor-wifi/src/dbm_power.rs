//! Layer: adapter — absolute **dBm** TX-power control for Linux mac80211 radios.
//!
//! The portable half of the power story. [`RadioKnobs::set_tx_power`] speaks an
//! opaque chip TXAGC index: nonlinear, and meaningless across parts. This module
//! implements [`RadioKnobs::set_tx_power_dbm`] instead, so cognition can spend
//! *link budget* (dB) rather than register units, and the same decision actuates
//! on any radio that exposes an absolute knob.
//!
//! Nothing here is specific to one driver or one PHY. Two mechanisms are probed,
//! in order:
//!
//! 1. **A driver debugfs knob** taking a plain decimal dBm value ([`DRIVER_KNOBS`]).
//!    This exists because the standards path frequently does *not* work on the
//!    interfaces named-radio actually transmits on: on a monitor vif the driver's
//!    `get_txpower` has no chanctx and nl80211 reports a stale regulatory number,
//!    and some drivers refuse `iw ... set txpower` on a monitor vif outright.
//!    Supporting a new driver is one row in the table, not new code.
//! 2. **nl80211 via `iw`**, the standards fallback for any mac80211 radio whose
//!    driver has no knob of its own.
//!
//! The range is never invented: a table row carries bounds only where they have
//! been read off the driver source or measured, and the nl80211 path takes its
//! ceiling from what the kernel itself reports for the phy. A radio with no
//! determinable range advertises none, and cognition falls back to the index
//! scale — which is the honest outcome, since a fabricated dB range would be
//! believed and spent as if it were real.
//!
//! Every setter returns the power **actually applied**, which regulatory/BCF
//! tables in the driver or firmware may clamp below the request.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use ndn_radio_hal::{Bandwidth, DbmRange, FaceError, RadioKnobs};

/// A driver debugfs knob that accepts a plain decimal dBm value.
///
/// Both current entries are *our* knobs, added to their vendor drivers so the
/// cognition plane could reach TX power at all; both take dBm and clamp in
/// firmware against the regulatory/board table, so both are read back after a
/// write rather than assumed.
struct KnobSpec {
    /// Human-readable radio this knob belongs to (diagnostics only).
    driver: &'static str,
    /// debugfs file name, searched for beneath the phy's debugfs directory.
    file: &'static str,
    /// Commandable bounds. The upper bound is what the *knob* accepts, not what
    /// the radio necessarily radiates — firmware clamps further, which is why
    /// [`Mac80211Knobs::set_tx_power_dbm`] reports the read-back value.
    range: DbmRange,
}

/// Driver knobs this adapter knows how to drive. Adding a radio is one row.
const DRIVER_KNOBS: &[KnobSpec] = &[
    // Morse Micro MM6108 (802.11ah). Writes run MORSE_CMD_ID_SET_TXPOWER through
    // the driver's clamping wrapper; 1..30 accepted, firmware clamps (measured:
    // 30 -> 27 on an FGH100M-H, and the commanded dB tracked radiated dB at
    // 0.99 dB/dB over a 21.5 dB span on an SDR).
    KnobSpec {
        driver: "Morse Micro MM6108",
        file: "tx_power_dbm",
        range: DbmRange { min: 1, max: 30 },
    },
    // Newracom NRC7292 (802.11ah). Same contract: dBm in, firmware "nrf txpwr
    // fixed <dBm>" behind it, 1..30 accepted.
    KnobSpec {
        driver: "Newracom NRC7292",
        file: "nrc_txpower",
        range: DbmRange { min: 1, max: 30 },
    },
];

/// Where an absolute-power write goes.
#[derive(Clone, Debug)]
enum Mechanism {
    /// A driver debugfs file taking decimal dBm.
    Debugfs {
        path: PathBuf,
        /// Which table row matched (diagnostics).
        driver: &'static str,
    },
    /// `iw dev <iface> set txpower fixed <mBm>`.
    Nl80211,
}

/// The generic mac80211 control seam: channel + absolute dBm power over an
/// interface name, with no driver-specific code above the [`DRIVER_KNOBS`] table.
///
/// Built by [`discover`](Self::discover), which never fails — a radio where
/// nothing is found simply reports [`tx_power_range`](Self::tx_power_range) as
/// `None` and rejects dBm writes, leaving the caller on the index scale.
pub struct Mac80211Knobs {
    iface: String,
    mechanism: Option<Mechanism>,
    range: Option<DbmRange>,
}

impl Mac80211Knobs {
    /// Probe `iface` for an absolute-power control: a known driver knob first,
    /// then nl80211. Never fails; a radio with neither yields a handle whose
    /// [`tx_power_range`](Self::tx_power_range) is `None`.
    pub fn discover(iface: &str) -> Self {
        let phy = phy_name(iface);
        let (mechanism, range) = match phy.as_deref().and_then(find_driver_knob) {
            Some((path, spec)) => (
                Some(Mechanism::Debugfs {
                    path,
                    driver: spec.driver,
                }),
                Some(spec.range),
            ),
            // No driver knob: fall back to nl80211, but only when the kernel
            // tells us a real ceiling for this phy. No ceiling -> no claim.
            None => match phy.as_deref().and_then(iw_phy_max_dbm) {
                Some(max) => (Some(Mechanism::Nl80211), Some(DbmRange::new(0, max))),
                None => (None, None),
            },
        };
        Self {
            iface: iface.to_string(),
            mechanism,
            range,
        }
    }

    /// The absolute-power range this radio actually offers, for
    /// [`RadioCapability::with_tx_power_dbm`](ndn_radio_hal::RadioCapability::with_tx_power_dbm).
    /// `None` = no absolute control was found.
    pub fn tx_power_range(&self) -> Option<DbmRange> {
        self.range
    }

    /// A short description of what is driving power, for logs.
    pub fn mechanism_name(&self) -> &'static str {
        match self.mechanism {
            Some(Mechanism::Debugfs { driver, .. }) => driver,
            Some(Mechanism::Nl80211) => "nl80211",
            None => "none",
        }
    }

    /// Write `dbm` and return what the radio reports it applied.
    fn write_dbm(&self, dbm: i8) -> io::Result<i8> {
        match &self.mechanism {
            Some(Mechanism::Debugfs { path, .. }) => {
                fs::write(path, format!("{dbm}\n"))?;
                // Read back where the knob supports it — the driver reports the
                // post-clamp value, which is the number worth believing.
                Ok(read_back_dbm(path).unwrap_or(dbm))
            }
            Some(Mechanism::Nl80211) => {
                let mbm = i32::from(dbm) * 100;
                run_iw(&["dev", &self.iface, "set", "txpower", "fixed", &mbm.to_string()])?;
                Ok(iw_iface_txpower_dbm(&self.iface).unwrap_or(dbm))
            }
            None => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "no absolute dBm TX-power control found for this radio",
            )),
        }
    }
}

impl RadioKnobs for Mac80211Knobs {
    /// Retune via nl80211. A monitor vif that is pinned to one channel (several
    /// S1G drivers refuse the set) would otherwise fail the whole actuation pass,
    /// so an already-correct channel is a no-op rather than a command.
    fn set_channel(&self, channel: u8, _bw: Bandwidth) -> Result<(), FaceError> {
        if iw_iface_channel(&self.iface) == Some(channel) {
            return Ok(());
        }
        run_iw(&["dev", &self.iface, "set", "channel", &channel.to_string()])
            .map(|_| ())
            .map_err(FaceError::Io)
    }

    fn set_tx_power_dbm(&self, dbm: i8) -> Result<i8, FaceError> {
        let want = self.range.map(|r| r.clamp(dbm)).unwrap_or(dbm);
        self.write_dbm(want).map_err(FaceError::Io)
    }
}

/// `/sys/class/net/<iface>/phy80211/name` — the phy backing a netdev.
fn phy_name(iface: &str) -> Option<String> {
    let p = format!("/sys/class/net/{iface}/phy80211/name");
    Some(fs::read_to_string(p).ok()?.trim().to_string())
}

/// Search a phy's debugfs for any knob in [`DRIVER_KNOBS`].
///
/// Drivers place their knobs inconsistently — some directly under the phy dir,
/// some in a subdirectory named after the driver — so both are checked rather
/// than hard-coding one layout per driver.
fn find_driver_knob(phy: &str) -> Option<(PathBuf, &'static KnobSpec)> {
    let roots = [
        PathBuf::from(format!("/sys/kernel/debug/ieee80211/{phy}")),
        PathBuf::from("/sys/kernel/debug"),
    ];
    for root in roots.iter().filter(|r| r.is_dir()) {
        for spec in DRIVER_KNOBS {
            if let Some(hit) = probe_knob(root, spec) {
                return Some((hit, spec));
            }
        }
    }
    None
}

/// `root/<file>` or `root/*/<file>` (one level down).
fn probe_knob(root: &Path, spec: &KnobSpec) -> Option<PathBuf> {
    let direct = root.join(spec.file);
    if direct.is_file() {
        return Some(direct);
    }
    for entry in fs::read_dir(root).ok()?.flatten() {
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            let nested = entry.path().join(spec.file);
            if nested.is_file() {
                return Some(nested);
            }
        }
    }
    None
}

/// Read a debugfs knob back as dBm. Knobs that are write-only simply yield `None`.
fn read_back_dbm(path: &Path) -> Option<i8> {
    parse_leading_i8(&fs::read_to_string(path).ok()?)
}

fn run_iw(args: &[&str]) -> io::Result<String> {
    let out = Command::new("iw").args(args).output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "iw {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The phy's regulatory ceiling as the kernel reports it, in dBm.
fn iw_phy_max_dbm(phy: &str) -> Option<i8> {
    parse_iw_phy_max_dbm(&run_iw(&["phy", phy, "info"]).ok()?)
}

fn iw_iface_txpower_dbm(iface: &str) -> Option<i8> {
    parse_iw_txpower(&run_iw(&["dev", iface, "info"]).ok()?)
}

fn iw_iface_channel(iface: &str) -> Option<u8> {
    parse_iw_channel(&run_iw(&["dev", iface, "info"]).ok()?)
}

// ---- pure parsers (unit-tested without hardware) ----

/// Leading signed integer of a string (`"27\n"` -> `27`).
fn parse_leading_i8(s: &str) -> Option<i8> {
    let t = s.trim();
    let end = t
        .char_indices()
        .position(|(i, c)| !(c.is_ascii_digit() || (i == 0 && (c == '-' || c == '+'))))
        .unwrap_or(t.len());
    t[..end].parse().ok()
}

/// Largest `(NN.N dBm)` limit in `iw phy <phy> info` output — the kernel's own
/// per-channel regulatory ceiling, rounded down to whole dBm.
fn parse_iw_phy_max_dbm(text: &str) -> Option<i8> {
    let mut best: Option<f32> = None;
    for (idx, _) in text.match_indices("dBm)") {
        let head = &text[..idx];
        let open = match head.rfind('(') {
            Some(o) => o + 1,
            None => continue,
        };
        if let Ok(v) = head[open..].trim().parse::<f32>()
            && best.map(|b| v > b).unwrap_or(true)
        {
            best = Some(v);
        }
    }
    best.map(|v| v.floor() as i8)
}

/// `txpower 27.00 dBm` from `iw dev <iface> info`.
fn parse_iw_txpower(text: &str) -> Option<i8> {
    let idx = text.find("txpower")? + "txpower".len();
    text[idx..]
        .split_whitespace()
        .next()?
        .parse::<f32>()
        .ok()
        .map(|v| v.floor() as i8)
}

/// `channel 5 (2432 MHz)` from `iw dev <iface> info`.
fn parse_iw_channel(text: &str) -> Option<u8> {
    let idx = text.find("channel")? + "channel".len();
    text[idx..].split_whitespace().next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_debugfs_readback() {
        assert_eq!(parse_leading_i8("27\n"), Some(27));
        assert_eq!(parse_leading_i8("5"), Some(5));
        assert_eq!(parse_leading_i8("-3\n"), Some(-3));
        assert_eq!(parse_leading_i8("garbage"), None);
    }

    #[test]
    fn parses_phy_regulatory_ceiling() {
        // Trimmed shape of real `iw phy phy0 info` output.
        let text = "\
Wiphy phy0
	Band 1:
		* 2412 MHz [1] (20.0 dBm)
		* 2417 MHz [2] (20.0 dBm)
		* 2432 MHz [5] (30.0 dBm)
		* 2437 MHz [6] (disabled)";
        assert_eq!(parse_iw_phy_max_dbm(text), Some(30));
    }

    #[test]
    fn no_ceiling_means_no_claim() {
        // A phy that reports no power limits must not produce a fabricated range.
        assert_eq!(parse_iw_phy_max_dbm("Wiphy phy0\n\tBand 1:\n"), None);
    }

    #[test]
    fn parses_iface_txpower_and_channel() {
        let text = "\
Interface mon0
	type monitor
	channel 5 (2432 MHz), width: 20 MHz
	txpower 27.00 dBm";
        assert_eq!(parse_iw_txpower(text), Some(27));
        assert_eq!(parse_iw_channel(text), Some(5));
    }

    #[test]
    fn requests_are_clamped_into_the_advertised_range() {
        let r = DbmRange::new(1, 30);
        assert_eq!(r.clamp(45), 30);
        assert_eq!(r.clamp(0), 1);
        assert_eq!(r.clamp(14), 14);
        assert_eq!(r.span_db(), 29);
    }

    #[test]
    fn unknown_radio_rejects_dbm_rather_than_pretending() {
        // No mechanism found -> the write must fail loudly so the caller falls
        // back to the index scale, instead of silently dropping the request.
        let k = Mac80211Knobs {
            iface: "nonexistent0".into(),
            mechanism: None,
            range: None,
        };
        assert!(k.tx_power_range().is_none());
        assert!(k.set_tx_power_dbm(10).is_err());
        assert_eq!(k.mechanism_name(), "none");
    }

    #[test]
    fn discovery_on_a_missing_interface_is_inert() {
        let k = Mac80211Knobs::discover("definitely-not-an-iface");
        assert!(k.tx_power_range().is_none());
        assert!(k.set_tx_power_dbm(10).is_err());
    }
}
