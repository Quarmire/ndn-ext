//! GNSS as a time source — a **pure** NMEA time parser plus a source that a
//! host feeds serial lines into. No serial dependency lives here: the parsing
//! is pure and testable, and the actual UART read is the host's job.

use std::time::Instant;

use ndn_time::{ClockCapability, TimeInterval};

use crate::{Reading, TimeSource};

/// Parse an `RMC` NMEA sentence into **Unix nanoseconds**, or `None` if it is
/// not a valid, fixed `RMC` (any talker: `GPRMC`, `GNRMC`, …). If a `*CS`
/// checksum is present it is verified; a wrong checksum yields `None`.
///
/// `RMC` is the one common sentence carrying both time *and* date; `GGA` has
/// time only, so it cannot be turned into an absolute timestamp on its own.
pub fn parse_rmc_unix_ns(sentence: &str) -> Option<i64> {
    let body = sentence.trim().strip_prefix('$')?;
    // Split off and (if present) verify the checksum: XOR of the body bytes.
    let (body, checksum) = match body.split_once('*') {
        Some((b, c)) => (b, Some(c)),
        None => (body, None),
    };
    if let Some(cs) = checksum {
        let want = u8::from_str_radix(cs.trim(), 16).ok()?;
        let got = body.bytes().fold(0u8, |a, b| a ^ b);
        if got != want {
            return None;
        }
    }

    let mut f = body.split(',');
    if !f.next()?.ends_with("RMC") {
        return None;
    }
    let time = f.next()?; // hhmmss(.sss)
    if f.next()? != "A" {
        return None; // status: A = valid fix, V = void
    }
    // Skip lat, N/S, lon, E/W, speed, course (6 fields) to reach the date.
    for _ in 0..6 {
        f.next()?;
    }
    let date = f.next()?; // ddmmyy

    if time.len() < 6 || date.len() < 6 {
        return None;
    }
    let hh: i64 = time.get(0..2)?.parse().ok()?;
    let mm: i64 = time.get(2..4)?.parse().ok()?;
    let ss: i64 = time.get(4..6)?.parse().ok()?;
    let frac_ns = frac_ns(time);
    let dd: i64 = date.get(0..2)?.parse().ok()?;
    let mo: i64 = date.get(2..4)?.parse().ok()?;
    let yy: i64 = date.get(4..6)?.parse().ok()?;
    if !(1..=12).contains(&mo) || !(1..=31).contains(&dd) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }

    let days = days_from_civil(2000 + yy, mo, dd);
    let secs = days * 86_400 + hh * 3_600 + mm * 60 + ss;
    secs.checked_mul(1_000_000_000)?.checked_add(frac_ns)
}

/// Nanoseconds from the fractional-seconds part of an `hhmmss.sss` field.
fn frac_ns(time: &str) -> i64 {
    let Some((_, frac)) = time.split_once('.') else {
        return 0;
    };
    let mut ns = 0i64;
    let mut scale = 100_000_000i64; // first fractional digit = 1e8 ns
    for c in frac.chars().take(9) {
        match c.to_digit(10) {
            Some(d) => {
                ns += d as i64 * scale;
                scale /= 10;
            }
            None => break,
        }
    }
    ns
}

/// Days from the Unix epoch (1970-01-01) for a proleptic-Gregorian civil date
/// (Howard Hinnant's `days_from_civil`). Pure integer arithmetic — no `chrono`.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// A GNSS receiver as a time source. Feed it NMEA lines with [`Self::feed`]
/// (from a UART read loop the host owns); [`TimeSource::poll`] then returns the
/// latest fix once and clears it (a fix is an event, not a steady reading).
pub struct GnssSource {
    latest: Option<Reading>,
    uncertainty_ns: u64,
    epoch: Instant,
}

impl GnssSource {
    /// A source whose fixes carry `uncertainty_ns` half-width. Without a PPS
    /// signal, NMEA-sentence timing jitter dominates (~1 ms is typical); a PPS
    /// discipline tightens this to tens of nanoseconds.
    pub fn new(uncertainty_ns: u64) -> Self {
        Self {
            latest: None,
            uncertainty_ns,
            epoch: Instant::now(),
        }
    }

    /// Feed one NMEA line. Updates the pending reading on a valid `RMC` fix and
    /// returns `true`; ignores everything else.
    pub fn feed(&mut self, line: &str) -> bool {
        match parse_rmc_unix_ns(line) {
            Some(unix_ns) => {
                self.latest = Some(Reading {
                    wall: TimeInterval::new(unix_ns, self.uncertainty_ns),
                    cap: ClockCapability::gnss_disciplined(),
                    captured_mono_ns: self.epoch.elapsed().as_nanos() as u64,
                });
                true
            }
            None => false,
        }
    }
}

impl Default for GnssSource {
    /// 1 ms — NMEA-without-PPS class. Pass a tighter value once PPS-disciplined.
    fn default() -> Self {
        Self::new(1_000_000)
    }
}

impl TimeSource for GnssSource {
    fn poll(&mut self) -> Option<Reading> {
        self.latest.take()
    }

    fn label(&self) -> &'static str {
        "gnss-nmea"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rmc_to_unix_ns() {
        // 2024-01-01 00:00:00 UTC = 1_704_067_200 s (checksum omitted → accepted).
        let s = "$GPRMC,000000.00,A,0000.0,N,00000.0,E,0,0,010124,,";
        assert_eq!(parse_rmc_unix_ns(s), Some(1_704_067_200 * 1_000_000_000));
    }

    #[test]
    fn fractional_seconds_become_nanoseconds() {
        let s = "$GNRMC,000000.25,A,0,N,0,E,0,0,010124,,";
        assert_eq!(
            parse_rmc_unix_ns(s),
            Some(1_704_067_200 * 1_000_000_000 + 250_000_000)
        );
    }

    #[test]
    fn void_fix_and_wrong_sentence_are_rejected() {
        assert_eq!(
            parse_rmc_unix_ns("$GPRMC,000000,V,0,N,0,E,0,0,010124,,"),
            None,
            "V = void fix"
        );
        assert_eq!(
            parse_rmc_unix_ns("$GPGGA,000000,0,N,0,E,1,08,0.9,0,M,0,M,,"),
            None,
            "GGA has no date"
        );
    }

    #[test]
    fn checksum_is_verified_when_present() {
        // Build a body, append its real checksum, and flip it to force a reject.
        let body = "GPRMC,120000.00,A,0,N,0,E,0,0,020224,,";
        let cs = body.bytes().fold(0u8, |a, b| a ^ b);
        let good = format!("${body}*{cs:02X}");
        assert!(parse_rmc_unix_ns(&good).is_some(), "valid checksum parses");
        let bad = format!("${body}*{:02X}", cs ^ 0xFF);
        assert_eq!(parse_rmc_unix_ns(&bad), None, "bad checksum rejected");
    }

    #[test]
    fn source_holds_a_fix_until_polled() {
        let mut g = GnssSource::default();
        assert!(g.poll().is_none(), "nothing before a fix");
        assert!(g.feed("$GPRMC,000000.00,A,0,N,0,E,0,0,010124,,"));
        let r = g.poll().expect("a fix");
        assert_eq!(r.wall.center_ns, 1_704_067_200 * 1_000_000_000);
        assert!(r.cap.reference_only, "GNSS is a reference clock");
        assert!(g.poll().is_none(), "a fix is consumed once");
    }
}
