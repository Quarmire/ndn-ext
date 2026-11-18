//! What [`Links::report`](crate::Links::report) says of the fault layer. The type
//! exists in every build, so a host's code does not change with the cargo feature
//! `fault-injection`; the layer itself (`crate::fault`, behind that feature) is the
//! only thing that fills it. See ndn-rs `docs/specs/ndn-link.md` §17B.

/// The fault layer of a build that has it: `LinkReport::fault_injection` is `Some`
/// exactly when ndn-link was built with `fault-injection` (**for tests only**) and
/// `None` in every other build, so a host can refuse to run, or say so loudly, when
/// it finds one in a production binary.
///
/// The counters are those of the plan installed now ([`Links::inject_faults`]
/// starts them again at zero), summed over every link.
///
/// [`Links::inject_faults`]: crate::Links
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FaultReport {
    /// The installed profile in its text form (`drop=0.2,dup=0.1,…,seed=3`, the form
    /// the conformance's `--faulty` reads); `None` while no plan is installed (the
    /// layer is compiled in and touches nothing).
    pub profile: Option<String>,
    /// Packets that arrived on a link and met the profile: the plan had no predicate,
    /// or its predicate chose them.
    pub met: u64,
    /// Of those, packets the profile dropped.
    pub dropped: u64,
    /// Of those, packets the profile delivered twice.
    pub duplicated: u64,
    /// Of those, Data packets the profile forged (one signature byte flipped).
    pub forged: u64,
    /// Of those, packets the profile held back (delivered later than they arrived).
    pub delayed: u64,
    /// Packets the plan's predicate left alone: delivered at once and untouched.
    pub passed: u64,
    /// Times the plan's predicate panicked; the packet it was asked about was
    /// delivered untouched (the layer fails open, and says so here).
    pub predicate_panics: u64,
}

#[cfg(not(feature = "fault-injection"))]
impl crate::Links {
    /// Without the feature there is no fault layer to report.
    pub(crate) fn fault_report(&self) -> Option<FaultReport> {
        None
    }
}
