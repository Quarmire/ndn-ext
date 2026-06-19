//! Event-driven probe scheduler: probes fire only on [`TriggerEvent`]s,
//! rate-limited to one per `hello_interval_base`.

use std::time::{Duration, Instant};

use crate::config::DiscoveryConfig;
use crate::strategy::{NeighborProbeStrategy, ProbeRequest, TriggerEvent};

pub struct ReactiveScheduler {
    min_interval: Duration,
    last_sent: Option<Instant>,
    pending: bool,
}

impl ReactiveScheduler {
    pub fn from_discovery_config(cfg: &DiscoveryConfig) -> Self {
        Self {
            min_interval: cfg.hello_interval_base,
            last_sent: None,
            pending: true,
        }
    }
}

impl NeighborProbeStrategy for ReactiveScheduler {
    fn on_tick(&mut self, now: Instant) -> Vec<ProbeRequest> {
        if !self.pending {
            return Vec::new();
        }

        if let Some(last) = self.last_sent
            && now.duration_since(last) < self.min_interval
        {
            return Vec::new();
        }

        self.pending = false;
        self.last_sent = Some(now);
        vec![ProbeRequest::Broadcast]
    }

    fn on_probe_success(&mut self, _rtt: Duration) {}

    fn on_probe_timeout(&mut self) {
        self.pending = true;
    }

    fn trigger(&mut self, event: TriggerEvent) {
        match event {
            TriggerEvent::PassiveDetection => {}
            TriggerEvent::FaceUp
            | TriggerEvent::ForwardingFailure
            | TriggerEvent::NeighborStale => {
                self.pending = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::config::{DiscoveryConfig, DiscoveryProfile};

    fn mobile_sched() -> ReactiveScheduler {
        ReactiveScheduler::from_discovery_config(&DiscoveryConfig::for_profile(
            &DiscoveryProfile::Mobile,
        ))
    }

    #[test]
    fn fires_on_first_tick() {
        let mut s = mobile_sched();
        let reqs = s.on_tick(Instant::now());
        assert_eq!(reqs, vec![ProbeRequest::Broadcast]);
    }

    #[test]
    fn does_not_fire_without_trigger() {
        let mut s = mobile_sched();
        let now = Instant::now();
        s.on_tick(now);

        let reqs = s.on_tick(now + Duration::from_secs(1));
        assert!(reqs.is_empty());
    }

    #[test]
    fn fires_after_trigger() {
        let mut s = mobile_sched();
        let now = Instant::now();
        s.on_tick(now);

        s.trigger(TriggerEvent::ForwardingFailure);
        let reqs = s.on_tick(now + Duration::from_secs(1));
        assert_eq!(reqs, vec![ProbeRequest::Broadcast]);
    }

    #[test]
    fn rate_limits_rapid_triggers() {
        let mut s = mobile_sched();
        let now = Instant::now();
        s.on_tick(now);

        s.trigger(TriggerEvent::NeighborStale);
        let reqs = s.on_tick(now);
        assert!(reqs.is_empty(), "should be rate-limited");

        let later = now + s.min_interval + Duration::from_millis(1);
        let reqs = s.on_tick(later);
        assert_eq!(reqs, vec![ProbeRequest::Broadcast]);
    }

    #[test]
    fn passive_detection_is_ignored() {
        let mut s = mobile_sched();
        let now = Instant::now();
        s.on_tick(now);

        s.trigger(TriggerEvent::PassiveDetection);
        let reqs = s.on_tick(now + Duration::from_secs(10));
        assert!(reqs.is_empty());
    }
}
