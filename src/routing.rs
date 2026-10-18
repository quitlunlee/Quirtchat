//! Cache selection uses only locally observed request outcomes, never peer claims.

use std::{collections::BTreeMap, time::Duration};

const MAX_OBSERVATIONS: usize = 2048;
const EXPLORE_EVERY: u64 = 4;

#[derive(Clone)]
struct Observation {
    latency_ms: u64,
    success_per_mille: u64,
    failures: u32,
    samples: u32,
    last_attempt: u64,
}

impl Default for Observation {
    fn default() -> Self {
        Self {
            latency_ms: 1_000,
            success_per_mille: 750,
            failures: 0,
            samples: 0,
            last_attempt: 0,
        }
    }
}

impl Observation {
    fn cost(&self) -> u64 {
        self.latency_ms * 1_000 / self.success_per_mille.max(100)
            + u64::from(self.failures.min(8)) * 1_000
    }
}

#[derive(Default)]
pub(super) struct RouteQuality {
    nodes: BTreeMap<String, Observation>,
    clock: u64,
    selections: BTreeMap<String, (u64, u64)>,
}

impl RouteQuality {
    /// A measured healthy cache can avoid waiting for an unknown/slow direct peer.
    /// Unknown cache nodes never win this fast path solely from an advertised score.
    pub(super) fn prefer_cache(&self, cache: &str, direct: &str) -> bool {
        self.nodes.get(cache).is_some_and(|cache| {
            cache.samples > 0
                && cache.failures == 0
                && cache.cost() < self.nodes.get(direct).cloned().unwrap_or_default().cost()
        })
    }

    fn entry(&mut self, node: &str) -> &mut Observation {
        if !self.nodes.contains_key(node)
            && self.nodes.len() >= MAX_OBSERVATIONS
            && let Some(oldest) = self
                .nodes
                .iter()
                .min_by_key(|(_, item)| item.last_attempt)
                .map(|(id, _)| id.clone())
        {
            self.nodes.remove(&oldest);
        }
        self.nodes.entry(node.to_owned()).or_default()
    }

    /// Candidates must already satisfy authorization, replica diversity and retry limits.
    /// Reserve one in four choices for an unmeasured/least recently tried endpoint.
    pub(super) fn choose(&mut self, scope: &str, candidates: &[&str]) -> Option<usize> {
        if candidates.is_empty() {
            return None;
        }
        self.clock = self.clock.saturating_add(1);
        if !self.selections.contains_key(scope)
            && self.selections.len() >= MAX_OBSERVATIONS
            && let Some(oldest) = self
                .selections
                .iter()
                .min_by_key(|(_, (_, last_used))| *last_used)
                .map(|(scope, _)| scope.clone())
        {
            self.selections.remove(&oldest);
        }
        let (turn, last_used) = self.selections.entry(scope.to_owned()).or_default();
        *turn = turn.wrapping_add(1);
        *last_used = self.clock;
        let explore = turn.is_multiple_of(EXPLORE_EVERY);
        let index = candidates
            .iter()
            .enumerate()
            .min_by_key(|(_, node)| {
                let sample = self.nodes.get(**node).cloned().unwrap_or_default();
                if explore {
                    (u64::from(sample.samples > 0), sample.last_attempt)
                } else {
                    (sample.cost(), sample.last_attempt)
                }
            })?
            .0;
        let clock = self.clock;
        self.entry(candidates[index]).last_attempt = clock;
        Some(index)
    }

    /// The elapsed value is the observed RPC round trip, including remote service time.
    /// EWMA (weight 1/4) reacts to changing routes without following every latency spike.
    pub(super) fn observe(&mut self, node: &str, elapsed: Duration, success: bool) {
        self.clock = self.clock.saturating_add(1);
        let clock = self.clock;
        let item = self.entry(node);
        let latency = elapsed.as_millis().clamp(1, 60_000) as u64;
        let outcome = if success { 1_000 } else { 0 };
        if item.samples == 0 {
            item.latency_ms = latency;
            item.success_per_mille = outcome;
        } else {
            item.latency_ms = (item.latency_ms * 3 + latency) / 4;
            item.success_per_mille = (item.success_per_mille * 3 + outcome) / 4;
        }
        item.failures = if success {
            0
        } else {
            item.failures.saturating_add(1)
        };
        item.samples = item.samples.saturating_add(1);
        item.last_attempt = clock;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measured_latency_and_failures_change_the_preferred_cache() {
        let mut routes = RouteQuality::default();
        routes.observe("slow", Duration::from_millis(300), true);
        routes.observe("fast", Duration::from_millis(20), true);
        assert_eq!(routes.choose("recipient", &["slow", "fast"]), Some(1));
        routes.observe("fast", Duration::from_secs(10), false);
        assert_eq!(routes.choose("recipient", &["slow", "fast"]), Some(0));
        for _ in 0..20 {
            routes.observe("fast", Duration::from_millis(20), true);
        }
        assert_eq!(routes.choose("recipient", &["slow", "fast"]), Some(1));
    }

    #[test]
    fn cache_fast_path_requires_success_and_yields_to_a_faster_direct_peer() {
        let mut routes = RouteQuality::default();
        assert!(!routes.prefer_cache("cache", "direct"));
        routes.observe("cache", Duration::from_millis(30), true);
        assert!(routes.prefer_cache("cache", "direct"));
        routes.observe("direct", Duration::from_millis(5), true);
        assert!(!routes.prefer_cache("cache", "direct"));
        routes.observe("direct", Duration::from_secs(10), false);
        assert!(routes.prefer_cache("cache", "direct"));
        routes.observe("cache", Duration::from_millis(5), false);
        assert!(!routes.prefer_cache("cache", "direct"));
    }

    #[test]
    fn bounded_exploration_visits_unknown_nodes_then_rechecks_old_routes() {
        let mut routes = RouteQuality::default();
        routes.observe("fast", Duration::from_millis(10), true);
        let candidates = ["fast", "new-a", "new-b", "new-c"];
        let mut tried = Vec::new();
        for turn in 1..=12 {
            let index = routes.choose("recipient", &candidates).unwrap();
            if turn % EXPLORE_EVERY == 0 {
                assert_ne!(index, 0);
                tried.push(index);
            } else {
                assert_eq!(index, 0);
            }
            routes.observe(
                candidates[index],
                Duration::from_millis(if index == 0 { 10 } else { 500 }),
                true,
            );
        }
        assert_eq!(tried, vec![1, 2, 3]);
        for _ in 0..3 {
            assert_eq!(routes.choose("recipient", &candidates), Some(0));
        }
        assert_eq!(routes.choose("recipient", &candidates), Some(1));
    }

    #[test]
    fn observations_are_bounded_and_empty_selection_does_not_spend_exploration() {
        let mut routes = RouteQuality::default();
        assert_eq!(routes.choose("empty", &[]), None);
        assert!(routes.selections.is_empty());
        for index in 0..=MAX_OBSERVATIONS {
            routes.observe(&format!("node-{index}"), Duration::from_millis(10), true);
            routes.choose(&format!("scope-{index}"), &["node-1"]);
        }
        assert_eq!(routes.nodes.len(), MAX_OBSERVATIONS);
        assert!(!routes.nodes.contains_key("node-0"));
        assert!(
            routes
                .nodes
                .contains_key(&format!("node-{MAX_OBSERVATIONS}"))
        );
        assert_eq!(routes.selections.len(), MAX_OBSERVATIONS);
        assert!(!routes.selections.contains_key("scope-0"));
    }

    #[test]
    fn interleaved_recipients_each_receive_exploration_turns() {
        let mut routes = RouteQuality::default();
        routes.observe("fast", Duration::from_millis(10), true);
        for turn in 1..=4 {
            for recipient in ["alice", "bob", "carol", "dave"] {
                let unknown = format!("{recipient}-new");
                assert_eq!(
                    routes.choose(recipient, &["fast", &unknown]),
                    Some(usize::from(turn == 4))
                );
            }
        }
    }
}
