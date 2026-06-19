//! Name-prefix trie FIB for the WASM simulation: insert, longest-prefix
//! match, and remove.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FibNexthop {
    pub face_id: u32,
    pub cost: u32,
}

#[derive(Default)]
struct TrieNode {
    nexthops: Vec<FibNexthop>,
    children: HashMap<String, TrieNode>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FibEntry {
    pub prefix: String,
    pub nexthops: Vec<FibNexthop>,
}

pub struct SimFib {
    root: TrieNode,
}

impl SimFib {
    pub fn new() -> Self {
        Self {
            root: TrieNode::default(),
        }
    }

    /// `prefix` is a slash-separated NDN name (e.g. `/ndn/ucla`).
    pub fn add_route(&mut self, prefix: &str, face_id: u32, cost: u32) {
        let components = parse_name(prefix);
        let mut node = &mut self.root;
        for comp in &components {
            node = node.children.entry(comp.clone()).or_default();
        }
        if let Some(nh) = node.nexthops.iter_mut().find(|n| n.face_id == face_id) {
            nh.cost = cost;
        } else {
            node.nexthops.push(FibNexthop { face_id, cost });
        }
    }

    pub fn remove_face(&mut self, face_id: u32) {
        Self::remove_face_recursive(&mut self.root, face_id);
    }

    fn remove_face_recursive(node: &mut TrieNode, face_id: u32) {
        node.nexthops.retain(|nh| nh.face_id != face_id);
        for child in node.children.values_mut() {
            Self::remove_face_recursive(child, face_id);
        }
    }

    /// Longest-prefix match; empty when no route applies, including no
    /// default route at `/`.
    pub fn lpm(&self, name: &str) -> Vec<FibNexthop> {
        let components = parse_name(name);
        let mut best: Vec<FibNexthop> = Vec::new();
        let mut node = &self.root;

        if !node.nexthops.is_empty() {
            best.clone_from(&node.nexthops);
        }

        for comp in &components {
            match node.children.get(comp.as_str()) {
                Some(n) => {
                    node = n;
                    if !node.nexthops.is_empty() {
                        best.clone_from(&node.nexthops);
                    }
                }
                None => break,
            }
        }
        best
    }

    pub fn snapshot(&self) -> Vec<FibEntry> {
        let mut entries = Vec::new();
        Self::collect_entries(&self.root, &mut Vec::new(), &mut entries);
        entries.sort_by(|a, b| a.prefix.cmp(&b.prefix));
        entries
    }

    fn collect_entries(node: &TrieNode, path: &mut Vec<String>, out: &mut Vec<FibEntry>) {
        if !node.nexthops.is_empty() {
            let prefix = if path.is_empty() {
                "/".to_string()
            } else {
                format!("/{}", path.join("/"))
            };
            out.push(FibEntry {
                prefix,
                nexthops: node.nexthops.clone(),
            });
        }
        for (comp, child) in &node.children {
            path.push(comp.clone());
            Self::collect_entries(child, path, out);
            path.pop();
        }
    }
}

impl Default for SimFib {
    fn default() -> Self {
        Self::new()
    }
}

pub fn parse_name(name: &str) -> Vec<String> {
    name.trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

pub fn format_name(components: &[String]) -> String {
    if components.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", components.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lpm_exact_match() {
        let mut fib = SimFib::new();
        fib.add_route("/ndn/ucla", 1, 0);
        let nexthops = fib.lpm("/ndn/ucla/paper.pdf");
        assert_eq!(nexthops.len(), 1);
        assert_eq!(nexthops[0].face_id, 1);
    }

    #[test]
    fn lpm_longer_beats_shorter() {
        let mut fib = SimFib::new();
        fib.add_route("/ndn", 1, 0);
        fib.add_route("/ndn/ucla", 2, 0);
        let nexthops = fib.lpm("/ndn/ucla/paper");
        assert_eq!(nexthops[0].face_id, 2);
    }

    #[test]
    fn lpm_no_match_returns_empty() {
        let fib = SimFib::new();
        assert!(fib.lpm("/ndn/data").is_empty());
    }

    #[test]
    fn default_route() {
        let mut fib = SimFib::new();
        fib.add_route("/", 99, 0);
        assert_eq!(fib.lpm("/anything/deep").len(), 1);
    }
}
