//! wasm-cleanliness guard.
//!
//! `ndn-viz` is depended on by the browser dashboard (`wasm32-unknown-unknown`),
//! where the platform clock / filesystem / environment / network / process APIs
//! panic at runtime or do not link. Compilation does not catch these — they only
//! blow up when the offending path is actually hit in a browser (exactly the
//! `days_to_expiry` → `SystemTime::now()` crash that motivated this crate). This
//! source-scan makes the ban a build failure instead: cheap, deterministic, and
//! it fires the moment a banned call is *added*, not when a user clicks it.
//!
//! The technique is the reusable half of the archived crate's
//! `architecture_guards.rs` (its specific token bans died with it).

use std::path::Path;

/// Substrings that must never appear in `ndn-viz/src`. Kept assembled from
/// fragments so this test file does not trip its own scan.
fn banned_tokens() -> Vec<String> {
    let s = "std::";
    vec![
        format!("{s}time"),
        format!("{s}fs"),
        format!("{s}env"),
        format!("{s}net"),
        format!("{s}process"),
        "SystemTime".to_string(),
        "Instant".to_string(),
    ]
}

fn scan_dir(dir: &Path, banned: &[String], hits: &mut Vec<String>) {
    let entries = std::fs::read_dir(dir).expect("read src dir");
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            scan_dir(&path, banned, hits);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read source file");
        for (lineno, line) in text.lines().enumerate() {
            for token in banned {
                if line.contains(token.as_str()) {
                    hits.push(format!(
                        "{}:{}: banned `{token}` — {}",
                        path.display(),
                        lineno + 1,
                        line.trim()
                    ));
                }
            }
        }
    }
}

#[test]
fn src_is_wasm_clean() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let banned = banned_tokens();
    let mut hits = Vec::new();
    scan_dir(&src, &banned, &mut hits);
    assert!(
        hits.is_empty(),
        "ndn-viz/src must stay wasm-clean (no platform clock/fs/env/net/process). \
         Route the platform call through the consumer instead. Offenders:\n{}",
        hits.join("\n")
    );
}
