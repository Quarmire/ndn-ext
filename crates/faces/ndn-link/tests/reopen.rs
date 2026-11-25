//! A device closed and let go releases its store: the same directory opens again in the same
//! process at once, with no retry.
//!
//! The device is the natural host's: the invitations' `Host` holds the `LinkHints` over the
//! device's `Links` (the hints are set after the links start), the node's judge holds the
//! host as its adopter, the links hold the surface of the invitations. Nothing of that may keep
//! the node alive once it is closed and the host has let go.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::*;
use ndn_heap::{Readers, Share};
use ndn_invite::Role;
use ndn_sync::DataStore;
use ndn_sync::store::BackendStore;

/// A directory under the temp directory, removed when the case ends.
struct Dir(PathBuf);

impl Dir {
    fn new(case: &str) -> Dir {
        let dir = std::env::temp_dir().join(format!("ndn-link-{case}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Dir(dir)
    }

    fn live(&self) -> PathBuf {
        self.0.join("live")
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The fjall store in `live`: opening it again while a first one lives there fails with
/// `Locked`, which is the failure these cases look for.
fn opened(live: &Path, when: &str) -> Arc<dyn DataStore> {
    match BackendStore::open_fjall(live) {
        Ok(store) => Arc::new(store),
        Err(e) => panic!("{when}, the store directory does not open again: {e}"),
    }
}

fn public() -> Share {
    Share {
        readers: Readers::Anyone,
        writers: Vec::new(),
    }
}

/// A device with a space, its links started and the natural host over them, is closed and let go:
/// its directory store opens again at once, and a device started over it holds the space.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closed_device_with_the_natural_host_releases_its_store_directory() {
    let dir = Dir::new("reopen");
    let alice = Person::new("/alice").await;
    let ann = embedded_on(
        &alice,
        ANN,
        Setup::inviter(),
        opened(&dir.live(), "at the first start"),
    )
    .await;
    ann.node.create(&n(FOLDER), public()).await.unwrap();
    ann.close().await;

    let again = embedded_on(
        &alice,
        ANN,
        Setup::inviter(),
        opened(&dir.live(), "after the device was closed and let go"),
    )
    .await;
    assert!(
        again.node.space(&n(FOLDER)).is_some(),
        "the device started over the directory does not hold the space it had"
    );
    again.close().await;
    drop(opened(&dir.live(), "after the second run was closed"));
}

/// The same with a person invited: the device has made an offer, admitted Bob, and holds the grant
/// it made (the invitations follow the space the grant is about).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closed_inviter_with_a_grant_releases_its_store_directory() {
    let dir = Dir::new("reopen-grant");
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let ann = embedded_on(
        &alice,
        ANN,
        Setup::inviter(),
        opened(&dir.live(), "at the first start"),
    )
    .await;
    let bob = embedded(&bobs, "/bob/member/phone", Setup::dialer()).await;
    answers_probes(&ann);
    answers_probes(&bob);
    invited(&ann, &bob, Role::Writer).await;
    assert_eq!(ann.links.grants().len(), 1, "{:#?}", ann.links.grants());
    ann.close().await;
    bob.close().await;

    drop(opened(
        &dir.live(),
        "after the inviter, who holds a grant, was closed and let go",
    ));
}

/// ndf's configuration: the links remember in the node's own store (`DeviceMemory` over
/// `node.store()`), so the links hold the store too, and the host, which holds the hints, lives
/// on after the device is closed (the invitations hold it until they are let go). The directory
/// opens again at once while the host lives: the hints are no owner of the links.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_outlives_its_device_does_not_hold_the_store_through_the_links() {
    let dir = Dir::new("reopen-memory");
    let alice = Person::new("/alice").await;
    let ann = embedded_on(
        &alice,
        ANN,
        Setup::inviter(),
        opened(&dir.live(), "at the first start"),
    )
    .await;
    ann.links.remember(
        ndn_link::DeviceMemory::new(Arc::clone(ann.node.store())),
        ndn_link::MemoryOptions {
            include_local: true,
            ..ndn_link::MemoryOptions::default()
        },
    );
    ann.node.create(&n(FOLDER), public()).await.unwrap();
    let host = ann.close_keeping_hints().await;

    drop(opened(
        &dir.live(),
        "after the device whose links remember in its store was closed, the host still alive",
    ));
    drop(host);
}

/// The hints a host holds are no owner of the links: a host that outlives its device's links
/// (the invitations hold the host, the node's judge holds it as its adopter) does not keep them,
/// their socket or what they hold (a remembered memory's store) alive. With the links gone the
/// hints fail closed and say why.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hints_a_host_still_holds_do_not_keep_the_closed_devices_links_alive() {
    let alice = Person::new("/alice").await;
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    assert!(
        ann.hints.hint().is_some(),
        "a device that listens has a link hint while it runs"
    );
    let hints = ann.close_keeping_hints().await;

    assert!(
        hints.hint().is_none(),
        "the hints a host still holds answer a link hint after the device's links were closed \
         and let go: they keep the links, their socket and what they hold alive"
    );
    let refused = hints
        .dial_first(
            &n("/bob/member/phone"),
            "127.0.0.1:9".parse().unwrap(),
            std::time::Duration::from_millis(200),
        )
        .await
        .expect_err("a dial over links that are gone must refuse");
    assert!(
        refused.contains("links are closed") && refused.contains("start the links again"),
        "the refusal does not say why or what to do: {refused}"
    );
}
