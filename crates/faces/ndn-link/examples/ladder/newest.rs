//! `/ndf/merge/newest/v=1`, the merge rule of the space the ladder's put->watch runs in: the same
//! one ndf's ladder uses, so the two ladders put the same bytes through the same rule. A path
//! holds the bytes of its newest version; a version supersedes every version in its past; the
//! state is the head with the highest digest. The value is `by ‖ bytes`, `by` the 32-byte hash
//! of the writer's person (the second component of its `/user/<0xA1 hash>` namespace).

use std::collections::BTreeSet;

use bytes::Bytes;
use ndn_data::{
    Counting, MergeError, MergeRule, MergeState, Name, Op, OpKind, Value, VersionId, Writer,
};

/// The type of the component that holds a person's key hash in `/user/<hash>`.
pub const PERSON: u64 = 0xA1;

/// The rule's name, as the members record of the space spells it.
pub const NEWEST: &str = "/ndf/merge/newest/v=1";

pub struct Newest(Name);

impl Newest {
    pub fn new() -> Self {
        Newest(NEWEST.parse().expect("the rule's name is an NDN name"))
    }
}

impl MergeRule for Newest {
    fn function(&self) -> &Name {
        &self.0
    }

    fn start(&self, _collection: &Name, _local: &Writer) -> Box<dyn MergeState> {
        Box::new(Heads(Vec::new()))
    }
}

struct Head {
    id: VersionId,
    digest: [u8; 32],
    value: Bytes,
}

struct Heads(Vec<Head>);

fn person_of(id: &VersionId) -> [u8; 32] {
    id.writer
        .key()
        .components()
        .get(1)
        .filter(|c| c.typ == PERSON)
        .and_then(|c| c.value[..].try_into().ok())
        .unwrap_or_default()
}

impl MergeState for Heads {
    fn check(&self, _op: &Op<'_>) -> Result<OpKind, MergeError> {
        Ok(OpKind::Edit)
    }

    fn apply(&mut self, op: &Op<'_>) -> Result<Counting, MergeError> {
        if self.0.iter().all(|h| h.id != *op.id) {
            self.0.retain(|h| !op.past.contains(&h.id));
            let mut value = person_of(op.id).to_vec();
            value.extend_from_slice(op.bytes);
            self.0.push(Head {
                id: op.id.clone(),
                digest: *op.digest,
                value: value.into(),
            });
        }
        Ok(Counting::Counted)
    }

    fn value(&self, excluded: &BTreeSet<VersionId>) -> Value {
        let winner = self
            .0
            .iter()
            .filter(|h| !excluded.contains(&h.id))
            .max_by_key(|h| h.digest);
        Value::Rule(winner.map(|h| h.value.clone()).unwrap_or_default())
    }
}
