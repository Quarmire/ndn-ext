# The Named-Data Radio, explained without the jargon

*A ten-minute on-ramp. Read this first; the other docs assume you already have the picture below.*

## The one idea

Normal radios work like the postal system: every device has an **address**, and something in
charge — a Wi-Fi access point, a cell tower — decides who gets to talk and when. Take away the thing
in charge and normal radios mostly stop working.

This radio throws out the address and puts the **name of the data** in charge instead. You don't ask
for "the device at address X"; you ask for a named thing — `/sensor/roof/temp/42`. And here is the
whole trick: **the name, plus a clock everyone shares, is enough for every device to compute the same
answers to every coordination question — with nobody in charge.** No access point, no scheduler, no
setup messages. Each device does the same arithmetic on the same name and lands on the same plan.

An analogy: imagine a potluck where the *guest list* is the only thing everyone shares. From that one
list, every guest independently works out the same seating chart, the same order of who serves when,
and which table each dish goes on — so the dinner runs itself, with no host directing traffic. Here
the "guest list" is the set of data names, the "clock" is a shared sense of time, and the arithmetic
is a hash of the name. Same inputs in, same plan out, everywhere.

## The four questions a radio has to answer

Any medium-access design has to answer four questions. This one answers all four *from the name*:

1. **Who/what may I bother to receive?** (the filter) — Every frame carries a tiny fingerprint of its
   name in a few header bytes. A receiver checks that fingerprint against the handful of name-prefixes
   it cares about and ignores everything else *without decoding the packet*. The fingerprint can only
   ever say "maybe yours" or "definitely not yours" — it never hides a packet you wanted.

2. **When may I transmit?** (the slot) — Time is chopped into slots. Each name "owns" one slot,
   computed as `hash(name)` mod (number of slots). In your slot you transmit; outside it you wait. No
   one hands out slots — the name *is* the slot assignment. If a slot's owner is silent, others may
   politely contend for it via a tiny name-keyed lottery so it isn't wasted.

3. **Where in the spectrum?** (the channel) — Same trick: `hash(name)` mod (number of channels) picks
   the channel, optionally rotating over time. Two devices that both want the same named data compute
   the same channel and meet there — no channel-negotiation handshake.

4. **How carefully?** (rate & coding) — How fast to transmit, and how much redundancy to add so a lossy
   link still delivers, is chosen *per name* from what the name says it needs (an alarm is treated
   differently from a bulk file) and from what the radio has measured about the link.

Notice the shape: **the name answers who, when, where, and how-carefully — and every device computes
the same answer, so they coordinate without ever talking about coordination.** That's the entire
design in one sentence.

## Follow one packet

You have a temperature reading to publish as `/sensor/roof/temp/42`.

1. Your radio hashes the name and works out: *this name owns slot 3, on channel 5.*
2. It waits for the shared clock to reach slot 3 on channel 5.
3. When slot 3 arrives and there's room before the slot ends, it transmits — stamping a few bytes of
   the name's fingerprint into the frame header.
4. A neighbour hears it. Before decoding anything, it checks the fingerprint against its own list of
   interests. `/sensor/roof/` is on its list → it keeps the frame. `/lights/` isn't → it would have
   dropped it, cheaply.
5. If the link is weak, your radio may have added redundancy so the reading survives a lost frame.

No address was used. No one scheduled slot 3. No one assigned channel 5. Nobody announced anything.

## What's actually proven (so you know what to trust)

This project has a strict rule: *measure, don't assert.* So the honest status is mixed, and that's on
purpose:

- **Measured on real radios, on air:** the name filter (zero wanted-packets dropped over 100k+
  frames), the per-name redundancy, the slot timing, and the shared-slot collision fix (below).
- **Simulated, not yet flown:** some multi-radio and fast channel-hopping behaviour.
- The docs distinguish these everywhere. If a claim isn't marked "on air," treat it as a hypothesis.

One worked example of the discipline: the slot rule promises "collision-free," but two *different*
names can hash to the *same* slot once there are more active names than slots. On air, that made two
senders collide invisibly. The fix — when a device detects another name is sharing its slot, it runs a
tiny within-slot backoff to take turns — was built, and the on-air run then caught **two** bugs the
lab test couldn't. That loop (promise → measure → find the gap → fix → measure again) is the method.

## Jargon decoder

The other docs use short names for these ideas. Here is every one you'll trip over, in one line each:

| You'll see | It means | Everyday version |
|---|---|---|
| **name / named data** | the identifier of a piece of content, like `/a/b/c` | a file path, not an IP address |
| **facet** | one of the four questions (who/when/where/how-well) | a chapter of the design |
| **Tier-0 / the Blur / prefix-set filter** | the name-fingerprint in the frame header | "is this maybe for me?" in a few bytes |
| **Bloom filter** | a bit-trick that answers set-membership with "maybe" or "no", never a false "no" | a bouncer's guest-list check that can wave in a gate-crasher but never turns away a real guest |
| **GCS** | the same fingerprint packed smaller, for tiny radios | a zip file of the fingerprint |
| **false positive / false negative** | "maybe-yours but wasn't" / "was yours but dropped" — the second is forbidden | a wrong bounce-in (tolerable) vs a wrong bounce-out (never) |
| **slot / token** | your computed turn to transmit in time | your reserved minute on a shared microphone |
| **owner** | the name whose hash lands on a given slot | whoever the seating-chart put in that seat |
| **claim** | using an idle owner's slot so it isn't wasted | taking an empty seat until its owner shows up |
| **shared-slot backoff** | taking turns when two names accidentally share a slot | two people reaching for the mic, one waits |
| **CCLF** | the tiny name-keyed lottery that orders contenders for an idle slot | drawing straws, but computed from the name |
| **common-view clock** | the shared sense of time every device agrees on | everyone's watches synced |
| **ephemeral ID / nonce** | a throwaway per-message tag standing in for "who sent it" | a numbered coat-check ticket, not your name |
| **SchedParams** | the handful of settings every device must agree on for the slot map to line up | the rules of the game, printed on every scorecard |
| **medium-keyed** | folding the channel into the slot math so different channels get different schedules | different rooms run on different clocks |
| **lease / guard band** | a name holds several slots; a safety gap so a frame never spills into the next slot | booking a block of time, with a buffer so you finish before the next act |
| **cognition** | the sense→decide→act loop that picks rate/coding/channel per name | the radio's "read the room and choose" layer |

## Where to go deeper (only after this)

- Each of the four questions has a full chapter: `name-filter-chapter.md`, `temporal-access-chapter.md`,
  `spectrum-multiradio-chapter.md`, `link-adaptation-chapter.md`.
- Why the design is the way it is, and proof the problems are real: `mac-design-roots.md`.
- How the four fit into one protocol, with the on-air ledger: `mac-synthesis.md`.
- The exact bytes on the air: `wire-format-spec.md`.

If a term in those docs isn't in the table above, it's built from the ideas that are.
