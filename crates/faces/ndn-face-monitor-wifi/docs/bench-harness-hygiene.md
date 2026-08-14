# Bench-harness hygiene — read before any multi-node on-air/fleet experiment

**Why this exists (2026-08-14):** a ~2-day "8812au sustained-RX hardware wedge" investigation —
complete with theories about USB RX-DMA aggregation, power amplifiers, an FNB-58 power meter and a
USB analyzer — turned out to be **three self-inflicted bench-state bugs in the test harness**. No
hardware was ever wrong. The dongle repeatedly called "broken/degraded" heard 2181 frames on a
clean open the instant the leftover process was killed. This checklist is the antidote; it is
cheaper than the 2 days.

## The core failure mode

**A frozen or repeating on-air result is the harness lying, not the world talking.** Identical
counts across "different" runs — especially an identical random value (a nonce, a seed, a
timestamp) — means the run did not execute and you are reading a stale file. Treat repetition as a
red flag, never as reproducibility.

## The five bugs, each with its fix

1. **`pkill -f <toolname>` self-kills the harness.** `-f` matches the *full command line*, and the
   harness's own remote shell has `<toolname>` in its argv (the path you're launching). It kills its
   own chain before the run starts.
   → Use **`pkill -x <exact-process-name>`** (matches the process *name*, not the shell cmdline).
   Verify: `pgrep -x <name>` should list the binary, not your `bash`/`ssh`.

2. **Leftover processes hold exclusive resources** (a USB device, a port, a lock). The next open
   fights a live handle; the OS may reset the device; you see "0 candidates" / "hears zero" and
   blame hardware.
   → **pkill before AND after every run**, and give the driver a clean shutdown (an `impl Drop` /
   trap that releases the device) so a *normal* exit frees it. SIGKILL skips Drop — that's what the
   pre-run pkill is for.

3. **Stale output files read as fresh results.** If the run silently didn't execute, an old log is
   still there.
   → **Delete the output file before the run** (and check its mtime after). If the file is
   root-owned in sticky `/tmp`, a non-root `rm` **silently fails** — use `sudo rm`.

4. **`env=val timeout N prog` doesn't pass the env.** `timeout` execs `env=val` as a *program* and
   fails; nothing runs (→ bug 3).
   → Put assignments **before** timeout: `VAR=val timeout N prog`, or `timeout N env VAR=val prog`.

5. **A run outliving its window holds the resource into the next run.**
   → Wrap every remote command in **`timeout`** so it can never outlive its window, independent of
   the tool's own timer or a dropped SSH session.

## The freshness guard (build it in, don't rely on discipline)

Make the tool **print a fresh random token at start and end** (the campaign tools print the §2
source nonce). Then:
- start-token identical across two runs ⇒ the run didn't execute; you're reading stale state.
- start-token ≠ end-token ⇒ some run-scoped thing rotated mid-run (e.g. the 5-min nonce); that run
  is instrument-invalid, re-run it.

## The meta-rule

**"Broken hardware" is a claim that requires physical evidence.** Recoverable device/kernel state
you created is not damage — it is a bug in your tooling. Before theorizing about silicon
(aggregation, PAs, power, DMA), **prove the instrument is clean**: kill leftovers, delete stale
files, confirm a fresh token, confirm a clean open works. When results freeze, suspect the harness
first, every time.

Reference implementation: `claim-c-harness.sh` in this directory.
