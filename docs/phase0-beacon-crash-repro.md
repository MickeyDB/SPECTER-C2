# Phase 0.1 — Beacon stability & large-output verification

## Goals

1. Capture or regress **sleep / session metadata** issues (server + implant).
2. **Lab-verify** the implant on real Windows with **small → medium → large** command output (no substitute for a live beacon).
3. Record **caps** that affect what can be exfiltrated in one check-in cycle.

For **profile + redirector** soak (not only direct listener), use **`docs/phase1.3-redirector-validation.md`**.

## Automated regression (CI / dev smoke)

Server-side persistence of sleep results and basic task completion is covered by integration tests. Run locally:

```bash
./scripts/phase01-regression.sh
```

Or manually:

```bash
cargo test -p specter-server --test listener_tests sleep_result_persists
cargo test -p specter-server --test listener_tests task_results_in_checkin
```

Mapping: `sleep_result_persists_and_beacon_remains_live_across_followup_checkins` mirrors **five follow-up check-ins** after a sleep result (`interval=…s jitter=…%`).

## Implant-side ceilings (know what you are testing)

| Limit | Where | Effect |
|-------|--------|--------|
| **Plaintext TLV buffer** | `comms.c` (~4 MiB cap) | Check-in body size upper bound; oversized **nested task results** are **skipped** (`continue`) and may be retried next cycle—not reported as error to the server. |
| **`TRANSFORM_MAX_OUTPUT`** | `implant/core/include/transform.h` (16384) | Profile **transform** path uses buffers bounded by this size; very large plaintext payloads can hit transform/stack or heap fallback behavior—**verify on Windows** with profile enabled. |
| **Per-task design** | e.g. upload/download ~1 MiB | Not a generic shell-output limit; large **shell** output depends on TLV nesting + buffer fit. |

Do **not** mark “large output fixed” until a **real Windows** run shows the expected behavior for your listener mode (legacy JSON vs encrypted beacon vs **profile**).

## Lab verification checklist (Windows target)

Record **implant build profile** (debug vs release) and **listener mode** (JSON `/api/checkin` vs encrypted `/api/beacon` vs profile) in your notes—they can change stack/heap behavior.

Fill in **Actual** and **Pass/Fail** during the run. Use your normal session channel (TUI or Web).

| Step | Command / action | What to check | Actual | Pass/Fail |
|------|------------------|---------------|--------|-----------|
| L1 | `whoami` | Output returns within one callback; session stays Active | | |
| L2 | `sleep 45 20` (or lab-safe values) | After result, **≥ 5** further check-ins; UI shows **sleep interval/jitter** matching command | | |
| L3 | `dir C:\Windows` | Medium directory listing returns without beacon exit | | |
| L4 | `cmd /c type C:\Windows\System32\drivers\etc\hosts` | Multi-KB file content returns (hosts is small; use `services` if larger sample needed) | | |
| L5 | Large output stress | e.g. `cmd /c dir /s /b C:\Windows\System32\*.dll` or generate **>16 KB** stdout | **PASS:** beacon stays alive and operator receives **≥16 KB** of output (may span callbacks or truncate per caps—document which). **FAIL:** process exit, or zero useful output after reasonable wait. | | |

## Original sleep-focused repro (historical)

### Trigger conditions

1. Establish an initial callback and verify at least one successful command task (`whoami`).
2. Queue a `sleep` task with interval and jitter (`sleep 45 20`).
3. Let the implant run through multiple callback cycles while periodically issuing low-noise tasks.

### Failure signature (pre-fix)

- Session eventually stops checking in or transitions to stale/dead unexpectedly.
- Sleep/session metadata drifts from command output.
- Beacon process exits during or after sleep-task processing.

### Minimum repro window

- **5** consecutive check-in cycles after the sleep task result is processed (matches server integration test).

## What only a real Windows run can prove

- Implant **sleep implementation** re-entering `comms_checkin` after real delays.
- **Profile transform** path with large plaintext (not fully represented by JSON `/api/checkin` tests).
- Behavior when a task result **does not fit** the current check-in buffer (silent skip of that nested TLV until a later cycle).

When closing a crash: update this doc with **build id / commit**, listener mode, and whether **profile** was enabled.

## Local Evidence - 2026-04-27

| Step | Command / action | Actual | Pass/Fail |
|------|------------------|--------|-----------|
| L3 | `dir C:\Windows` through encrypted `/api/beacon` from local PIC loader | `.\scripts\pic-windows-dir-smoke.ps1` returned 5,200 bytes for task `400a30e4-ea02-4c3f-a58d-5b2aa106a706`; session `12db3086-3efb-4ce5-89b4-5bb75cb63e13`; no loader crash | PASS |
| L5 | Synthetic large shell output through encrypted `/api/beacon` from local PIC loader | `.\scripts\pic-large-output-smoke.ps1` returned 110,493 bytes for task `9d8aa28d-8d50-480d-8834-a68e534e807b`; session `4342ac57-6aaa-4470-b2d1-4f1129afc8c0`; no loader crash | PASS |
