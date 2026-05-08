# Resident-First Memory Layout Hardening Plan

Source of truth mirror for editor accessibility (copied from internal plan file).

## Goal
Build a smaller, less noisy resident implant stage first (`BAREBONE_MODULES=1` path), validate measurable memory-telemetry improvements, and only then decide whether to invest in sleep remap/module stomping complexity.

## Current Architecture Anchors
- Implant bootstrap and evasion entry points: [`implant/core/src/entry.c`](c:/Users/localuser/Documents/SPECTER-C2/implant/core/src/entry.c), [`implant/core/src/evasion/modoverload.c`](c:/Users/localuser/Documents/SPECTER-C2/implant/core/src/evasion/modoverload.c), [`implant/core/src/evasion/ntcontinue_entry.c`](c:/Users/localuser/Documents/SPECTER-C2/implant/core/src/evasion/ntcontinue_entry.c), [`implant/core/src/sleep.c`](c:/Users/localuser/Documents/SPECTER-C2/implant/core/src/sleep.c)
- Module lifecycle/load path: [`implant/core/src/bus/loader.c`](c:/Users/localuser/Documents/SPECTER-C2/implant/core/src/bus/loader.c), [`implant/core/src/bus/lifecycle.c`](c:/Users/localuser/Documents/SPECTER-C2/implant/core/src/bus/lifecycle.c)
- Server config/TLV delivery path: [`crates/specter-server/src/builder/config_gen.rs`](c:/Users/localuser/Documents/SPECTER-C2/crates/specter-server/src/builder/config_gen.rs), [`implant/core/src/config.c`](c:/Users/localuser/Documents/SPECTER-C2/implant/core/src/config.c)
- Existing decision/evidence baseline: [`docs/phase2-memory-layout-contract.md`](c:/Users/localuser/Documents/SPECTER-C2/docs/phase2-memory-layout-contract.md), [`docs/phase2-next-strategy.md`](c:/Users/localuser/Documents/SPECTER-C2/docs/phase2-next-strategy.md), [`scripts/phase2-memory-scanner-evidence.ps1`](c:/Users/localuser/Documents/SPECTER-C2/scripts/phase2-memory-scanner-evidence.ps1)

## Implementation Phases

### Phase 1: Define resident-stage contract (no risky behavior changes)
- Formalize what stays resident vs streamed in docs and build knobs (resident comms/beacon core only).
- Make compile-time selection the source of truth for resident image contents (`SPECTER_BAREBONE` / `SPECTER_BAREBONE_MODULES`); treat runtime TLV as policy/metadata only.
- Add explicit lab-only gating knobs (builder/profile plus optional config TLV metadata) for resident-minimal mode; default OFF.
- Preserve backward compatibility by making new runtime fields additive and optional.

### Phase 2: Implement `BAREBONE_MODULES` runtime path
- Keep only the minimal module loader/lifecycle surface resident in `BAREBONE_MODULES`; keep streamed module payload code, optional COFF support, and advanced evasion overlays out of the resident image until explicitly streamed or compiled in.
- Keep current module-overload + `.pdata` + NtContinue behaviors as optional overlays, not prerequisites.
- Harden cleanup path so streamed module memory is zeroed/released deterministically after execution.
- Fix shutdown guard symmetry in [`implant/core/src/entry.c`](c:/Users/localuser/Documents/SPECTER-C2/implant/core/src/entry.c): if `SPECTER_BAREBONE_MODULES` initializes bus/guardian/modmgr, `implant_cleanup()` must also run their shutdown path under the same condition.

### Phase 3: Evidence harness alignment and guardrails
- Extend scanner harness to enforce three collection windows with explicit script semantics (not prose only):
  - Resident-only window: scan before module dispatch (`-ScanAfterFirstCheckin` with module smoke disabled).
  - Module-active window: dispatch module (`-ModuleSmoke`) and scan after the dispatch marker; use a long-running module or `-ScanDelayMs` tuning when true active-execution coverage is required.
  - Post-cleanup window: require proof of cleanup completion before scan (task result drained + `modmgr_poll()` cleanup cycle completed + `modmgr_cleanup_generation()` advanced, then optional `-HoldAfterTaskCompleteMs` before scan).
- Implement either three separate named runs (recommended for clean artifacts) or one multi-window run that emits clearly labeled outputs per window.
- Use `scripts/phase2-memory-scanner-evidence.ps1 -EvidenceWindow resident-only|module-active|post-cleanup` for window-tagged single-run artifacts.
- Capture size and telemetry deltas as release criteria (memory scanner + Sysmon + size baseline).
- Add fail/rollback gates: if module-active or post-cleanup footprint regresses beyond threshold, keep feature lab-only.
- Add config-size budget gate before adding resident-minimal TLVs: assert decrypted config remains within parser limits, or ship a safe decrypt-buffer resizing change first.

### Phase 4: Promote to controlled opt-in (still conservative)
- Expose feature to operators as explicit profile/builder opt-in with warning text in docs.
- Keep aggressive remap-on-sleep and module stomping deferred until resident-minimal gains plateau.
- Reassess with fresh evidence before investing in callstack/sleep-remap complexity.

## Acceptance Checklist (Pass/Fail)

### Phase 1 acceptance (contract and gating)
- Pass when all are true:
  - Resident content contract is documented with compile-time source of truth (`SPECTER_BAREBONE` / `SPECTER_BAREBONE_MODULES`) and TLV scope limited to runtime policy/metadata.
  - Lab-gated knobs default OFF in builder/profile surfaces.
  - Backward-compatibility note confirms additive-only runtime fields and no required config-version bump.
- Fail if any are true:
  - Plan relies on runtime TLV to remove resident code.
  - New knobs are enabled by default without lab-only guardrails.

### Phase 2 acceptance (runtime and cleanup correctness)
- Pass when all are true:
  - `SPECTER_BAREBONE_MODULES` path keeps post-exploitation module payloads, optional COFF support, and advanced evasion overlays out of the resident stage until explicit stream/load or compile-time opt-in; only the minimal loader/lifecycle surface remains resident as required.
  - Init/cleanup guard symmetry is implemented in `implant/core/src/entry.c` (if module lifecycle is initialized, shutdown path runs).
  - Streamed module cleanup proves deterministic wipe/release on completion.
- Fail if any are true:
  - Barebone-with-modules can initialize module state and skip cleanup at shutdown.
  - Completed modules can remain resident without deterministic cleanup path.

### Phase 3 acceptance (evidence harness and synchronization)
- Pass when all are true:
  - Evidence collection includes three explicit windows: resident-only, module-active, and post-cleanup/sleep.
  - Post-cleanup window has hard synchronization proof (result drain + `modmgr_poll()` cleanup completion + `modmgr_cleanup_generation()` advancing) before scan.
  - Artifacts are clearly labeled by window (either three runs or one multi-window run with labeled outputs).
  - Regression gates are enforced for scanner, Sysmon, and size deltas.
- Fail if any are true:
  - Post-cleanup scan can run before cleanup completion.
  - Window labels are ambiguous or not attributable to specific runtime states.

### Phase 4 acceptance (controlled opt-in promotion)
- Pass when all are true:
  - Feature remains lab-only until evidence gates pass.
  - Operator-facing opt-in is explicit and documented with risk notes.
  - Deferred items (sleep remap, deeper callstack shaping, expanded stomping) remain out of default path.
- Fail if any are true:
  - Feature is promoted without meeting Phase 3 gates.
  - Deferred evasion work becomes default behavior before resident-first goals are met.

### Cross-phase release gates
- Config size safety gate:
  - Pass: config decrypt-size budget test passes under current/additive TLV load, or safe buffer-sizing update ships first.
  - Fail: additive fields can exceed parser/decrypt limits without deterministic failure handling.
- Compatibility gate:
  - Pass: old implants tolerate new TLVs (ignore unknown) and new implants preserve behavior when fields absent.
  - Fail: additive rollout causes behavior changes in absence of new fields.
- Evidence reproducibility gate:
  - Pass: each run stores window-tagged outputs and command parameters sufficient to reproduce.
  - Fail: artifacts cannot be traced to exact run mode/window.

## Remaining Evasion Implementation Plan

### Scope
This implementation plan covers only the evasion work that remains open on the roadmap after the resident-module-streaming proof:
- syscall gadget-rotation validation quality
- resident-stage memory/callstack signal investigation
- evidence-gated decision on remap-on-sleep investment
- continued lab-only posture for risky techniques until gates pass

### Workstream A: Syscall gadget-rotation validation (Phase 2.2 completion)
- Objective: prove gadget rotation is functioning as intended and not collapsing to low diversity.
- Target files:
  - [`implant/core/src/syscalls.c`](c:/Users/localuser/Documents/SPECTER-C2/implant/core/src/syscalls.c)
  - [`scripts/phase2-telemetry-evidence.ps1`](c:/Users/localuser/Documents/SPECTER-C2/scripts/phase2-telemetry-evidence.ps1)
- Deliverables:
  - Lab evidence run that reports gadget diversity distribution across syscall families.
  - Regression test(s) asserting distinct syscall paths prefer distinct gadgets where expected.
  - Failure mode note for low-entropy fallback behavior.
- Exit criteria:
  - Diversity metrics are stable across repeated runs in the same lab profile.
  - Tests fail on forced single-gadget regression.

### Workstream B: Resident-stage dominant signal reduction (Phase 2.3 remaining)
- Objective: isolate and reduce persistent scanner-visible resident signal (private executable mapping/callstack integrity).
- Target files:
  - [`implant/core/src/entry.c`](c:/Users/localuser/Documents/SPECTER-C2/implant/core/src/entry.c)
  - [`implant/core/src/evasion/stackspoof.c`](c:/Users/localuser/Documents/SPECTER-C2/implant/core/src/evasion/stackspoof.c)
  - [`implant/core/src/evasion/ntcontinue_entry.c`](c:/Users/localuser/Documents/SPECTER-C2/implant/core/src/evasion/ntcontinue_entry.c)
  - [`implant/core/src/evasion/modoverload.c`](c:/Users/localuser/Documents/SPECTER-C2/implant/core/src/evasion/modoverload.c) (lab-only variants)
  - [`scripts/phase2-memory-scanner-evidence.ps1`](c:/Users/localuser/Documents/SPECTER-C2/scripts/phase2-memory-scanner-evidence.ps1)
- Deliverables:
  - Explicit A/B evidence sets for resident-before-module, module-active, and post-cleanup windows.
  - Root-cause attribution report for what still triggers `implanted_shc = 1` in resident windows.
  - At least one candidate mitigation with reproducible telemetry delta, or a documented null result.

### Workstream C: Remap-on-sleep research decision gate
- Objective: decide whether to implement remap-on-sleep next, based on evidence rather than intuition.
- Deliverables:
  - Decision memo: `implement now` or `defer`, with risk/benefit and rollback implications.
  - If `implement now`, a lab-only prototype scope with strict non-goals and kill-switches.

#### Astral-informed feasibility checklist
- External reference model:
  - [Astral Projection: Advanced Module Stomping](https://kuwaitist.github.io/posts/Astral-Projection/)
  - [KuwaitiSt/Astral_Projection](https://github.com/KuwaitiSt/Astral_Projection)
- Required primitives to prove in SPECTER before coding:
  - Safe section-handle lifecycle control for sacrificial image views.
  - Stable sleep-mask choreography for unmap/remap and protection transitions.
  - Crash-safe interaction with unwind/callstack handling during wake/sleep transitions.
  - Explicit rollback path that restores current baseline behavior on any remap failure.
- Lab-only constraints:
  - Feature flag default OFF.
  - Kill-switch path must short-circuit to existing sleep behavior in one branch decision.
  - No operator-default enablement until all evidence gates pass.
- Minimum measurable success thresholds (must all pass):
  - Resident-before-module window shows a reproducible reduction in dominant scanner signal versus current baseline.
  - Post-cleanup/sleep window improves without increasing modified-backed-image findings.
  - No regression in smoke stability, task completion, or cleanup synchronization checks.
- Null-result/abort criteria:
  - If remap-on-sleep does not produce reliable scanner delta across repeated runs, close as null result and defer.
  - If complexity increases instability or artifact volume, revert to baseline and keep the branch lab-only.

#### Research freshness rules for Workstream C
- Pin scanner versions in every evidence artifact batch (PE-sieve, HollowsHunter, Moneta tooling revision).
- Re-run one baseline and one remap candidate on the same host snapshot before claiming deltas.
- Refresh external references quarterly or when a major scanner release changes thread/callstack heuristics.

### Execution sequence
1. Complete Workstream A first (low-risk validation).
2. Run Workstream B with strict three-window labeling and synchronization checks.
3. Use B outputs to execute Workstream C decision gate.
4. Update roadmap + traceability evidence only after each gate passes.

### Timeboxed milestones
- Milestone 1 (2-3 days): gadget validation closeout.
- Milestone 2 (4-6 days): resident signal attribution.
- Milestone 3 (1-2 days): remap decision memo.

## Init-to-Sleep Stack Hygiene Plan (New Attribution Branch)

### Trigger for this branch
- Evidence from [`target/local-evidence/resident-memory-window-summary-20260430.md`](c:/Users/localuser/Documents/SPECTER-C2/target/local-evidence/resident-memory-window-summary-20260430.md) indicates:
  - benign private-PIC controls are clean,
  - static SPECTER bytes in private memory are clean when entry is patched to spin,
  - pure barebone still triggers callstack/call-integrity findings,
  - suspicious location resolves near `cfg_init+0xdd` during `NtDelayExecution`.
- Working hypothesis: dominant signal is init-to-sleep runtime callstack residue from resident initialization, not module residue and not private-memory existence alone.

### Objective
- Reduce or eliminate resident-window `SUS_CALLSTACK_SHC` / `SUS_CALLS_INTEGRITY` by hardening the init-to-sleep transition and validating stack hygiene effects before any remap-on-sleep investment.

### Phase A: Precision attribution instrumentation (1-2 days)
- Scope:
  - [`implant/core/src/entry.c`](c:/Users/localuser/Documents/SPECTER-C2/implant/core/src/entry.c)
  - [`implant/core/src/config.c`](c:/Users/localuser/Documents/SPECTER-C2/implant/core/src/config.c)
  - [`implant/core/src/sleep.c`](c:/Users/localuser/Documents/SPECTER-C2/implant/core/src/sleep.c)
  - [`scripts/phase2-memory-scanner-evidence.ps1`](c:/Users/localuser/Documents/SPECTER-C2/scripts/phase2-memory-scanner-evidence.ps1)
- Tasks:
  - Add lab-gated markers around `cfg_init -> comms setup -> first sleep` boundaries to correlate scanner hit windows with exact transition points.
  - Add run metadata that records whether the first sleep follows direct return path, context transfer path, or alternate stack path.
  - Extend script outputs to include explicit `init_done`, `first_checkin_done`, `sleep_entered` stamps.
  - Record scanner `susp_addr`, resolved PIC offset/symbol, thread state/wait reason/last syscall, protection/module size, payload hash, and map file used for symbol resolution.
- Exit criteria:
  - Every suspicious scan can be mapped to a specific transition boundary and symbolized against the exact build artifact.
  - No ambiguity about whether signal originates pre-sleep or during sleep wait.
  - Phase B cannot start until repeated Phase A runs confirm the finding consistently lands in the init-to-sleep boundary.

### Phase B: Stack-hygiene candidate implementations (3-5 days)
- Candidate 1: deterministic transition to clean execution context (preferred first candidate if Phase A confirms the hypothesis)
  - Route into sleep path via controlled context-transfer path (existing `NtContinue`-style primitives where appropriate) to avoid carrying bootstrap frame residue.
- Candidate 2: call-integrity-friendly frame shaping at first sleep boundary
  - Ensure unwind/return chain posture at `NtDelayExecution` reflects expected benign transition structure.
- Candidate 3: bounded init stack hygiene experiment (highest-risk candidate)
  - Lab-only experiment to sanitize transient init frame artifacts no longer needed after runtime bootstrap.
  - Requires safe stack-bound discovery, proof that active return/unwind/SEH/VEH state is untouched, and immediate fallback on any validation failure.
- Scope:
  - [`implant/core/src/entry.c`](c:/Users/localuser/Documents/SPECTER-C2/implant/core/src/entry.c)
  - [`implant/core/src/evasion/ntcontinue_entry.c`](c:/Users/localuser/Documents/SPECTER-C2/implant/core/src/evasion/ntcontinue_entry.c)
  - [`implant/core/src/evasion/stackspoof.c`](c:/Users/localuser/Documents/SPECTER-C2/implant/core/src/evasion/stackspoof.c)
  - [`implant/core/src/sleep.c`](c:/Users/localuser/Documents/SPECTER-C2/implant/core/src/sleep.c)
- Guardrails:
  - Feature-flag all changes; default OFF.
  - Preserve current functional behavior and fallback immediately on transition failure.
  - Do not implement Candidate 3 until Candidate 1/2 results are known or Phase A proves a specific scrub-safe target.

### Phase C: A/B evidence matrix and gating (2-3 days)
- Required runs (same host snapshot and tool versions):
  - Baseline pure barebone resident-only, repeated at least 3 times.
  - Candidate 1 ON, others OFF, repeated at least 3 times.
  - Candidate 2 ON, others OFF, repeated at least 3 times.
  - Candidate 3 ON, others OFF, repeated at least 3 times only if its guardrails are satisfied.
  - Best pair combination (if single candidates help).
- Success criteria:
  - Resident-window reduction in `implanted_shc`, thread dump `is_shellcode`, `SUS_CALLSTACK_SHC`, and/or `SUS_CALLS_INTEGRITY` with stable repeatability.
  - No increase in `modified` findings or new crash instability.
  - No regression in suspicious protection, HollowsHunter suspicious count, smoke stability, or result path correctness.
- Fail criteria:
  - No reliable scanner delta across repeated runs.
  - Instability, race regressions, or artifact migration to worse categories.

### Decision gate after Phase C
- If stack-hygiene branch yields reliable improvement:
  - Promote the best candidate to primary Phase 2.3 follow-on (still lab-gated).
- If no reliable improvement:
  - Document null result and then evaluate remap-on-sleep branch using existing Astral-informed feasibility checklist.

### Deliverables
- Updated evidence pack with per-run transition stamps and scanner deltas.
- Short attribution memo: “init-to-sleep residue confirmed/refuted” with selected next branch.
- Roadmap note updating 2.3 status from broad investigation to stack-transition-focused findings.

## Off-Thread Wait Branch Plan (Post-2026-04-30 Evidence)

### Why this is the next branch
- New evidence in [`target/local-evidence/resident-memory-window-summary-20260430.md`](c:/Users/localuser/Documents/SPECTER-C2/target/local-evidence/resident-memory-window-summary-20260430.md) shows:
  - `CLEAN_SLEEP_ENTRY=1` is a null result for scanner outcome.
  - `BENIGN_SLEEP=1` removes `SUS_CALLS_INTEGRITY` but leaves `SUS_CALLSTACK_SHC` / `implanted_shc = 1`.
  - Dominant remaining signal is the sleeping thread call chain still containing resident private PIC frames.
- Decision: prioritize off-thread/callback-based waiting over additional init-stack scrubbing or immediate remap-on-sleep.

### Scope and constraints
- Keep already-proven hygiene work in scope:
  - `BAREBONE_MODULES` init/cleanup guard symmetry.
  - Post-cleanup synchronization (`modmgr_cleanup_generation()` and scan gating).
  - Config decrypt budget and builder-side budget checks.
- Keep all new behavior lab-only and OFF by default.
- Do not treat `BENIGN_SLEEP=1` as final; treat it as a baseline-improving subcomponent.

### Phase D1: Build off-thread wait candidate (2-4 days)
- Primary target: move blocked wait posture to a thread/callback path where the observed waiting stack is Windows-backed, not resident-PIC-backed.
- Candidate implementations (ordered):
  1. Timer queue callback wait path.
  2. Threadpool timer/work item wait path.
  3. Dedicated helper thread + callback dispatch path.
- Files:
  - [`implant/core/src/sleep.c`](c:/Users/localuser/Documents/SPECTER-C2/implant/core/src/sleep.c)
  - [`implant/core/src/entry.c`](c:/Users/localuser/Documents/SPECTER-C2/implant/core/src/entry.c)
  - [`implant/core/src/unity.c`](c:/Users/localuser/Documents/SPECTER-C2/implant/core/src/unity.c)
  - [`implant/Makefile`](c:/Users/localuser/Documents/SPECTER-C2/implant/Makefile)
- Build knobs:
  - Keep `BENIGN_SLEEP` and `CLEAN_SLEEP_ENTRY`.
  - Add one new lab-only knob for off-thread wait candidate (single feature gate; default OFF).

### Phase D2: Harness and evidence updates (1-2 days)
- Files:
  - [`scripts/phase2-memory-scanner-evidence.ps1`](c:/Users/localuser/Documents/SPECTER-C2/scripts/phase2-memory-scanner-evidence.ps1)
- Add script switches to toggle:
  - baseline direct sleep,
  - benign sleep,
  - off-thread wait candidate,
  - combined modes where relevant.
- Require report metadata fields:
  - selected sleep mode,
  - calling path (`direct_simple`, `benign_sleep`, `off_thread_wait`),
  - first-sleep boundary timestamps.

### Phase D3: A/B matrix and decision gate (2-3 days)
- Required resident-only runs on same host snapshot:
  - Baseline (`direct_simple`)
  - `CLEAN_SLEEP_ENTRY=1`
  - `BENIGN_SLEEP=1`
  - Off-thread wait only
  - Off-thread wait + benign sleep
  - Off-thread wait + clean entry + benign sleep
- Success criteria:
  - `SUS_CALLSTACK_SHC` materially reduced or cleared in repeated runs.
  - `implanted_shc` reduced without introducing new modified-image/private-memory regressions.
  - No stability regressions (smoke checks, check-in cadence, tasking behavior).
- Failure criteria:
  - `SUS_CALLSTACK_SHC` persists across repeated runs with no measurable delta.
  - New suspicious categories increase (e.g., modified image artifacts or unstable call paths).

### Decision outcomes
- If D3 succeeds:
  - Promote off-thread wait candidate as primary lab mitigation branch for Phase 2.3.
  - Keep remap-on-sleep deferred.
- If D3 is null:
  - Close branch as null result and proceed to remap-on-sleep feasibility branch (existing Astral-informed checklist).

### Validation checklist for this branch
- Parser/lint and build validation:
  - PowerShell parser check for evidence script passes.
  - `make DEV=1 BAREBONE=1` variants with relevant lab knobs pass.
  - `git diff --check` clean except acknowledged line-ending warnings.
- Evidence references to retain in branch notes:
  - `phase2-memory-scanner-resident-only-evidence-20260430-043711.md`
  - `phase2-memory-scanner-resident-only-evidence-20260430-043949.md`
  - `phase2-memory-scanner-resident-only-evidence-20260430-044046.md`
  - `phase2-memory-scanner-resident-only-evidence-20260430-050318.md`

## Builder-Equivalent Evidence Pivot (Post Off-Thread Null Result)

### Why pivot now
- The fixed off-thread-only run (`phase2-memory-scanner-resident-only-evidence-20260430-050318.md`) proved the lab marker can truthfully report `path=off_thread_wait`, but PE-sieve still reported:
  - `SUS_CALLSTACK_SHC`
  - `implanted_shc = 1`
  - resident private PIC frame in the scanned waiting stack
- Continuing the raw `pic_loader.exe` off-thread matrix risks optimizing a lab-only load shape.
- Production/operator flow goes through the builder output and its config/transform/finalization path, so scanner conclusions about resident layout should be gated on builder-equivalent evidence before deeper sleep-path work.

### Concrete next steps
1. Freeze the current off-thread wait branch as a raw-harness null result.
   - Keep `OFFTHREAD_WAIT=1` lab-only and OFF by default.
   - Do not spend more time on `OFFTHREAD_WAIT + BENIGN_SLEEP` or `OFFTHREAD_WAIT + CLEAN_SLEEP_ENTRY` in the raw harness until builder-equivalent scans exist.
   - Record the 2026-04-30 05:03 run as the evidence boundary for this branch.

2. Add a builder-equivalent evidence mode to `scripts/phase2-memory-scanner-evidence.ps1`.
   - New switch: `-BuilderEquivalent` or a new script with the same report schema if that is cleaner.
   - Build or obtain the payload through the same server-side builder path used for operator output.
   - Preserve the existing report fields: payload SHA256, loader PID, markers, scanner summaries, raw scan root.
   - Add explicit fields:
     - `Artifact source: raw_pic|builder_equivalent`
     - `Builder transform enabled: True/False`
     - `Builder config blob size`
     - `Builder output SHA256`

3. Run a minimum paired comparison on the same host snapshot.
   - Raw PIC baseline: current resident-only harness, no off-thread wait.
   - Builder-equivalent baseline: same implant behavior, builder-produced artifact.
   - Builder-equivalent with the best known hygiene knobs that are actually supported by builder output.
   - Optional only after the above: builder-equivalent off-thread wait, if the build knob can be represented in that flow.

4. Decision gate after paired comparison.
   - If builder-equivalent output clears or materially changes `implanted_shc` / `SUS_CALLSTACK_SHC`, prioritize builder/loader transform work and stop optimizing raw-loader callstacks.
   - If builder-equivalent output still shows the same waiting-stack resident PIC signal, resume runtime mitigation work with timer queue or threadpool callback gating instead of the current helper-thread fire-and-return path.
   - If builder-equivalent output introduces new modified-image/private-memory findings, treat that as a builder transform regression and investigate before sleep-path work.

5. Update the evidence summary.
   - Add a `Raw PIC vs Builder Equivalent` table to `target/local-evidence/resident-memory-window-summary-20260430.md`.
   - Include at least: artifact source, payload SHA256, marker sleep path, PE-sieve modified regions, `implanted_shc`, thread indicators, wait reason, suspicious protection, HollowsHunter count.
   - Mark the off-thread helper-thread candidate as null in raw harness unless builder-equivalent evidence proves otherwise.

### Immediate command targets
- Re-run raw baseline only if a fresh comparison is needed:
  - `.\scripts\phase2-memory-scanner-evidence.ps1 -Barebone -LoaderSplitProtect -LoaderRwOffset 0x8000 -EvidenceWindow resident-only -ScanAfterFirstCheckin`
- Builder-equivalent target to add:
  - `.\scripts\phase2-memory-scanner-evidence.ps1 -BuilderEquivalent -LoaderSplitProtect -LoaderRwOffset 0x8000 -EvidenceWindow resident-only -ScanAfterFirstCheckin`

## Callback Tick Promotion Notes (2026-04-30)

### Implemented lab evidence path
- `CALLBACK_TICK=1` schedules the resident loop through a one-shot timer queue callback and returns the initial resident PIC entry thread after initialization.
- `pic_loader --detach-thread` keeps the harness process alive from loader-owned code while the callback path owns subsequent ticks.
- The evidence script automatically enables loader detach for `-LabCallbackTick`, labels resident-only/module-active/post-cleanup windows, and records callback markers plus builder-equivalent metadata.

### Evidence outcome
- Resident-only callback tick runs cleared PE-sieve modified/private-shellcode findings and HollowsHunter suspicious counts in repeated runs.
- Builder-equivalent raw output with callback tick also cleared those scanner fields, so the previous raw-vs-builder concern is closed for this candidate.
- Module-active and post-cleanup windows stayed clean when the RW split offset was derived from the `BAREBONE_MODULES` map (`0xb000` on the 2026-04-30 build). The forced legacy `0x8000` offset crashed before session registration and is not valid for that build flavor.

### 2026-05-08 barebone-modules baseline
- Clean `BAREBONE=1 BAREBONE_MODULES=1` build produced a 125,784-byte PIC and a 126,170-byte configured raw payload, still above the 20 KiB target but materially smaller than the full DEV PIC.
- The template module load/execute/result path passed with `result_bytes=4` and `beacon_checkins=3` in `manual-barebone-modules-raw-module`.
- Scanner windows without callback-tick/split-stack lab overlays remained visible:
  - resident-only: `phase2-memory-scanner-resident-only-evidence-20260508-050045.md`
  - module-active: `phase2-memory-scanner-module-active-evidence-20260508-050151.md`
  - post-cleanup: `phase2-memory-scanner-post-cleanup-evidence-20260508-045932.md`
- The earlier `phase2-memory-scanner-module-active-evidence-20260508-050110.md` run raced process exit and has unknown PE-sieve fields; use the later held run above for scanner posture.

### Production stub bridge
- PE template stubs now have an opt-in `DETACHED_HOLD=1` build mode.
- In that mode, the stub allocates/copies the PIC as before, starts the PIC entry on a detached host-created thread, and keeps the process/service alive from stub-owned code.
- Service stubs use a stop-aware host loop; EXE and DLL stubs use a host-owned hold path.
- The first EXE stub hold attempt used `Sleep(INFINITE)` in the original stub thread and still produced `SUS_CALLSTACK_SHC`; PE-sieve saw a private PIC address under the host `SleepEx` chain.
- The native EXE stub now uses a host-owned fresh-stack wait for the detached-hold path. The previous tail-sleep experiment was too brittle and crashed before registration; the fresh-stack wait keeps a real blocking wait while removing the original setup stack as confounding residue.
- PE-template resident-only evidence now passes repeatedly with `CALLBACK_TICK=1`, `DETACHED_HOLD=1`, builder transforms enabled, and `Artifact format: dotnet`:
  - `phase2-memory-scanner-resident-only-evidence-20260430-060705.md`
  - `phase2-memory-scanner-resident-only-evidence-20260430-060750.md`
  - `phase2-memory-scanner-resident-only-evidence-20260430-061316.md`
- PE-template module windows also pass with `BAREBONE_MODULES`, `CALLBACK_TICK=1`, `DETACHED_HOLD=1`, builder transforms enabled, and `Artifact format: dotnet`:
  - `phase2-memory-scanner-module-active-evidence-20260430-061357.md`
  - `phase2-memory-scanner-post-cleanup-evidence-20260430-061908.md`
- Service-format direct fallback now uses the same fresh-stack detached holder and also passes the PE-template matrix:
  - `phase2-memory-scanner-resident-only-evidence-20260430-062214.md`
  - `phase2-memory-scanner-module-active-evidence-20260430-062250.md`
  - `phase2-memory-scanner-post-cleanup-evidence-20260430-062310.md`
- True SCM-managed service launch now passes the same scanner gate after the service stub explicitly resolves/loads `advapi32.dll` before service registration:
  - `phase2-memory-scanner-resident-only-evidence-20260430-073814.md`
  - `phase2-memory-scanner-module-active-evidence-20260430-073853.md`
  - `phase2-memory-scanner-post-cleanup-evidence-20260430-073906.md`
- The evidence harness now has an explicit minimum beacon-checkin gate before scan, which turns dwell checks into a measured condition rather than a blind sleep:
  - resident-only SCM dwell: `phase2-memory-scanner-resident-only-evidence-20260430-074627.md` (`12` observed beacon check-ins)
  - post-cleanup SCM dwell: `phase2-memory-scanner-post-cleanup-evidence-20260430-074941.md` (module complete, cleanup observed, `6` observed beacon check-ins)
- `scripts/phase2-memory-scanner-soak.ps1` now wraps the evidence harness for repeat service-SCM dwell runs and writes an aggregate pass/fail table.
- Short service-SCM soak gate passed on 2026-04-30:
  - resident-only: `phase2-memory-scanner-soak-resident-only-20260430-084114.md` (`2/2` clean, `13` and `12` check-ins)
  - post-cleanup: `phase2-memory-scanner-soak-post-cleanup-20260430-083901.md` (`2/2` clean, module dispatch and cleanup observed in both runs)
- Broader service-SCM dwell gate also passed after separating the scan delay from the smoke-process lifetime:
  - resident-only: `phase2-memory-scanner-soak-resident-only-20260430-132041.md` (`3/3` clean, `18`, `18`, and `19` check-ins)
  - post-cleanup: `phase2-memory-scanner-soak-post-cleanup-20260430-133648.md` produced `2/3` clean scanner-attached runs (`31` and `32` check-ins); the third failed before scan because the module task returned failed status.
  - replacement post-cleanup: `phase2-memory-scanner-soak-post-cleanup-20260430-134902.md` (`1/1` clean, module dispatch and cleanup observed, `32` check-ins)
  - Net broader post-cleanup scanner-attached evidence: `3` clean runs, PE-sieve modified `0`, PE-sieve implanted shellcode `0`, HollowsHunter suspicious `0`.
- `scripts/phase2-service-scm-telemetry-evidence.ps1` now captures local event-log telemetry around the promoted service-SCM lab shape.
- Resident-only service-SCM telemetry capture passed on 2026-04-30:
  - `phase2-service-scm-telemetry-evidence-20260430-135459.md`
  - evidence run: `phase2-service-scm-telemetry-run-resident-only-20260430-135459.md`
  - smoke `PASS`, `12` beacon check-ins, PE-sieve modified `0`, PE-sieve implanted shellcode `0`, HollowsHunter suspicious `0`
  - local logs available: Sysmon, Defender Operational, Security-Mitigations, System, Application
  - `Microsoft-Windows-Threat-Intelligence/Operational` is not present on this host, so this run records a local telemetry baseline but does not close the ETW-TI gate.
- Builder/profile UX now has an explicit lab intent path:
  - `implant/build/specter.features` records whether the PIC was built with `CALLBACK_TICK=1`.
  - `implant/build/stub.features` records whether PE stubs were built with `DETACHED_HOLD=1`.
  - `specter-build --lab-callback-tick-detached-holder` refuses to build unless those manifests prove the templates match the requested lab mode.
  - Profiles can declare `lab.resident_wait.callback_tick` plus `lab.resident_wait.detached_holder`; validation rejects detached holder without callback tick and emits a lab-only warning when callback tick is requested.
  - `GeneratePayloadRequest.lab.callback_tick_detached_holder` carries the same intent through gRPC/Web builds, and the server applies the same manifest validation before building.
  - The Web Payload Builder exposes this under Lab Builds and only sends it for PE-template formats.
- These PE-template runs report:
  - PE-sieve modified regions: `0`
  - PE-sieve implanted shellcode findings: `0`
  - HollowsHunter suspicious process count: `0`
- SCM cleanup was verified after the run (`SpecterSvc` no longer installed).

### Roadmap Order From Here

1. Local hardening and maintainability, next:
   - Keep `CALLBACK_TICK + DETACHED_HOLD` lab-gated and off by default.
   - Add/maintain focused tests around manifest validation, profile validation, gRPC request validation, and Web Payload Builder lab intent.
   - Use `docs/module-validation-matrix.md` and `scripts/module-validation-audit.ps1` to keep module build/unit coverage separate from operational feature validation.
   - Preserve the repeatable service-SCM evidence commands as regression checks for future stub/builder changes.
   - Clean up superseded/null lab branches only after the callback-tick path is stable in review.

2. Documentation and operator UX, next:
   - Document the lab-only option, required build manifests, supported PE-template formats, and current evidence boundaries.
   - Keep SOCKS5 and other real modules marked as not end-to-end validated until an approved lab plan records feature-specific evidence.
   - Make the UI/API copy explicit that this is an opt-in lab posture, not a default implant behavior.
   - Keep the memory-scanner evidence pack linked from roadmap and operator docs.

3. Final external-validation gate, last:
   - Run `scripts/phase2-service-scm-telemetry-evidence.ps1` under a host/sensor stack with ETW-TI or the target EDR product enabled.
   - Treat this as last because it depends on environment access, sensor licensing/configuration, and collection policy outside this repo.
   - Do not block local code cleanup, tests, or docs on this gate.
   - Do not promote beyond explicit lab opt-in until this external gate is complete.
