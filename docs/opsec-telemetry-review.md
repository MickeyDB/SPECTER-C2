# OPSEC Telemetry Review

## Purpose

This review records what the current implant and loader expose to host and network telemetry. It is not a claim of invisibility. The goal is to make evasion decisions evidence-led: each technique must have a known benefit, a known residual signal, and a rollback path.

## Scope

Review the following build profiles separately:

- **Barebone PIC:** `make DEV=1 BAREBONE=1`
- **Full DEV PIC:** `make DEV=1`
- **Profile HTTP build:** generated payload with profile transport enabled
- **Evasion-enabled build:** only one advanced evasion feature enabled at a time

Do not combine multiple new evasion features in the same first-pass lab run. If telemetry changes, isolate which feature caused it.

## Research Notes

The Astral Projection references are useful as a checklist for module-stomping and sleep-mask tradeoffs:

- File-backed image memory can reduce the simple "private executable region" signal, but scanners may still flag modified image sections, shared-original / working-set anomalies, PEB loader-entry inconsistencies, and unwind issues.
- Remapping a clean sacrificial module during sleep changes what point-in-time scanners see, but adds its own behavior: map/unmap cadence, exception/VEH activity, loader-entry manipulation, and extra protection transitions.
- Unwind metadata matters. If executable code lives in a mapped image but stack walking cannot unwind through it cleanly, that becomes a separate signal.
- The approach does not address static signatures, network behavior, process lineage, kernel telemetry, or behavior correlation.

SPECTER already has a simpler module-overloading primitive (`evasion/modoverload.c`) and `.pdata` registration (`evasion/pdata_reg.c`). Phase 2 should first prove what those produce before adopting a more complex remap-on-sleep design.

## Telemetry Sources

Minimum local collection:

- Windows Security log: process creation if enabled, logon context, service/task artifacts
- Sysmon or equivalent: process, network, image load, file, registry, remote thread, and memory-related events where available
- ETW collection for loader/API behavior when available in the lab
- Memory scanner snapshots while awake and while sleeping
- Teamserver and redirector access logs
- Packet capture or proxy logs for callback shape, timing, size, and retry behavior

Useful memory-scan questions:

- Are executable implant regions private or image-backed?
- Are there RWX windows, and how long do they last?
- Do backed image sections differ from the file on disk?
- Do PEB loader entries match the mapped image state?
- Can stack walking unwind through implant frames?
- Does sleep change those answers?

## Review Matrix

| Area | Signal to inspect | Accept / mitigate / defer |
|------|-------------------|----------------------------|
| Loader memory | Private RX/RWX regions, image-backed RX, protection transitions | Accept for barebone baseline; mitigate only with measured module-backed designs |
| Module overloading | Modified image sections, backing-file mismatch, loader-entry consistency | Mitigate only after lab evidence; do not assume file-backed equals clean |
| Sleep | Memory state while awake vs sleeping, callback cadence, timer/APC artifacts | Keep advanced sleep opt-in until stable across repeated cycles |
| Syscalls | Clean ntdll mapping, syscall gadget diversity, stack/callback visibility | Treat as user-mode hook reduction only |
| ETW patching | User-mode patch artifact, failed patch attempts, kernel ETW visibility | Off by default; document user-mode-only scope |
| Network | URI/header profile, payload sizes, jitter distribution, retry pattern | Compare legacy and profile paths separately |
| Process behavior | Parent/child tree, command execution, file access, injection artifacts | Keep feature modules opt-in and label OPSEC cost |

## Required Evidence

For each reviewed build/profile, record:

- Payload SHA256, size, build flags, and profile name
- OS build and telemetry tools used
- Command sequence used for the run
- At least five callback cycles
- One low-noise task result (`whoami` or equivalent)
- One sleep interval change and follow-up callback
- Memory state while awake
- Memory state while sleeping
- Network callback summary
- Findings in this format: `signal -> source -> severity -> decision`

Severity scale:

- **High:** likely mature EDR detection or stability risk
- **Medium:** noticeable signal with situational impact
- **Low:** expected baseline noise or lab-only signal

## Phase 2 Gates

Before enabling a technique by default:

1. It must pass the existing PIC smoke for the selected transport.
2. It must not crash across at least five callback cycles.
3. It must have a telemetry note explaining what it helps and what it does not defeat.
4. It must have a rollback path in `docs/evasion-playbook.md`.
5. If it increases PIC size, the size delta must be recorded.

## Current Recommendation

Keep the default production posture boring:

- barebone or legacy encrypted `/api/beacon` for minimal footprint,
- profile HTTP only when the target traffic model justifies it,
- ETW user-mode patch off by default,
- advanced sleep/module remap experiments behind explicit build/config gates.

The next implementation step is not to add a full Astral-style sleep remapper. It is to build repeatable evidence for SPECTER's current module overloading and `.pdata` behavior, then decide whether a remap-on-sleep design is worth the added VEH/loader-surface complexity.
