# Evasion Playbook

## Purpose

Operational guidance for selecting and validating evasion techniques with a stability-first, OPSEC-first posture.

## Default posture

- Use balanced defaults in production.
- Keep aggressive techniques **opt-in** until they pass soak validation in your lab.
- Prefer deterministic behavior over opaque runtime mutation.
- **User-mode ETW patch** (`EVASION_FLAG_ETW_USERMODE_PATCH` / builder “ETW user-mode patch”) is **off** by default and does **not** defeat kernel ETW-TI.

## Technique matrix (honest scope)

| Technique | Helps against (typical) | Does **not** defeat |
|-----------|-------------------------|---------------------|
| **User-mode ETW patch** (`evasion_patch_etw` — `EtwEventWrite` in ntdll) | Some user-mode ETW consumers, naive AMSI-adjacent telemetry that relies on patched usermode paths | **Kernel** ETW-TI, minifilter callbacks, kernel APCs, modern EDR kernel sensors (MDE, CrowdStrike, SentinelOne, etc.) |
| **Indirect syscalls** | User-mode hooks on ntdll syscall stubs | Kernel stack/callback telemetry, hypervisor-assisted inspection |
| **Sleep encryption / advanced sleep** | Point-in-time memory scans **during** sleep windows | Pre-sleep execution, thread context inspection, kernel memory access, timing anomalies |
| **Stack spoofing** (where implemented) | Trivial user-mode stack walks | Full kernel stack traces, ETW stack events with kernel frames, careful unwind with `.pdata` |
| **Module overloading** (file-backed image) | “Unbacked executable memory” heuristics vs naive scanners | Compare-on-disk vs in-memory image, kernel-backed inspection, behavioral correlation |

This table is **not** exhaustive; vendors differ. Validate against **your** target stack.

## Memory masking and module remap guidance

Module-backed execution can reduce one narrow signal: executable memory that is obviously private and unbacked. It does not make the region clean. A defender can still compare mapped image contents to disk, inspect working-set sharing, inspect PEB loader entries, walk stacks, and correlate behavior.

Research such as Astral Projection is useful because it highlights the tradeoff: remapping a clean sacrificial module during sleep can improve point-in-time memory snapshots, but it also introduces new observable behavior around map/unmap cadence, exception handling, loader metadata, and unwind correctness.

For SPECTER, treat this as a Phase 2 lab question:

- First validate the existing `evasion_module_overload` RW -> copy -> RX behavior.
- Confirm `.pdata` registration allows clean unwind through implant frames.
- Record memory state while awake and while sleeping.
- Only then decide whether a remap-on-sleep design is worth the extra complexity.

## Sleep technique guidance

- `SLEEP_DELAY`: safest baseline; lowest crash risk.
- `SLEEP_WFS`: moderate stealth, moderate complexity.
- `SLEEP_EKKO` / `SLEEP_FOLIAGE` / `SLEEP_THREADPOOL`: advanced techniques; only enable after lab validation for target OS/build.

### Failure and fallback policy

- If an advanced sleep method fails at runtime, beacon must fall back to `SLEEP_DELAY`.
- Cryptographic integrity failures remain fail-closed.
- Profile transform failures remain operational fail-safe to legacy baseline comms.

## Operator validation checklist

1. Confirm stable callback cadence over at least 5 consecutive cycles.
2. Run low-noise command set (`whoami`, `pwd`, `sleep`) and verify task/result continuity.
3. Validate session metadata consistency (`sleep_interval`, `sleep_jitter`, status).
4. Confirm no unexplained process exits under chosen sleep method.
5. If **ETW user-mode patch** is enabled: confirm in lab that behavior matches expectations and that you still assume **kernel telemetry is visible** to mature EDR.
6. If **module overloading** is enabled: capture memory evidence before sleep, during sleep, and after wake; record whether executable regions are private or image-backed and whether the backing image contents differ from disk.

## Rollback procedure

- Disable advanced sleep method and redeploy with `SLEEP_DELAY`.
- Disable profile-driven comms and use legacy baseline if transform failures appear.
- Disable **ETW user-mode patch** in payload builder and redeploy if instability or unexpected host telemetry appears.
- Re-run callback continuity checks before re-enabling advanced options.
