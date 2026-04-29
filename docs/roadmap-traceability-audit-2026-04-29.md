# Roadmap Traceability Audit - 2026-04-29

This audit maps the roadmap to implementation and evidence so we can distinguish "implemented", "reviewed", and "proven in the lab". It is intentionally conservative: local smoke tests count as evidence for a specific path, not for every deployment or operator workflow.

## Summary

The roadmap is directionally complete for the current project goals, but static-review completeness is uneven. The core beacon path, payload builder basics, local profile transport, and Phase 2 memory telemetry have strong evidence. Redirector deployment, module streaming, Web UI parity, reporting, release packaging, and production key persistence still need dedicated review passes before the roadmap can be called complete.

The most important architecture gap is now clear: "barebone first, stream functionality as needed" is the right direction, but the module streaming path is not yet proven as the dominant delivery model. Phase 2 memory work should feed into that architecture instead of becoming a standalone module-overload polishing track.

## Traceability Matrix

| Subsystem | Intended capability | Current implementation | Static review status | Dynamic evidence | Remaining gap | Roadmap phase |
| --- | --- | --- | --- | --- | --- | --- |
| Beacon check-in core | Register, poll, fetch tasks, return results over encrypted HTTP | Implant `comms.c`, server listener/check-in paths, shared TLV parsing | Strong for local legacy/profile paths; duplicated listener paths still tracked as architecture debt | Listener-aligned PIC smoke, large-output smoke, Windows dir smoke, profile smoke | Centralize all check-in flows through shared processor and keep WS/profile parity tested | Phase 0/1 |
| Large result handling | Avoid crash/truncation and surface oversized results explicitly | 4 MiB plaintext cap, heap-backed buffers, explicit failed oversized nested results | Strong | `pic-large-output-smoke.ps1`, listener tests for large task results | Chunked file/results framing for larger transfers | Phase 1/3 |
| Payload builder | Build configured raw/PE payloads with listener keys, config TLVs, build/evasion flags, layout metadata | Rust builder, config generation, template-dir support, map-derived layout metadata | Medium-strong for raw local path; full output-format matrix not fully audited | Builder tests, `pic-listener-smoke`, marker scan, layout-metadata scanner evidence | Full review of PE/DLL/service/.NET formats, release artifact roots, gRPC/Web parity, proto generation discipline | Phase 0/4/5 |
| Malleable profiles | Shape HTTP URI/headers/transforms while preserving shared plaintext TLV semantics | Profile schema/compiler, implant profile bridge, listener profile handling | Medium | `pic-profile-smoke.ps1`, `pic-profile-redirector-soak.ps1`, profile tests | Grammar/edge-case review, transform failure behavior, UI editor parity, redirector-specific profile validation | Phase 1/5 |
| Redirectors/deployment | Local/cloud redirectors route traffic without breaking profile semantics; deployment paths are reproducible | Local redirector smoke, Azure guide/pattern, Docker config paths | Partial | Local redirector/profile soak | Static review Azure/AWS/Cloudflare paths, release/container packaging, domain rotation evidence, production secrets story | Phase 4 |
| Module bus and streaming | Keep initial PIC small and stream nonessential capability as modules | Module bus, module repository, modules for socks/token/lateral/inject/exfil/collect/template | Partial; modules exist but architecture is not yet proven as the primary functionality delivery path | Module build evidence, some module tests | End-to-end module upload/execute/result tests, Web UI module UX, signing/versioning, OPSEC labels, default-kit inventory | Phase 3 |
| Barebone implant split | Minimal resident stage with required beacon/tasking; stream the rest | `SPECTER_BAREBONE`, size baseline, barebone smoke | Medium | Barebone size baseline and listener smoke | Memory scanner evidence for barebone, explicit stage contract, state separation plan, module streaming proof | Phase 2/3 |
| Evasion memory telemetry | Measure memory posture with scanner evidence before adopting techniques | Sysmon, Moneta, PE-sieve, HollowsHunter harnesses; module-overload variants | Strong for local lab measurements; not EDR/kern ETW complete | Multiple Phase 2 scanner reports, sleep-state and patch-only canaries | Barebone comparison, kernel ETW-TI/EDR stack not proven, decide module-overload default status | Phase 2 |
| Syscall/evasion controls | Indirect syscall/gadget behavior, optional user-mode patches, honest limits | Syscall wrappers, gadget scan logic, ETW path present but not called by default | Medium | Static telemetry script, Sysmon scoped baseline, hash audit | Gadget distribution tests, ETW patch gating/proto/Web parity, kernel telemetry limits documented per operator guide | Phase 2 |
| File transfer/tasking | Built-in upload/download and shell/task execution without crashes | Inline upload/download, shell tasking, task result paths | Medium | Large shell output, Windows dir smoke, server task tests | Chunked >1 MiB transfers, Web native file picker/save-as parity, module-bus transfer design | Phase 3 |
| Web UI operator flows | Builder/session/profile/redirector/module/report workflows usable end to end | React UI, gRPC-Web, session terminal, payload builder, redirector/profile pages | Partial | UI data-path validation doc, web type/build/lint/test evidence from regression runs | Full workflow review for modules, reports, upload/download, profile editor, builder evasion flags/proto regeneration | Phase 5 |
| Persistence/release packaging | Restart-safe keys/artifacts and predictable Docker/release behavior | Per-listener keys in DB, configurable template-dir, Docker artifact path | Partial | Payload artifact root hardening evidence | CA key persistence, module signing key persistence, session recovery, release gate naming | Phase 4/5 |
| Documentation and operator guidance | Accurate docs that state evidence and limits | Roadmap, evasion playbook, OPSEC review, memory layout contract, deployment docs | Medium | Docs updated alongside evidence runs | Refresh deployment/operator/developer guides and keep traceability matrix current | All phases |

## Static Review Completeness

- Complete enough for local evidence: beacon check-in, large output, raw payload builder, local profile path, local memory telemetry harness.
- Partially complete: redirector deployment, malleable profile edge cases, module bus/streaming, Web UI parity, payload output-format matrix, persistence/release packaging.
- Not complete: full production deployment review across cloud redirectors, full module-streaming architecture proof, full report-generation workflow, real EDR/kernel ETW-TI validation.

## Roadmap Adjustments

- Keep Phase 2.3 open, but narrow the immediate question to full-vs-barebone memory posture and modified-backed-image footprint.
- Promote Phase 2.5 plus Phase 3.4 as the strategic architecture track: smaller resident PIC, clearer stage contract, streamed modules for nonessential functionality.
- Treat module overloading as experimental/lab-only unless barebone evidence shows a material scanner improvement or a later design removes the large modified-image footprint.
- Add a recurring traceability rule: every roadmap item should eventually have at least one static-review note and one dynamic evidence artifact, or be explicitly marked research/deferred.

## Next Evidence Batch

Barebone memory evidence was captured with:

- baseline barebone loader mapping
- split-protect barebone
- patch-only barebone module-overload canary

Results:

- Initial pure barebone configured payload: `69968` bytes, beacon smoke PASS, but PE-sieve/HollowsHunter still report `implanted_shc = 1`.
- Initial barebone split-protect failed before scan because mutable `.data` started inside page 0, producing an invalid page split offset.
- Linker layout was corrected to collect `.text$*` function sections before data and align `.data` to a 4 KiB boundary.
- Page-aligned barebone configured payload: `71857` bytes, beacon smoke PASS, split-protect PASS with RW offset `0x8000`, but PE-sieve/HollowsHunter still report `implanted_shc = 1`.
- Page-aligned barebone patch-only module-overload: configured payload `76059` bytes, `urlmon.dll` patch footprint is `3860` bytes, but PE-sieve/HollowsHunter still report `implanted_shc = 1`.

Decision impact: size reduction and page-level RX/RW state separation are strategically correct and now compatible, but module overloading should remain experimental/lab-only until backed execution/staging or a transient restore/remap design removes the scanner-visible private-code and modified-image footprints.

## Step 5 Decision

The next prototype is documented in `docs/phase2-next-strategy.md`: build a `BAREBONE_MODULES=1` resident-stage proof that keeps the page-aligned barebone split and adds only enough module package loading to execute one streamed PIC module. This tests the project architecture goal directly: small resident stage first, streamed functionality as needed.

Module overloading remains lab-only. Sleep-remap/restoration work is deferred until the module-streaming architecture has an end-to-end proof and scanner baseline.
