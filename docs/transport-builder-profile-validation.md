# Transport, Builder, Profile, And Redirector Validation

Date: 2026-05-05

This document tracks the local validation boundary for roadmap items 4 and 5 after module-loader validation.

## Latest Matrices

- Script: `scripts/transport-builder-profile-matrix.ps1`
- Report: `target/local-evidence/transport-builder-profile-matrix-20260508-051223.md`
- Result: PASS
- Runtime scope:
  - local PIC loader,
  - local HTTP listener,
  - local profile listener mode,
  - local reverse-proxy redirector mode.
- External operational traffic exercised: False

- Script: `scripts/wrapper-runtime-matrix.ps1`
- Report: `target/local-evidence/wrapper-runtime-matrix-20260506-111657.md`
- Result: PASS
- Runtime scope:
  - direct PE-template EXE execution,
  - Windows SCM service create/start/task/cleanup path.
- External operational traffic exercised: False

- Script: `scripts/profile-fixture-matrix.ps1`
- Report: `target/local-evidence/profile-fixture-matrix-20260508-042823.md`
- Result: PASS
- Runtime scope:
  - checked-in `profiles/generic-https.yaml`,
  - checked-in `profiles/slack-webhook.yaml`,
  - local profile listener tasking,
  - local reverse-proxy redirector tasking.
- External operational traffic exercised: False

## Covered

| Area | Check | Result | Evidence |
| --- | --- | --- | --- |
| Builder | raw no-obfuscate build and marker scan | PASS | marker scan clean |
| Builder | raw default build and marker scan | PASS | marker scan clean |
| Builder | raw XOR wrapper build and marker scan | PASS | marker scan clean |
| Builder | .NET/EXE wrapper build and integrity check | PASS | build succeeds |
| Builder | service wrapper build and integrity check | PASS | build succeeds |
| Wrapper runtime | .NET/EXE direct runtime smoke | PASS | `result_bytes=27`, `beacon_checkins=3` |
| Wrapper runtime | service SCM runtime smoke | PASS | `result_bytes=28`, `beacon_checkins=3` |
| Runtime transport | raw legacy `/api/beacon` task smoke | PASS | `result_bytes=26`, `beacon_checkins=3` |
| Runtime transport | builder-equivalent raw task smoke | PASS | `result_bytes=26`, `beacon_checkins=3` |
| Runtime transport | profile-enabled default raw task smoke | PASS | `result_bytes=28`, `beacon_checkins=3` |
| Runtime transport | profile-enabled default raw module smoke | PASS | `result_bytes=4`, `beacon_checkins=3` |
| Runtime transport | XOR-wrapped raw task smoke | PASS | `result_bytes=24`, `beacon_checkins=3` |
| Runtime transport | XOR-wrapped raw module smoke | PASS | `result_bytes=4`, `beacon_checkins=3` |
| Operator WebSocket | session command mapper tests | PASS | `cargo test -p specter-server listener::ws_handler::tests` |
| File transfer | large upload chunk planner test | PASS | `cargo test -p specter-client large_upload_queues_ordered_chunks` |
| File transfer | implant chunk task compile check | PASS | `make -C implant clean; make -C implant DEV=1 BAREBONE=1` |
| Profile | transformed profile task smoke | PASS | `result_bytes=27`, `beacon_checkins=3` |
| Redirector | local reverse-proxy profile soak | PASS | `result_bytes=30`, `beacon_checkins=5`, `profile_checkins=5` |
| Profile fixtures | generic HTTPS direct profile task smoke | PASS | `result_bytes=50`, `beacon_checkins=3` |
| Profile fixtures | generic HTTPS local redirector task smoke | PASS | `result_bytes=53`, `beacon_checkins=5`, `profile_checkins=5` |
| Profile fixtures | Slack webhook direct profile task smoke | PASS | `result_bytes=50`, `beacon_checkins=3` |
| Profile fixtures | Slack webhook local redirector task smoke | PASS | `result_bytes=53`, `beacon_checkins=5`, `profile_checkins=5` |
| Wrapper memory | .NET/EXE resident scanner evidence | VISIBLE | `phase2-memory-scanner-resident-only-evidence-20260508-043505.md`: PE-sieve `implanted_shc=1`, HollowsHunter `suspicious_count=1` |
| Wrapper memory | service EXE resident scanner evidence | VISIBLE | `phase2-memory-scanner-resident-only-evidence-20260508-043545.md`: PE-sieve `implanted_shc=1`, HollowsHunter `suspicious_count=1` |
| Wrapper memory | .NET/EXE post-cleanup module scanner evidence | VISIBLE | `phase2-memory-scanner-post-cleanup-evidence-20260508-045517.md`: template module complete with default profile-enabled tasking; PE-sieve `implanted_shc=1`, HollowsHunter `suspicious_count=1` |
| Wrapper memory | service EXE post-cleanup module scanner evidence | VISIBLE | `phase2-memory-scanner-post-cleanup-evidence-20260508-045558.md`: template module complete with default profile-enabled tasking; PE-sieve `implanted_shc=1`, HollowsHunter `suspicious_count=1` |
| Server tests | builder/profile/profile YAML/listener/redirector tests | PASS | cargo integration tests pass |

## Important Finding

The first matrix attempt showed that a profile-enabled payload could register once on legacy `/api/beacon`, queue a task, and then time out because the smoke harness kept serving the legacy-only listener after the implant switched to its configured profile URI. `pic-listener-smoke` now treats any non-`--legacy-only` build as profile-transport enabled and starts the profile-aware router.

This keeps the validation claim precise:

- legacy encrypted `/api/beacon` remains the raw baseline,
- profile HTTP is a transform/profile wrapper around the same tasking path,
- redirector validation is currently a local reverse-proxy path.

The checked-in profile fixture run found and fixed two profile-runtime contract gaps:

- profile embed-point encoding is an additional HTTP embedding layer, so the listener now decodes request embed data before transform decode and applies response embed encoding after transform encode;
- transport-owned request headers such as `Host` and `Content-Length` are suppressed from implant profile headers because the HTTP request builder owns them.

The wrapper post-cleanup scanner runs now use the default profile-enabled tasking path. Earlier legacy-scoped runs also passed (`phase2-memory-scanner-post-cleanup-evidence-20260508-044614.md`, `phase2-memory-scanner-post-cleanup-evidence-20260508-044659.md`), but the current evidence above is the primary claim.

The raw XOR wrapper is now runtime-covered, not only marker-scanned. Validation found two builder issues and fixed them:

- the final payload assembly path accepted `--xor` but did not apply the outer wrapper;
- the handwritten x64 decrypt stub branched one byte early on loop completion, landing on `0xEA` and faulting with `0xc000001d`.

## Boundaries

- PE wrapper formats now have local runtime smoke coverage, including direct EXE execution and SCM service launch.
- PE wrapper formats do not change the current memory scanner posture: both direct EXE and SCM service launches remain visible to PE-sieve/HollowsHunter in resident-only and post-cleanup module scans.
- No cloud redirector deployment is exercised.
- DNS, Azure, SMB, and WebSocket channels are covered by unit/integration tests where present, but not by real implant end-to-end transport smokes here. Operator WebSocket command streaming is locally type-checked and mapper-tested, but still needs a browser-to-implant smoke.
- Chunked file-transfer tasking is implemented for TUI large uploads and implant chunk handlers, but the matrix has not yet captured a real >1 MiB implant upload/download artifact hash.
- This matrix does not validate external infrastructure, domain fronting, certificates, WAF/proxy behavior, or provider-specific routing.

## Next Work

1. Add optional external redirector lab plans with explicit provider, domain, certificate, telemetry, and cleanup boundaries.
2. Keep DNS/Azure/SMB/WebSocket end-to-end transport smokes separate from the local HTTP/profile redirector matrix.
3. Keep wrapper scanner posture work separate from transport correctness: current wrappers execute correctly, but do not improve PE-sieve/HollowsHunter memory findings.
