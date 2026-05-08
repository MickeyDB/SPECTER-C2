# Module Validation Matrix

Date: 2026-05-04

This matrix tracks defensive quality coverage for implant modules. It intentionally separates build/unit coverage from operational end-to-end validation. Do not treat a module as operationally validated unless an approved lab run explicitly exercises that module through the implant tasking path and records evidence.

## Current Status

| Module | Artifact | Build | Server/unit coverage | Implant module smoke | Service-SCM callback-tick evidence | End-to-end feature validation | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `collect` | `implant/build/modules/collect.bin` | PASS | Safe-failure coverage, module repository coverage | PASS via safe unsupported-subcommand task | Not run | Safe-failure loader path only | Loader/task safe smoke covered |
| `exfil` | `implant/build/modules/exfil.bin` | PASS | Safe-failure coverage, module repository coverage | PASS via safe unsupported-subcommand task | Not run | Safe-failure loader path only | Loader/task safe smoke covered |
| `inject` | `implant/build/modules/inject.bin` | PASS | Safe-failure coverage, module repository coverage | PASS via safe unsupported-subcommand task | Not run | Safe-failure loader path only | Loader/task safe smoke covered |
| `lateral` | `implant/build/modules/lateral.bin` | PASS | Safe-failure coverage, module repository coverage | PASS via safe unsupported-subcommand task | Not run | Safe-failure loader path only | Loader/task safe smoke covered |
| `smoke` | `implant/build/modules/smoke.bin` | PASS | Module repository coverage only | PASS via no-op task | Not run | No-op module only | Loader/task smoke covered |
| `socks5` | `implant/build/modules/socks5.bin` | PASS | Safe-failure coverage; `crates/specter-server/tests/socks_tests.rs` covers relay manager lifecycle and wire-format basics | PASS via `status` task | Not run | Control/status only; no relay traffic | Loader/task smoke covered |
| `template` | `implant/build/modules/template.bin` | PASS | Module repository coverage only | PASS in memory-scanner evidence windows; PASS via safe unsupported-subcommand task | PASS in service-SCM module/post-cleanup evidence | Template task only | Validated harness can load one simple module |
| `token` | `implant/build/modules/token.bin` | PASS | Safe-failure coverage, module repository coverage | PASS via safe unsupported-subcommand task | Not run | Safe-failure loader path only | Loader/task safe smoke covered |

## Latest Non-Operational Audit

- Command: `.\scripts\module-validation-audit.ps1`
- Report: `target/local-evidence/module-validation-audit-20260504-071641.md`
- Result: PASS
- Scope:
  - builds module artifacts,
  - records module sizes and SHA256 hashes,
  - runs SOCKS manager tests,
  - runs module repository tests.
- Boundaries:
  - does not exercise real implant module execution,
  - does not exercise SOCKS5 pivot traffic,
  - does not validate stealth or evasion behavior,
  - does not close ETW-TI/EDR gates.

## Shared Argument Hardening

- Hardened: `implant/modules/include/module.h`
- Test: `implant/tests/test_module_args.c`
- Result: PASS, `64/64`
- Coverage added:
  - `module_parse_args` rejects a null output pointer,
  - parsing uses overflow-safe length checks,
  - `module_args_begin` rejects null buffers and counts above `MODULE_MAX_ARGS`,
  - `module_args_append` rejects null buffers and nonzero-length null data,
  - string/int/bytes/wide-string accessors reject null argument contexts,
  - string accessors reject unterminated `ARG_TYPE_STRING`,
  - wide-string accessors reject unterminated or odd-length `ARG_TYPE_WSTRING`.

## Lifecycle And Bounds Hardening

- Hardened: `implant/modules/socks5/socks5.c`
- Test: `implant/tests/test_socks5_safe_fail.c`
- Result: PASS, `24/24`
- Coverage added:
  - `send_msg` rejects payloads above `MAX_CHUNK_SIZE` before stack-buffer sizing,
  - inbound SOCKS wire-message parsing uses overflow-safe `payload_len` checks,
  - inbox loop uses subtraction-based bounds checks before computing message totals,
  - `start` fails cleanly when required bus callbacks are absent,
  - `start` treats zero throttle as the default and clamps extreme throttle values,
  - synthetic inbox stop message exits the `start` loop cleanly,
  - stop-path test asserts no network connect is attempted.

- Hardened: `implant/modules/collect/collect.c`
- Coverage added:
  - screenshot interval is clamped to `SCREENSHOT_MAX_INTERVAL` before converting seconds to milliseconds.

- Hardened: `implant/modules/exfil/exfil.c`
- Test: `implant/tests/test_exfil_safe_fail.c`
- Result: PASS, `12/12`
- Coverage added:
  - malformed, missing, unterminated, and unknown subcommands fail safely,
  - `file` and `directory` subcommands fail before file enumeration when required exports cannot resolve,
  - chunk count calculation avoids addition overflow,
  - throttle argument is clamped before inter-chunk waits.

- Hardened: `implant/modules/token/token.c`
- Test: `implant/tests/test_token_safe_fail.c`
- Result: PASS, `12/12`
- Coverage added:
  - malformed, missing, unterminated, and unknown subcommands fail safely,
  - `steal`, `make`, `revert`, and `list` reject incomplete bus callback tables before dereferencing them.

- Hardened: `implant/modules/inject/inject.c`
- Test: `implant/tests/test_inject_safe_fail.c`
- Result: PASS, `12/12`
- Coverage added:
  - malformed, missing, unterminated, and unknown subcommands fail safely,
  - `createthread`, `apc`, `hijack`, and `stomp` reject incomplete bus callback tables before target-process interaction.

- Hardened: `implant/modules/lateral/lateral.c`
- Test: `implant/tests/test_lateral_safe_fail.c`
- Result: PASS, `12/12`
- Coverage added:
  - malformed, missing, unterminated, and unknown subcommands fail safely,
  - `wmi`, `scm`, `dcom`, and `schtask` fail before remote interaction when required exports cannot resolve.

## Latest Static Audit

- Command: `.\scripts\module-static-audit.ps1`
- Report: `target/local-evidence/module-static-audit-20260504-071641.md`
- Result: PASS
- Notable review flags:
  - `collect` and `socks5` contain long loops; non-operational lifecycle/bounds coverage has started, but end-to-end module execution remains unvalidated.
  - `collect`, `exfil`, and `token` show allocation/free count mismatches in static inventory; this is not automatically a leak, but each mismatch should remain explainable in review.
  - `inject`, `lateral`, and `token` now have non-operational safe-failure coverage, but still touch sensitive process/token/control surfaces and should stay outside promotion decisions until feature-specific tests and approved lab evidence exist.

## SOCKS5 Validation Boundary

SOCKS5 now has a real loader/task smoke for the non-relay `status` path.

- Script: `scripts/socks5-module-loader-smoke.ps1`
- Report: `target/local-evidence/socks5-module-loader-smoke-20260504-063640.md`
- Result: PASS
- Scope:
  - builds a barebone module-capable implant,
  - stores and packages `implant/build/modules/socks5.bin`,
  - queues a real `module_load` task with args `status`,
  - observes session registration, module task completion, and module cleanup.
- Boundaries:
  - no SOCKS listener is opened,
  - no proxy data relay is exercised,
  - no target endpoint connection is attempted.

The server-side `SocksManager` tests cover listener lifecycle, duplicate relay rejection, stop behavior, no-op routing for unknown sessions, and the basic wire-message layout. The remaining SOCKS gap is controlled lab validation of connect, data relay, close, and cleanup behavior.

Before claiming SOCKS5 feature validation, an approved lab plan must define:

- test environment and authorization,
- expected traffic shape,
- allowed target endpoint,
- success criteria for connect, data relay, close, and cleanup,
- telemetry collection boundaries,
- rollback and cleanup.

## Module Loader Safe-Smoke Boundary

The first module-loader matrix smoke now covers the larger non-SOCKS modules without exercising their operational behavior.

- Script: `scripts/module-loader-safe-smoke.ps1`
- Reports:
  - `target/local-evidence/module-loader-safe-smoke-20260504-064937.md`
  - `target/local-evidence/module-loader-safe-smoke-20260504-071524.md`
- Result: PASS
- Modules:
  - `exfil`: PASS, result bytes `25`
  - `token`: PASS, result bytes `25`
  - `inject`: PASS, result bytes `26`
  - `lateral`: PASS, result bytes `27`
  - `collect`: PASS, result bytes `27`
  - `template`: PASS, result bytes `28`
  - `smoke`: PASS, result bytes `0`
- Scope:
  - builds a barebone module-capable implant,
  - stores and packages each module artifact,
  - queues real `module_load` tasks with args `__specter_safe_smoke__`,
  - observes session registration, task completion, module output, and cleanup.
- Boundaries:
  - unsupported subcommands return before capture, file collection, credential/token operations, process injection, or remote-control behavior,
  - `smoke` is a no-op module and intentionally returns no output,
  - no target endpoint, process target, credential material, listener, relay, or lateral remote host is used.

This run exposed a real task-delivery envelope issue: `inject` and `lateral` packages were larger than the old fixed HTTP response receive cap. The implant now separates low-level socket receive chunking (`COMMS_RECV_BUF_SIZE`) from full HTTP response buffering (`COMMS_RESPONSE_MAX_SIZE`) so larger signed module packages can be delivered through the local tasking path.

## Next Safe Work

1. Keep `template` as the memory-scanner lifecycle sentinel.
2. Add approved lab plans for SOCKS relay validation and any other operational module validation, with authorization and telemetry scope.
3. Keep ETW-TI/EDR validation last because it depends on environment-specific providers and tooling.
