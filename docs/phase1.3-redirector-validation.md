# Phase 1.3 — Profile + redirector validation (lab)

Validate that a **profile-bound implant** checks in through a **production-like redirector** while the teamserver sees correct sessions, metadata, and stable callbacks. This is **not** automated in CI; run in an authorized lab.

## References

- Profile examples: `profiles/generic-https.yaml`, `profiles/slack-webhook.yaml`
- Implant bridge: `implant/core/src/entry.c` (profile init + `comms_set_profile`, legacy fallback on failure)
- Server: profile-aware listener (`crates/specter-server/src/listener/mod.rs` — `profile_handler`, binary TLV)
- Stability cross-check: `docs/phase0-beacon-crash-repro.md`

## Lab artifacts

| Piece | Notes |
|--------|--------|
| Teamserver | Built from this repo; HTTP(S) listener matching profile scheme |
| TLS | Redirector or teamserver terminates TLS; implant must trust the chain used in lab |
| Profile YAML | Loaded into teamserver / builder so the **payload** embeds `profile_blob` |
| Redirector | Reverse proxy (nginx, Caddy, cloud edge, or repo Terraform patterns) **in front of** the listener URL the implant calls |
| Payload | Built with **callback URL = redirector**, not raw teamserver IP, when testing redirector path |

## Checklist

Record **date**, **commit**, **profile name**, and **redirector type** before starting.

1. [ ] Teamserver + listener up; health reachable from operator host.
2. [ ] Profile applied on server / embedded in config blob; builder output includes profile when expected.
3. [ ] Redirector routes `Host`, path, and method per profile; upstream points at teamserver listener.
4. [ ] Implant executed; **DEV build**: confirm no `profile_init FAILED` / `comms_set_profile FAILED` trace (or capture failure and confirm intentional legacy fallback).
5. [ ] Session appears in UI/TUI; hostname/user/pid sensible.
6. [ ] **≥ 5** consecutive check-ins without the session becoming **stale** — define stale for your profile, e.g. **no successful check-in for `3 × callback_interval`** (or your team’s standard).
7. [ ] Queue low-noise tasks (`whoami`, `pwd`); results return.
8. [ ] Optional: packet capture or redirector access logs show **expected URI**, **User-Agent**, and **Host** per profile.
9. [ ] Optional: compare TLS client fingerprint (JA3 / JA4) to profile expectations if your tooling captures it.
10. [ ] On failure: attach logs, note whether traffic fell back to legacy baseline, and link to `phase0-beacon-crash-repro.md` if crash.

## Pass / fail

| Result | Condition |
|--------|-----------|
| **Pass** | Stable callbacks, tasks work, HTTP/TLS shape matches profile; no unexplained beacon exit |
| **Fail** | Parse/transform errors, wrong route, missing session, or crash — capture traces and repro steps |

## After the run

Add a short **Evidence** subsection below (or paste into your engagement notes).

### Evidence (template)

```
Date:
Commit:
Profile:
Redirector type: (nginx / Caddy / CloudFront / other)
Redirector URL:
Pass/Fail:
Notes:
```

### Evidence - Local Reverse Proxy Soak

```
Date: 2026-04-27
Commit: local working tree
Profile: pic-listener-smoke
Redirector type: local in-process reverse proxy
Redirector URL: http://127.0.0.1:43166
Upstream listener URL: http://127.0.0.1:43165
Pass/Fail: PASS
Notes: .\scripts\pic-profile-redirector-soak.ps1 built target/local-evidence/pic-profile-redirector-soak.bin, executed it via implant/build/tests/pic_loader.exe, observed legacy bootstrap plus 5 transformed /api/profile callbacks through the redirector, queued task a5cd6bb6-b203-4f7b-9a04-cf40bfb4a3e8, and received a 31 byte result for session 3c06515a-a042-47ba-a411-da3485715049.
Artifacts: target/local-evidence/pic-profile-redirector-soak.bin, target/local-evidence/pic-profile-redirector-soak.loader.log, target/local-evidence/pic-profile-redirector-soak.db
```
