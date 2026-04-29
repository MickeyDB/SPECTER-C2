# UI Data Path Validation - 2026-04-28

## Scope

Validated the Web UI data paths from generated protobuf types through React pages, gRPC-Web transport, teamserver RPC handlers, persistence-backed domain services, and browser route rendering.

Covered UI RPC usage:

- auth: `authenticate`
- sessions/tasks: `listSessions`, `getSession`, `queueTask`, `getTaskResult`, `listTasks`
- listeners: `createListener`, `listListeners`, `startListener`, `stopListener`, `deleteListener`
- profiles: `createProfile`, `listProfiles`, `getProfile`, `deleteProfile`
- payload builder: `listFormats`, `generatePayload`
- redirectors: `deployRedirector`, `destroyRedirector`, `burnRedirector`, `listRedirectors`, `getRedirectorHealth`, `addDomainToPool`
- modules: `listModules`, `loadModule`
- campaigns: `createCampaign`, `listCampaigns`, `add/remove session`, `add/remove operator`
- operators/certs: `listOperators`, `issue/revoke/list certificates`
- webhooks: `create/list/delete/test webhook`
- reports: `generate/list/get report`
- azure dead drop: `createAzureListener`, `listAzureContainers`
- streams/collaboration: `subscribeEvents`, `sendChatMessage`

## Commands Run

Web:

```powershell
cd web
npm run generate
npm run type-check
npm run test
npm run build
npm run lint
```

Rust/server:

```powershell
cargo check -p specter-server --bins
cargo test -p specter-server --tests -- --nocapture
cargo test -p specter-common -- --nocapture
```

Focused server checks also run before the full sweep:

```powershell
cargo test -p specter-server --test listener_tests -- --nocapture
cargo test -p specter-server --test builder_tests -- --nocapture
cargo test -p specter-server --test redirector_tests -- --nocapture
cargo test -p specter-server --test profile_tests -- --nocapture
```

Browser smoke:

- Started `specter-server` in dev mode on gRPC `50051` and HTTP listener `18080` with throwaway DB `target/local-evidence/ui-e2e.db`.
- Started Vite on `http://127.0.0.1:5173/ui/`.
- Logged in through the UI with the generated first-run `admin` token.
- Loaded each primary route through the browser:
  - `/ui/dashboard`
  - `/ui/sessions`
  - `/ui/map`
  - `/ui/tasks`
  - `/ui/modules`
  - `/ui/profiles`
  - `/ui/builder`
  - `/ui/listeners`
  - `/ui/redirectors`
  - `/ui/azure-deaddrop`
  - `/ui/campaigns`
  - `/ui/operators`
  - `/ui/webhooks`
  - `/ui/reports`

## Results

- `npm run generate`: PASS. Regenerated `web/src/gen/specter/v1/builder_pb.ts` from the current proto.
- `npm run type-check`: PASS.
- `npm run test`: PASS, 11 test files / 144 tests.
- `npm run build`: PASS. Vite production build completed. Route-level code splitting reduced the initial app chunk from about 1.4 MB to about 255 kB. The remaining warning is the PWA plugin's internal deprecated `inlineDynamicImports` option.
- `npm run lint`: PASS with no warnings after excluding generated protobuf code and fixing page-level hook warnings.
- `cargo check -p specter-server --bins`: PASS.
- `cargo test -p specter-server --tests`: PASS. Full server test sweep passed across lib tests and integration test binaries.
- `cargo test -p specter-common`: PASS, 8 TLV/check-in tests.
- Browser login and route smoke: PASS. All primary routes rendered after real gRPC-Web authentication with no browser console errors.
- `git diff --check`: PASS.

## Warnings / Follow-Up

- The prior ESLint warnings were cleaned:
  - generated protobuf files are excluded from lint,
  - `PayloadBuilder.tsx` includes `selectedListener` in the payload-generation callback dependencies,
  - `SessionInteract.tsx` includes `termRef` in the terminal setup effect dependencies,
  - `Sessions.tsx` has a narrow documented suppression for TanStack Virtual's React Compiler warning.
- Build warning remaining:
  - PWA plugin reports deprecated `inlineDynamicImports` from its generated service-worker build path; revisit with a `vite-plugin-pwa` upgrade or config migration when touching PWA packaging.
- Browser route smoke used a clean dev database with minimal data. It proves route/render/auth/list-path health, not every complex create/update/delete interaction through the browser.
- `SubscribeEvents` proxy errors appeared only after the teamserver was intentionally stopped while Vite was still running; no route smoke console errors occurred while the teamserver was up.

## Artifacts

- `target/local-evidence/ui-e2e.db`
- `target/local-evidence/ui-e2e-server.out.log`
- `target/local-evidence/ui-e2e-server.err.log`
- `target/local-evidence/ui-e2e-vite.out.log`
- `target/local-evidence/ui-e2e-vite.err.log`
