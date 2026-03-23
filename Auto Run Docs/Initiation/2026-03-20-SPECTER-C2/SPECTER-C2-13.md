# Phase 13: Web UI

This phase builds the optional Web UI — a React/TypeScript SPA with Tailwind CSS and ShadCN/UI. It connects to the teamserver via gRPC-Web and provides a modern dark-themed dashboard with: global overview, interactive D3.js session graph, xterm.js terminal console, task timeline, module browser, profile editor with live preview, and redirector dashboard. Design is inspired by linear.app and Vercel — minimal, information-dense, and beautiful. By the end, operators have a full web-based alternative to the TUI.

## Context

The Web UI is served by the teamserver as static assets. It communicates via gRPC-Web through tonic-web middleware. The UI supports mTLS authentication via browser client certificates, with OAuth2/OIDC as fallback.

Web UI source: `C:\Users\localuser\Documents\SPECTER-C2\web\`
Teamserver source: `C:\Users\localuser\Documents\SPECTER-C2\crates\specter-server\`

## Tasks

- [x] Set up React/TypeScript project and gRPC-Web connectivity:
  - Create `web/` directory, initialize with Vite (`npm create vite@latest . -- --template react-ts`)
  - Install dependencies: React 18+, React Router, Tailwind CSS 3+, ShadCN/UI, @connectrpc/connect + connect-web, @bufbuild/protobuf + buf, d3 + @types/d3, @xterm/xterm + addons, lucide-react, date-fns, zustand, recharts, @tanstack/react-virtual
  - Configure Tailwind dark theme (Catppuccin/Dracula palette: bg-zinc-950, text-zinc-100, accent-emerald-500)
  - Generate TypeScript gRPC client from proto files using buf/protoc-gen-es + protoc-gen-connect-es → `web/src/gen/`
  - Add `tonic-web` to teamserver, wrap gRPC service with `tonic_web::enable()`, add CORS headers, serve static files from `web/dist/` at `/ui/`
  - Update `CLAUDE.md` with Web UI instructions
  <!-- Completed 2026-03-21: Vite React-TS project initialized in web/, all deps installed (React 19, Tailwind CSS 4, Connect-ES v2, D3, xterm.js, Zustand, Recharts, etc.), dark theme configured with Catppuccin/Dracula palette, 12 proto files generated to web/src/gen/ via buf + protoc-gen-es, tonic-web + CORS added to teamserver server.rs, AppLayout/Sidebar/TopBar created, CLAUDE.md updated. All tests pass (Rust + Vitest), production build succeeds. Note: ShadCN/UI deferred to component-level integration in later tasks; using Tailwind utility classes directly. -->

- [x] Build the global dashboard page:
  - Create `web/src/pages/Dashboard.tsx`:
    - Session overview cards (total, active/stale/dead/new with color coding, clickable)
    - Activity timeline: chronological event feed (auto-updates via gRPC stream, scrollable, last 100)
    - Redirector health sidebar widget: status indicators, domain/provider, last health check
    - Session check-in chart: recharts line chart of check-in frequency (last 24h)
  - Create `web/src/components/layout/`: Sidebar.tsx (collapsible nav), TopBar.tsx (breadcrumbs, search, notifications), AppLayout.tsx wrapper
  <!-- Completed 2026-03-21: Built Dashboard.tsx with: SessionOverviewCards (5 clickable cards: total/active/stale/dead/new with color coding, percentage indicators, navigation to /sessions with status filter), ActivityTimeline (chronological event feed derived from sessions, last 100, scrollable, auto-refreshes every 15s), RedirectorHealthWidget (status indicators, domain/provider display, health state), CheckInChart (Recharts line chart of check-in frequency over 24h with hourly buckets), QuickActions sidebar. Layout components (Sidebar, TopBar, AppLayout) already existed from Phase 13 task 1. Updated App.tsx routing to use real Dashboard. Created Dashboard.test.tsx with 11 tests covering all widgets. All 13 tests pass, build succeeds, lint clean. -->

- [x] Build session list and interaction console pages:
  - Create `web/src/pages/Sessions.tsx`:
    - Sortable/filterable table: Status dot, Hostname, Username, PID, OS, Integrity, IP, Last Check-in, First Seen, Actions
    - Search bar + status dropdown, virtualized list (@tanstack/react-virtual for 1000+ sessions), real-time updates
  - Create `web/src/pages/SessionInteract.tsx`:
    - Split layout: xterm.js terminal (70% height) + session details sidebar (30% width, collapsible)
    - Terminal: `specter>` prompt, ANSI colors, 10000-line scrollback, tab completion, command history
    - Sidebar: session metadata, active modules, quick action buttons (Sleep, Kill, Upload, Download)
    - Task queuing via QueueTask gRPC, subscribe to events for results
    - Multi-session tabs with independent xterm instances
  <!-- Completed 2026-03-21: Built Sessions.tsx with sortable/filterable virtualized table (10 columns: Status dot, Hostname, Username, PID, OS, Integrity, IP, Last Check-in, First Seen, Actions), search bar with hostname/username/IP/PID filtering, status dropdown filter synced with URL params, @tanstack/react-virtual for 1000+ session virtualization, 15s auto-refresh. Built SessionInteract.tsx with xterm.js terminal (specter> prompt, ANSI 16-color theme, 10000-line scrollback, tab completion for 30+ commands, command history with arrow keys), collapsible session details sidebar (metadata, quick actions: Sleep/Kill/Upload/Download, recent tasks list with status), task queuing via QueueTask gRPC, multi-session tabs with independent state. Updated App.tsx routing. Created Sessions.test.tsx (14 tests) and SessionInteract.test.tsx (11 tests). All 37 tests pass, build succeeds, type-check clean, lint clean (1 known TanStack Virtual warning). -->

- [x] Build the session map (interactive network graph):
  - Create `web/src/pages/SessionMap.tsx`:
    - D3.js force-directed graph: nodes = sessions (rounded rects with hostname/user, color by status, size by pivot count), edges = pivot relationships (solid=active, dashed=dead, arrow direction, label=link type)
    - Interactions: click → details popup, drag to rearrange, zoom/pan, double-click → interact page, pin nodes
    - SVG/PNG export button
  - Create `web/src/components/graph/`: SessionNode.tsx, PivotEdge.tsx, GraphControls.tsx
  <!-- Completed 2026-03-21: Built SessionMap.tsx with D3.js force-directed graph featuring: SessionNodeSVG (rounded rects colored by status — emerald/active, amber/stale, red/dead, blue/new — sized by pivot count with hostname/username labels), PivotEdgeSVG (solid=active, dashed=dead edges with arrow markers and link type labels for subnet/channel relationships), GraphControls (zoom in/out, fit view, unpin all, SVG/PNG export, node/edge counter). Graph derives pivot edges from shared subnets (internal IP /24) and shared external IPs (C2 channel). Interactions: click → details popup (metadata + pin/interact buttons), drag to rearrange nodes, zoom/pan via D3 zoom, double-click → navigate to /sessions/:id, pin/unpin nodes. SVG and PNG export with dark background. Created SessionNode.tsx, PivotEdge.tsx (with ArrowMarkerDefs), GraphControls.tsx. Updated App.tsx routing. Created SessionMap.test.tsx with 13 tests covering rendering, empty state, error state, node/edge rendering, popup interaction, pin/unpin, navigate. All 50 tests pass, build succeeds, type-check clean, lint clean. -->

- [x] Build task timeline and module browser pages:
  - Create `web/src/pages/TaskTimeline.tsx`:
    - Vertical chronological timeline: operator, session target, task type, status, result summary
    - Color by type (blue=recon, orange=lateral, red=injection), filters (operator, session, type, time range, status)
    - Expandable entries for full output, Markdown export
  - Create `web/src/pages/Modules.tsx`:
    - Grid/list of modules: name, version, description, OPSEC rating (1-5 shields), type (PIC/COFF)
    - Deploy button → dialog: select sessions, configure args (dynamic form from schema), Execute
    - Search/filter by name, type, OPSEC rating
  <!-- Completed 2026-03-21: Built TaskTimeline.tsx with vertical chronological timeline featuring: task categorization (recon/lateral/injection/exfil/persistence/other with color coding — blue/orange/red/purple/teal/gray), status indicators (Queued/Dispatched/Complete/Failed with icons), expandable entries showing full task output, operator/session/time metadata, filters (search, status dropdown, category dropdown, operator dropdown), category legend with clickable filter, URL param sync, Markdown export. Built Modules.tsx with grid/list toggle view, module cards showing name/version/description/type (PIC/COFF/BOF)/blob size/OPSEC rating (1-5 shields inferred from module name/type), search/filter by name/type/OPSEC rating, Deploy dialog (multi-session selector, arguments textarea, execute via LoadModule gRPC, result feedback). Updated App.tsx routing to use real TaskTimeline and Modules pages. Created TaskTimeline.test.tsx (14 tests) and Modules.test.tsx (16 tests). All 80 tests pass, build succeeds, type-check clean, lint clean (0 errors, 13 pre-existing warnings). -->

- [x] Build profile editor and redirector dashboard:
  - Create `web/src/pages/ProfileEditor.tsx`:
    - Monaco editor (YAML syntax), split view: editor (50%) + live preview (50%)
    - Preview: HTTP request/response examples, timing histogram, computed JA3 hash
    - Real-time validation, save via gRPC, load existing profiles
  - Create `web/src/pages/Redirectors.tsx`:
    - Grid of cards: name, domain, provider icon, status indicator, health check, TLS expiry, traffic volume
    - Actions: health check, burn & replace (confirmation), destroy
    - Deploy wizard: provider → domain → profile → deploy (with progress)
    - Domain pool table: domain, provider, status, actions
  <!-- Completed 2026-03-21: Built ProfileEditor.tsx with: Monaco editor (@monaco-editor/react) with YAML syntax highlighting and vs-dark theme, split view layout (50% editor / 50% live preview), profile list sidebar (load existing profiles via ListProfiles/GetProfile gRPC), live HTTP request/response preview (GET check-in and POST task results with parsed headers/URIs), timing distribution histogram (deterministic visualization of sleep/jitter intervals), computed JA3 hash display, real-time YAML validation (tab detection, empty content), save via CreateProfile gRPC, profile name/description editing, validation status indicators. Built Redirectors.tsx with: responsive grid of redirector cards (name, domain, provider icon, status indicator with color coding — running/degraded/stopped/error, TLS expiry simulation, traffic volume display), health check action (GetRedirectorHealth gRPC with loading state), burn & replace action (BurnRedirector gRPC with confirmation dialog), destroy action (DestroyRedirector gRPC with confirmation dialog), 4-step deploy wizard (provider selection → domain entry → profile selection → review & deploy via DeployRedirector gRPC with progress), domain pool table (AddDomainToPool gRPC, domain/provider/status display, inline add form), search/filter. Updated App.tsx routing to use real ProfileEditor and Redirectors pages (removed PlaceholderPage). Created ProfileEditor.test.tsx (19 tests) and Redirectors.test.tsx (19 tests). All 118 tests pass, build succeeds, type-check clean, lint clean (0 errors, 13 pre-existing warnings). -->

- [x] Implement authentication and state management:
  - `web/src/auth/`: mTLS via browser cert selection, OAuth2/OIDC fallback (PKCE flow), protected routes, role-based UI
  - `web/src/store/` (Zustand): sessionStore, taskStore, uiStore, authStore
  - `web/src/hooks/`: useGrpcStream, useSessions, useTaskResults, useNotifications
  - Configure Vitest, create tests: Dashboard.test.tsx, Sessions.test.tsx, CommandParsing.test.tsx
  - Build verification: `npm run build`, `npm run lint`, `npm run type-check`
  <!-- Completed 2026-03-21: Implemented full auth module in web/src/auth/ with: AuthContext (React context), AuthProvider (token + OAuth2 login via gRPC Authenticate RPC, auto-revalidation on mount), useAuth hook, ProtectedRoute (role-based access control using OperatorRole enum), LoginPage (mTLS cert selection + token auth forms, dark themed), mTLS module (attemptMtlsAuth, getMtlsCertInfo), OAuth2/OIDC PKCE module (code verifier/challenge generation, authorization flow, callback handler, token refresh). Created 4 Zustand stores in web/src/store/: authStore (operator, token, role, persist to localStorage), sessionStore (sessions CRUD, status filtering, counts), taskStore (tasks by session, queue via gRPC, result fetching), uiStore (sidebar, notifications, command palette, persist preferences). Created 4 custom hooks in web/src/hooks/: useGrpcStream (SubscribeEvents server streaming with auto-reconnect), useSessions (polling + real-time session updates), useTaskResults (polling + real-time task updates, submitTask), useNotifications (auto-generate from gRPC events). Updated App.tsx with AuthProvider wrapper and ProtectedRoute guards. Created CommandParsing.test.tsx with 23 tests covering command parsing, tab completion, local command detection, and known commands validation. All 141 tests pass (10 test files), build succeeds, type-check clean, lint 0 errors (13 pre-existing warnings from generated protos and TanStack Virtual). -->
