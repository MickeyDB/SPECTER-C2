# Web UI Documentation

The web UI is a React/TypeScript single-page application providing a browser-based operator interface.

## Stack

| Technology | Purpose |
|------------|---------|
| React 19 | UI framework |
| TypeScript | Type safety |
| Vite | Build tool and dev server |
| Tailwind CSS 4 | Styling |
| Connect-ES | gRPC-Web client (`@connectrpc/connect-web`) |
| Zustand | State management |
| Recharts | Charts and metrics |
| D3 | Force-directed graph visualization |
| xterm.js | Terminal emulation |
| Monaco Editor | Code/YAML editing |

## Development

```bash
cd web
npm install          # Install dependencies
npm run dev          # Start dev server (with gRPC proxy)
npm run build        # Production build → dist/
npm run lint         # ESLint
npm run type-check   # TypeScript strict checking
npm run test         # Run tests
npm run generate     # Regenerate proto TypeScript from .proto files
```

The Vite dev server proxies gRPC-Web requests to the teamserver. In production, the teamserver serves gRPC-Web directly via `tonic-web`.

## Pages

| Page | File | Description |
|------|------|-------------|
| Dashboard | `pages/Dashboard.tsx` | Overview with session metrics and activity charts |
| Sessions | `pages/Sessions.tsx` | Session list with filtering and status indicators |
| Session Interact | `pages/SessionInteract.tsx` | Per-session task execution and result viewing |
| Session Map | `pages/SessionMap.tsx` | D3 force-directed graph of session topology |
| Task Timeline | `pages/TaskTimeline.tsx` | Timeline view of task execution across sessions |
| Modules | `pages/Modules.tsx` | Module repository browser |
| Profile Editor | `pages/ProfileEditor.tsx` | YAML C2 profile creation and editing (Monaco) |
| Payload Builder | `pages/PayloadBuilder.tsx` | Implant payload generation with format, channel, sleep, obfuscation, and kill date config |
| Redirectors | `pages/Redirectors.tsx` | Redirector deployment and management |
| Reports | `pages/Reports.tsx` | Engagement report generation and viewing |

## Components

### Layout
- `layout/AppLayout.tsx` — Main application layout with sidebar and content area
- `layout/Sidebar.tsx` — Navigation sidebar
- `layout/TopBar.tsx` — Header with user info and settings

### Graph Visualization
- `graph/SessionNode.tsx` — Session node rendering
- `graph/PivotEdge.tsx` — Edge rendering between sessions
- `graph/GraphControls.tsx` — Zoom, pan, and layout controls

### Collaboration
- `ChatWidget.tsx` — Real-time team chat widget

## State Management (Zustand)

| Store | File | Purpose |
|-------|------|---------|
| Auth | `store/authStore.ts` | Authentication state and tokens |
| Sessions | `store/sessionStore.ts` | Session list, filtering, selection |
| Tasks | `store/taskStore.ts` | Task queue and results |
| Collaboration | `store/collaborationStore.ts` | Operator presence and chat |
| UI | `store/uiStore.ts` | UI state (panels, selected session) |

## Authentication

| File | Purpose |
|------|---------|
| `auth/AuthContext.ts` | React auth context provider |
| `auth/LoginPage.tsx` | Login form |
| `auth/ProtectedRoute.tsx` | Route guard for authenticated routes |
| `auth/mtls.ts` | mTLS client certificate handling |
| `auth/oauth.ts` | OAuth2 support (future) |

## Networking

| File | Purpose |
|------|---------|
| `lib/client.ts` | Connect-ES gRPC client initialization |
| `lib/transport.ts` | gRPC-Web transport configuration |

## Auto-Generated Code

`src/gen/specter/v1/` contains TypeScript types generated from protobuf definitions. **Do not edit these files manually.** Regenerate with:

```bash
npm run generate
```

This uses `buf` with `protoc-gen-es` to generate from `crates/specter-common/proto/`.
