import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { SessionInteract } from '@/pages/SessionInteract'
import { specterClient } from '@/lib/client'

// Mock the gRPC client
vi.mock('@/lib/client', () => ({
  specterClient: {
    listSessions: vi.fn().mockRejectedValue(new Error('not connected')),
    listRedirectors: vi.fn().mockRejectedValue(new Error('not connected')),
    getSession: vi.fn().mockRejectedValue(new Error('not connected')),
    listTasks: vi.fn().mockResolvedValue({ tasks: [] }),
    queueTask: vi.fn().mockRejectedValue(new Error('not connected')),
  },
}))

// Mock xterm to avoid DOM issues in jsdom
vi.mock('@xterm/xterm', () => {
  class MockTerminal {
    loadAddon = vi.fn()
    open = vi.fn()
    writeln = vi.fn()
    write = vi.fn()
    onKey = vi.fn()
    clear = vi.fn()
    dispose = vi.fn()
  }
  return { Terminal: MockTerminal }
})

vi.mock('@xterm/addon-fit', () => {
  class MockFitAddon {
    fit = vi.fn()
  }
  return { FitAddon: MockFitAddon }
})

vi.mock('@xterm/addon-web-links', () => {
  class MockWebLinksAddon {}
  return { WebLinksAddon: MockWebLinksAddon }
})

// Mock xterm CSS import
vi.mock('@xterm/xterm/css/xterm.css', () => ({}))

const mockClient = vi.mocked(specterClient)

function renderSessionInteract(sessionId = 'sess-1') {
  return render(
    <MemoryRouter initialEntries={[`/sessions/${sessionId}`]}>
      <Routes>
        <Route path="sessions/:id" element={<SessionInteract />} />
      </Routes>
    </MemoryRouter>
  )
}

describe('SessionInteract page', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Reset ResizeObserver mock
    globalThis.ResizeObserver = class {
      observe = vi.fn()
      disconnect = vi.fn()
      unobserve = vi.fn()
    } as unknown as typeof ResizeObserver
  })

  it('renders terminal container', () => {
    renderSessionInteract()
    expect(screen.getByTestId('terminal-container')).toBeInTheDocument()
  })

  it('renders session sidebar with details heading', () => {
    renderSessionInteract()
    expect(screen.getByText('Session Details')).toBeInTheDocument()
  })

  it('shows loading state for session', () => {
    renderSessionInteract()
    expect(screen.getByText('Loading session...')).toBeInTheDocument()
  })

  it('renders new tab button', () => {
    renderSessionInteract()
    expect(screen.getByTitle('New tab')).toBeInTheDocument()
  })

  it('renders tab bar with initial tab', () => {
    renderSessionInteract()
    // The tab should show "..." initially since session hasn't loaded
    expect(screen.getByText('...')).toBeInTheDocument()
  })
})

describe('SessionInteract with session data', () => {
  const now = BigInt(Math.floor(Date.now() / 1000))

  beforeEach(() => {
    vi.clearAllMocks()

    globalThis.ResizeObserver = class {
      observe = vi.fn()
      disconnect = vi.fn()
      unobserve = vi.fn()
    } as unknown as typeof ResizeObserver

    mockClient.getSession.mockResolvedValue({
      session: {
        id: 'sess-1',
        hostname: 'WORKSTATION-1',
        username: 'admin',
        pid: 1234,
        osVersion: 'Windows 10',
        integrityLevel: 'High',
        processName: 'explorer.exe',
        internalIp: '192.168.1.10',
        externalIp: '1.2.3.4',
        lastCheckin: { seconds: now, nanos: 0 },
        firstSeen: { seconds: now - 3600n, nanos: 0 },
        status: 2, // ACTIVE
        activeChannel: 'https',
      },
    } as any) // eslint-disable-line @typescript-eslint/no-explicit-any

    mockClient.listTasks.mockResolvedValue({
      tasks: [
        {
          id: 'task-1',
          sessionId: 'sess-1',
          taskType: 'whoami',
          arguments: new Uint8Array(),
          priority: 2, // NORMAL
          status: 3, // COMPLETE
          createdAt: { seconds: now - 60n, nanos: 0 },
          completedAt: { seconds: now - 30n, nanos: 0 },
          operatorId: 'op-1',
          result: new Uint8Array(),
        },
      ],
    } as any) // eslint-disable-line @typescript-eslint/no-explicit-any
  })

  it('renders session metadata in sidebar', async () => {
    renderSessionInteract()

    await vi.waitFor(() => {
      expect(screen.getAllByText('WORKSTATION-1').length).toBeGreaterThanOrEqual(1)
    })

    expect(screen.getByText('admin')).toBeInTheDocument()
    expect(screen.getByText('1234')).toBeInTheDocument()
    expect(screen.getByText('explorer.exe')).toBeInTheDocument()
    expect(screen.getByText('High')).toBeInTheDocument()
    expect(screen.getByText('1.2.3.4')).toBeInTheDocument()
    expect(screen.getByText('192.168.1.10')).toBeInTheDocument()
    expect(screen.getByText('Windows 10')).toBeInTheDocument()
  })

  it('renders quick action buttons', async () => {
    renderSessionInteract()

    await vi.waitFor(() => {
      expect(screen.getAllByText('WORKSTATION-1').length).toBeGreaterThanOrEqual(1)
    })

    expect(screen.getByText('Sleep')).toBeInTheDocument()
    expect(screen.getByText('Kill')).toBeInTheDocument()
    expect(screen.getByText('Upload')).toBeInTheDocument()
    expect(screen.getByText('Download')).toBeInTheDocument()
  })

  it('renders recent tasks', async () => {
    renderSessionInteract()

    await vi.waitFor(() => {
      expect(screen.getByText('whoami')).toBeInTheDocument()
    })

    expect(screen.getByText('Complete')).toBeInTheDocument()
  })

  it('sidebar can be collapsed', async () => {
    renderSessionInteract()

    await vi.waitFor(() => {
      expect(screen.getAllByText('WORKSTATION-1').length).toBeGreaterThanOrEqual(1)
    })

    const collapseBtn = screen.getByTitle('Collapse sidebar')
    fireEvent.click(collapseBtn)

    // After collapse, "Session Details" heading should not be visible
    expect(screen.queryByText('Session Details')).not.toBeInTheDocument()
    expect(screen.getByTitle('Expand sidebar')).toBeInTheDocument()
  })

  it('sidebar can be expanded after collapse', async () => {
    renderSessionInteract()

    await vi.waitFor(() => {
      expect(screen.getAllByText('WORKSTATION-1').length).toBeGreaterThanOrEqual(1)
    })

    // Collapse
    fireEvent.click(screen.getByTitle('Collapse sidebar'))
    expect(screen.queryByText('Session Details')).not.toBeInTheDocument()

    // Expand
    fireEvent.click(screen.getByTitle('Expand sidebar'))
    expect(screen.getByText('Session Details')).toBeInTheDocument()
  })

  it('shows active session status', async () => {
    renderSessionInteract()

    await vi.waitFor(() => {
      // Status label in sidebar
      const activeLabels = screen.getAllByText('Active')
      expect(activeLabels.length).toBeGreaterThanOrEqual(1)
    })
  })
})
