import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { Sessions } from '@/pages/Sessions'
import { specterClient } from '@/lib/client'

// Mock the gRPC client
vi.mock('@/lib/client', () => ({
  specterClient: {
    listSessions: vi.fn().mockRejectedValue(new Error('not connected')),
    listRedirectors: vi.fn().mockRejectedValue(new Error('not connected')),
    getSession: vi.fn().mockRejectedValue(new Error('not connected')),
    listTasks: vi.fn().mockRejectedValue(new Error('not connected')),
    queueTask: vi.fn().mockRejectedValue(new Error('not connected')),
  },
}))

// Mock @tanstack/react-virtual since jsdom has no layout engine
vi.mock('@tanstack/react-virtual', () => ({
  useVirtualizer: ({ count, estimateSize }: { count: number; estimateSize: () => number }) => ({
    getTotalSize: () => count * estimateSize(),
    getVirtualItems: () =>
      Array.from({ length: count }, (_, i) => ({
        index: i,
        start: i * estimateSize(),
        size: estimateSize(),
        key: i,
      })),
  }),
}))

const mockClient = vi.mocked(specterClient)

function renderSessions(initialEntries = ['/sessions']) {
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      <Sessions />
    </MemoryRouter>
  )
}

describe('Sessions page', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the sessions heading', () => {
    renderSessions()
    expect(screen.getByText('Sessions')).toBeInTheDocument()
  })

  it('renders search input', () => {
    renderSessions()
    expect(screen.getByPlaceholderText(/Search by hostname/)).toBeInTheDocument()
  })

  it('renders status filter dropdown', () => {
    renderSessions()
    expect(screen.getByDisplayValue('All')).toBeInTheDocument()
  })

  it('renders refresh button', () => {
    renderSessions()
    expect(screen.getByText('Refresh')).toBeInTheDocument()
  })

  it('shows empty state when no sessions', () => {
    renderSessions()
    expect(screen.getByText('No sessions found')).toBeInTheDocument()
  })

  it('renders column headers', () => {
    renderSessions()
    expect(screen.getByText('Hostname')).toBeInTheDocument()
    expect(screen.getByText('Username')).toBeInTheDocument()
    expect(screen.getByText('PID')).toBeInTheDocument()
    expect(screen.getByText('OS')).toBeInTheDocument()
    expect(screen.getByText('Integrity')).toBeInTheDocument()
    expect(screen.getByText('IP')).toBeInTheDocument()
    expect(screen.getByText('Last Check-in')).toBeInTheDocument()
    expect(screen.getByText('First Seen')).toBeInTheDocument()
  })

  it('shows error when fetch fails', async () => {
    mockClient.listSessions.mockRejectedValue(new Error('connection failed'))
    renderSessions()
    await vi.waitFor(() => {
      expect(screen.getByText('Unable to fetch sessions')).toBeInTheDocument()
    })
  })
})

describe('Sessions page with data', () => {
  beforeEach(() => {
    vi.clearAllMocks()

    const now = BigInt(Math.floor(Date.now() / 1000))

    mockClient.listSessions.mockResolvedValue({
      sessions: [
        {
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
        {
          id: 'sess-2',
          hostname: 'SERVER-DC1',
          username: 'SYSTEM',
          pid: 4,
          osVersion: 'Windows Server 2022',
          integrityLevel: 'System',
          processName: 'svchost.exe',
          internalIp: '10.0.0.1',
          externalIp: '5.6.7.8',
          lastCheckin: { seconds: now - 600n, nanos: 0 },
          firstSeen: { seconds: now - 7200n, nanos: 0 },
          status: 3, // STALE
          activeChannel: 'https',
        },
        {
          id: 'sess-3',
          hostname: 'LAPTOP-DEV',
          username: 'developer',
          pid: 5678,
          osVersion: 'Windows 11',
          integrityLevel: 'Medium',
          processName: 'notepad.exe',
          internalIp: '172.16.0.5',
          externalIp: '9.10.11.12',
          lastCheckin: { seconds: now - 86400n, nanos: 0 },
          firstSeen: { seconds: now - 172800n, nanos: 0 },
          status: 4, // DEAD
          activeChannel: 'https',
        },
      ],
    } as any) // eslint-disable-line @typescript-eslint/no-explicit-any
  })

  it('renders session data in table', async () => {
    renderSessions()

    await vi.waitFor(() => {
      expect(screen.getByText('WORKSTATION-1')).toBeInTheDocument()
    })

    expect(screen.getByText('SERVER-DC1')).toBeInTheDocument()
    expect(screen.getByText('LAPTOP-DEV')).toBeInTheDocument()
    expect(screen.getByText('admin')).toBeInTheDocument()
    expect(screen.getByText('SYSTEM')).toBeInTheDocument()
  })

  it('shows session count', async () => {
    renderSessions()

    await vi.waitFor(() => {
      expect(screen.getByText('3 of 3 sessions')).toBeInTheDocument()
    })
  })

  it('filters sessions by search query', async () => {
    renderSessions()

    await vi.waitFor(() => {
      expect(screen.getByText('WORKSTATION-1')).toBeInTheDocument()
    })

    const search = screen.getByPlaceholderText(/Search by hostname/)
    fireEvent.change(search, { target: { value: 'SERVER' } })

    expect(screen.getByText('SERVER-DC1')).toBeInTheDocument()
    expect(screen.queryByText('WORKSTATION-1')).not.toBeInTheDocument()
    expect(screen.queryByText('LAPTOP-DEV')).not.toBeInTheDocument()
  })

  it('filters sessions by status dropdown', async () => {
    renderSessions()

    await vi.waitFor(() => {
      expect(screen.getByText('WORKSTATION-1')).toBeInTheDocument()
    })

    const select = screen.getByDisplayValue('All')
    fireEvent.change(select, { target: { value: 'active' } })

    expect(screen.getByText('WORKSTATION-1')).toBeInTheDocument()
    expect(screen.queryByText('SERVER-DC1')).not.toBeInTheDocument()
    expect(screen.queryByText('LAPTOP-DEV')).not.toBeInTheDocument()
  })

  it('shows status dots with correct labels', async () => {
    renderSessions()

    await vi.waitFor(() => {
      expect(screen.getByText('WORKSTATION-1')).toBeInTheDocument()
    })

    // Status labels should appear
    const activeLabels = screen.getAllByText('Active')
    expect(activeLabels.length).toBeGreaterThanOrEqual(1)

    const staleLabels = screen.getAllByText('Stale')
    expect(staleLabels.length).toBeGreaterThanOrEqual(1)

    const deadLabels = screen.getAllByText('Dead')
    expect(deadLabels.length).toBeGreaterThanOrEqual(1)
  })

  it('renders interact buttons for each session', async () => {
    renderSessions()

    await vi.waitFor(() => {
      expect(screen.getByText('WORKSTATION-1')).toBeInTheDocument()
    })

    const interactButtons = screen.getAllByTitle('Interact')
    expect(interactButtons.length).toBe(3)
  })
})
