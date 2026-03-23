import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { Dashboard } from '@/pages/Dashboard'
import { specterClient } from '@/lib/client'

// Mock the gRPC client
vi.mock('@/lib/client', () => ({
  specterClient: {
    listSessions: vi.fn().mockRejectedValue(new Error('not connected')),
    listRedirectors: vi.fn().mockRejectedValue(new Error('not connected')),
  },
}))

const mockClient = vi.mocked(specterClient)

// Mock recharts to avoid rendering issues in jsdom
vi.mock('recharts', () => ({
  ResponsiveContainer: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="responsive-container">{children}</div>
  ),
  LineChart: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="line-chart">{children}</div>
  ),
  Line: () => <div data-testid="line" />,
  XAxis: () => <div data-testid="x-axis" />,
  YAxis: () => <div data-testid="y-axis" />,
  CartesianGrid: () => <div data-testid="cartesian-grid" />,
  Tooltip: () => <div data-testid="tooltip" />,
}))

function renderDashboard() {
  return render(
    <MemoryRouter initialEntries={['/dashboard']}>
      <Dashboard />
    </MemoryRouter>
  )
}

describe('Dashboard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the dashboard heading', async () => {
    renderDashboard()
    expect(screen.getByText('Dashboard')).toBeInTheDocument()
    expect(screen.getByText('Global overview of operations')).toBeInTheDocument()
  })

  it('renders session overview cards with zero counts', async () => {
    renderDashboard()
    // All cards should show 0 when no sessions loaded
    const zeros = screen.getAllByText('0')
    expect(zeros.length).toBeGreaterThanOrEqual(5)
  })

  it('renders the activity timeline section', async () => {
    renderDashboard()
    expect(screen.getByText('Activity Timeline')).toBeInTheDocument()
    expect(screen.getByText('No activity yet')).toBeInTheDocument()
  })

  it('renders the redirectors widget', async () => {
    renderDashboard()
    expect(screen.getByText('Redirectors')).toBeInTheDocument()
    expect(screen.getByText('No redirectors configured')).toBeInTheDocument()
  })

  it('renders the check-in frequency chart', async () => {
    renderDashboard()
    expect(screen.getByText('Check-in Frequency (24h)')).toBeInTheDocument()
  })

  it('renders the quick actions section', async () => {
    renderDashboard()
    expect(screen.getByText('Quick Actions')).toBeInTheDocument()
    expect(screen.getByText('Sessions')).toBeInTheDocument()
    expect(screen.getByText('Session Map')).toBeInTheDocument()
    expect(screen.getByText('Task Timeline')).toBeInTheDocument()
    expect(screen.getByText('Modules')).toBeInTheDocument()
  })

  it('renders refresh button', async () => {
    renderDashboard()
    expect(screen.getByText('Refresh')).toBeInTheDocument()
  })

  it('renders session status labels', async () => {
    renderDashboard()
    expect(screen.getByText('Total')).toBeInTheDocument()
    expect(screen.getByText('Active')).toBeInTheDocument()
    expect(screen.getByText('Stale')).toBeInTheDocument()
    expect(screen.getByText('Dead')).toBeInTheDocument()
    expect(screen.getByText('New')).toBeInTheDocument()
  })
})

describe('Dashboard with data', () => {
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
      ],
    } as any) // eslint-disable-line @typescript-eslint/no-explicit-any

    mockClient.listRedirectors.mockResolvedValue({
      redirectors: [
        {
          id: 'redir-1',
          name: 'cdn-front',
          redirectorType: 'azure-cdn',
          provider: 'Azure',
          domain: 'cdn.example.com',
          state: 'running',
          backendUrl: 'https://backend.example.com',
          configYaml: '',
        },
      ],
    } as any) // eslint-disable-line @typescript-eslint/no-explicit-any
  })

  it('renders session counts from fetched data', async () => {
    renderDashboard()

    // Wait for async data to load - total should be 2
    await vi.waitFor(() => {
      expect(screen.getByText('2')).toBeInTheDocument()
    })

    // Both Active and Stale should show 1
    const ones = screen.getAllByText('1')
    expect(ones.length).toBeGreaterThanOrEqual(2)
  })

  it('renders redirector from fetched data', async () => {
    renderDashboard()

    await vi.waitFor(() => {
      expect(screen.getByText('cdn-front')).toBeInTheDocument()
    })

    expect(screen.getByText('cdn.example.com')).toBeInTheDocument()
    expect(screen.getByText('running')).toBeInTheDocument()
  })

  it('renders activity events from sessions', async () => {
    renderDashboard()

    await vi.waitFor(() => {
      const events = screen.getAllByText(/WORKSTATION-1/)
      expect(events.length).toBeGreaterThanOrEqual(1)
    })
  })
})
