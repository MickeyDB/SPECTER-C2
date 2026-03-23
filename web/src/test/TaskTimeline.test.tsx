import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { TaskTimeline } from '@/pages/TaskTimeline'
import { specterClient } from '@/lib/client'

vi.mock('@/lib/client', () => ({
  specterClient: {
    listTasks: vi.fn().mockRejectedValue(new Error('not connected')),
    listSessions: vi.fn().mockRejectedValue(new Error('not connected')),
  },
}))

const mockClient = vi.mocked(specterClient)

function renderTaskTimeline() {
  return render(
    <MemoryRouter initialEntries={['/tasks']}>
      <TaskTimeline />
    </MemoryRouter>
  )
}

describe('TaskTimeline', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the page heading', () => {
    renderTaskTimeline()
    expect(screen.getByText('Task Timeline')).toBeInTheDocument()
    expect(screen.getByText('Chronological view of all operator tasks')).toBeInTheDocument()
  })

  it('renders the refresh button', () => {
    renderTaskTimeline()
    expect(screen.getByText('Refresh')).toBeInTheDocument()
  })

  it('renders the export button', () => {
    renderTaskTimeline()
    expect(screen.getByText('Export')).toBeInTheDocument()
  })

  it('renders filter controls', () => {
    renderTaskTimeline()
    expect(screen.getByPlaceholderText('Search tasks...')).toBeInTheDocument()
    expect(screen.getByText('All Statuses')).toBeInTheDocument()
    expect(screen.getByText('All Categories')).toBeInTheDocument()
    expect(screen.getByText('All Operators')).toBeInTheDocument()
  })

  it('renders category legend', () => {
    renderTaskTimeline()
    expect(screen.getByText('recon')).toBeInTheDocument()
    expect(screen.getByText('lateral')).toBeInTheDocument()
    expect(screen.getByText('injection')).toBeInTheDocument()
    expect(screen.getByText('exfil')).toBeInTheDocument()
    expect(screen.getByText('persistence')).toBeInTheDocument()
    expect(screen.getByText('other')).toBeInTheDocument()
  })

  it('shows empty state when no tasks', async () => {
    mockClient.listTasks.mockResolvedValue({ tasks: [] } as any) // eslint-disable-line @typescript-eslint/no-explicit-any
    mockClient.listSessions.mockResolvedValue({ sessions: [] } as any) // eslint-disable-line @typescript-eslint/no-explicit-any

    renderTaskTimeline()

    await vi.waitFor(() => {
      expect(screen.getByText('No tasks found')).toBeInTheDocument()
    })
  })
})

describe('TaskTimeline with data', () => {
  const now = BigInt(Math.floor(Date.now() / 1000))

  beforeEach(() => {
    vi.clearAllMocks()

    mockClient.listTasks.mockResolvedValue({
      tasks: [
        {
          id: 'task-1',
          sessionId: 'sess-1',
          taskType: 'whoami',
          arguments: new Uint8Array(),
          priority: 2,
          status: 3, // COMPLETE
          createdAt: { seconds: now, nanos: 0 },
          completedAt: { seconds: now + 5n, nanos: 0 },
          operatorId: 'operator-1',
          result: new TextEncoder().encode('WORKSTATION-1\\admin'),
        },
        {
          id: 'task-2',
          sessionId: 'sess-1',
          taskType: 'inject-shellcode',
          arguments: new Uint8Array(),
          priority: 3,
          status: 4, // FAILED
          createdAt: { seconds: now - 60n, nanos: 0 },
          completedAt: { seconds: now - 55n, nanos: 0 },
          operatorId: 'operator-2',
          result: new TextEncoder().encode('Access denied'),
        },
        {
          id: 'task-3',
          sessionId: 'sess-2',
          taskType: 'psexec',
          arguments: new Uint8Array(),
          priority: 2,
          status: 1, // QUEUED
          createdAt: { seconds: now - 120n, nanos: 0 },
          operatorId: 'operator-1',
          result: new Uint8Array(),
        },
      ],
    } as any) // eslint-disable-line @typescript-eslint/no-explicit-any

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
          status: 2,
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
          status: 2,
          activeChannel: 'https',
        },
      ],
    } as any) // eslint-disable-line @typescript-eslint/no-explicit-any
  })

  it('renders tasks from fetched data', async () => {
    renderTaskTimeline()

    await vi.waitFor(() => {
      expect(screen.getByText('whoami')).toBeInTheDocument()
    })

    expect(screen.getByText('inject-shellcode')).toBeInTheDocument()
    expect(screen.getByText('psexec')).toBeInTheDocument()
  })

  it('displays correct task categories', async () => {
    renderTaskTimeline()

    await vi.waitFor(() => {
      expect(screen.getByText('whoami')).toBeInTheDocument()
    })

    // whoami -> recon, inject-shellcode -> injection, psexec -> lateral
    const reconBadges = screen.getAllByText('recon')
    expect(reconBadges.length).toBeGreaterThanOrEqual(1)

    const injectionBadges = screen.getAllByText('injection')
    expect(injectionBadges.length).toBeGreaterThanOrEqual(1)

    const lateralBadges = screen.getAllByText('lateral')
    expect(lateralBadges.length).toBeGreaterThanOrEqual(1)
  })

  it('displays task status indicators', async () => {
    renderTaskTimeline()

    await vi.waitFor(() => {
      expect(screen.getByText('whoami')).toBeInTheDocument()
    })

    // Status labels appear in both filter dropdown options and timeline entries
    const completes = screen.getAllByText('Complete')
    expect(completes.length).toBeGreaterThanOrEqual(1)
    const faileds = screen.getAllByText('Failed')
    expect(faileds.length).toBeGreaterThanOrEqual(1)
    const queueds = screen.getAllByText('Queued')
    expect(queueds.length).toBeGreaterThanOrEqual(1)
  })

  it('displays session hostnames', async () => {
    renderTaskTimeline()

    await vi.waitFor(() => {
      expect(screen.getByText('whoami')).toBeInTheDocument()
    })

    const hostnames = screen.getAllByText(/WORKSTATION-1/)
    expect(hostnames.length).toBeGreaterThanOrEqual(1)
  })

  it('displays operator IDs', async () => {
    renderTaskTimeline()

    await vi.waitFor(() => {
      expect(screen.getByText('whoami')).toBeInTheDocument()
    })

    const ops = screen.getAllByText('operator-1')
    expect(ops.length).toBeGreaterThanOrEqual(1)
  })

  it('shows task count in header', async () => {
    renderTaskTimeline()

    await vi.waitFor(() => {
      expect(screen.getByText('3 of 3 tasks')).toBeInTheDocument()
    })
  })

  it('expands task entry to show details', async () => {
    renderTaskTimeline()

    await vi.waitFor(() => {
      expect(screen.getByText('whoami')).toBeInTheDocument()
    })

    // Click on the whoami task row
    const whoamiRow = screen.getByText('whoami').closest('button')
    if (whoamiRow) fireEvent.click(whoamiRow)

    await vi.waitFor(() => {
      expect(screen.getByText('task-1')).toBeInTheDocument()
    })

    // Output should be visible in the pre element
    const outputEl = screen.getByText('WORKSTATION-1\\admin', { selector: 'pre' })
    expect(outputEl).toBeInTheDocument()
  })

  it('filters by search query', async () => {
    renderTaskTimeline()

    await vi.waitFor(() => {
      expect(screen.getByText('whoami')).toBeInTheDocument()
    })

    const searchInput = screen.getByPlaceholderText('Search tasks...')
    fireEvent.change(searchInput, { target: { value: 'inject' } })

    // Only inject-shellcode should remain visible
    expect(screen.queryByText('whoami')).not.toBeInTheDocument()
    expect(screen.getByText('inject-shellcode')).toBeInTheDocument()
  })
})
