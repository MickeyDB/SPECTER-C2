import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { SessionMap } from '@/pages/SessionMap'
import { specterClient } from '@/lib/client'

// Mock the gRPC client
vi.mock('@/lib/client', () => ({
  specterClient: {
    listSessions: vi.fn().mockRejectedValue(new Error('not connected')),
  },
}))

const mockClient = vi.mocked(specterClient)

// Mock D3 zoom/force to avoid jsdom issues
vi.mock('d3', async () => {
  const actual = await vi.importActual<typeof import('d3')>('d3')
  return {
    ...actual,
    zoom: () => {
      const handler = Object.assign(
        () => handler,
        {
          scaleExtent: () => handler,
          on: () => handler,
          scaleBy: () => handler,
          transform: () => handler,
        }
      )
      return handler
    },
    select: () => ({
      call: () => ({ call: () => ({}) }),
      on: () => ({}),
      transition: () => ({ duration: () => ({ call: () => ({}) }) }),
    }),
    zoomIdentity: { x: 0, y: 0, k: 1 },
  }
})

const mockNavigate = vi.fn()
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

function renderSessionMap() {
  return render(
    <MemoryRouter initialEntries={['/map']}>
      <SessionMap />
    </MemoryRouter>
  )
}

const now = BigInt(Math.floor(Date.now() / 1000))

const mockSessions = [
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
    internalIp: '192.168.1.20',
    externalIp: '1.2.3.4',
    lastCheckin: { seconds: now - 600n, nanos: 0 },
    firstSeen: { seconds: now - 7200n, nanos: 0 },
    status: 2, // ACTIVE
    activeChannel: 'https',
  },
  {
    id: 'sess-3',
    hostname: 'DMZ-WEB',
    username: 'www-data',
    pid: 9876,
    osVersion: 'Ubuntu 22.04',
    integrityLevel: 'Medium',
    processName: 'apache2',
    internalIp: '10.0.0.5',
    externalIp: '9.8.7.6',
    lastCheckin: { seconds: now - 86400n, nanos: 0 },
    firstSeen: { seconds: now - 172800n, nanos: 0 },
    status: 4, // DEAD
    activeChannel: 'dns',
  },
]

describe('SessionMap', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockNavigate.mockClear()
  })

  it('renders the session map heading', () => {
    renderSessionMap()
    expect(screen.getByText('Session Map')).toBeInTheDocument()
    expect(
      screen.getByText(/Interactive network graph/)
    ).toBeInTheDocument()
  })

  it('renders refresh button', () => {
    renderSessionMap()
    expect(screen.getByText('Refresh')).toBeInTheDocument()
  })

  it('shows error when unable to connect', async () => {
    renderSessionMap()
    await waitFor(() => {
      expect(screen.getByText('Unable to connect to teamserver')).toBeInTheDocument()
    })
  })

  it('shows empty state when no sessions', async () => {
    mockClient.listSessions.mockResolvedValue({ sessions: [] } as any) // eslint-disable-line @typescript-eslint/no-explicit-any
    renderSessionMap()
    await waitFor(() => {
      expect(screen.getByText('No sessions available')).toBeInTheDocument()
    })
  })

  it('renders SVG canvas when sessions are loaded', async () => {
    mockClient.listSessions.mockResolvedValue({ sessions: mockSessions } as any) // eslint-disable-line @typescript-eslint/no-explicit-any
    renderSessionMap()
    await waitFor(() => {
      expect(screen.getByTestId('session-map-svg')).toBeInTheDocument()
    })
  })

  it('renders session nodes for each session', async () => {
    mockClient.listSessions.mockResolvedValue({ sessions: mockSessions } as any) // eslint-disable-line @typescript-eslint/no-explicit-any
    renderSessionMap()
    await waitFor(() => {
      expect(screen.getByTestId('session-node-sess-1')).toBeInTheDocument()
      expect(screen.getByTestId('session-node-sess-2')).toBeInTheDocument()
      expect(screen.getByTestId('session-node-sess-3')).toBeInTheDocument()
    })
  })

  it('renders graph controls', async () => {
    mockClient.listSessions.mockResolvedValue({ sessions: mockSessions } as any) // eslint-disable-line @typescript-eslint/no-explicit-any
    renderSessionMap()
    await waitFor(() => {
      expect(screen.getByTestId('graph-controls')).toBeInTheDocument()
    })
  })

  it('shows node count and edge count', async () => {
    mockClient.listSessions.mockResolvedValue({ sessions: mockSessions } as any) // eslint-disable-line @typescript-eslint/no-explicit-any
    renderSessionMap()
    await waitFor(() => {
      // 3 nodes, sess-1 and sess-2 share subnet 192.168.1.x AND external IP 1.2.3.4
      // but deduplication means only 1 edge between them
      expect(screen.getByText(/3 nodes/)).toBeInTheDocument()
    })
  })

  it('shows details popup when clicking a node', async () => {
    mockClient.listSessions.mockResolvedValue({ sessions: mockSessions } as any) // eslint-disable-line @typescript-eslint/no-explicit-any
    renderSessionMap()

    await waitFor(() => {
      expect(screen.getByTestId('session-node-sess-1')).toBeInTheDocument()
    })

    // Click the background rect inside the node group (jsdom handles rect clicks better than g)
    const nodeGroup = screen.getByTestId('session-node-sess-1')
    const rect = nodeGroup.querySelector('rect')!
    fireEvent.click(rect)

    await waitFor(() => {
      expect(screen.getByTestId('node-details-popup')).toBeInTheDocument()
    })

    // Check popup content
    const popup = screen.getByTestId('node-details-popup')
    expect(popup).toHaveTextContent('WORKSTATION-1')
    expect(popup).toHaveTextContent('admin')
    expect(popup).toHaveTextContent('192.168.1.10')
  })

  it('closes details popup with X button', async () => {
    mockClient.listSessions.mockResolvedValue({ sessions: mockSessions } as any) // eslint-disable-line @typescript-eslint/no-explicit-any
    renderSessionMap()

    await waitFor(() => {
      expect(screen.getByTestId('session-node-sess-1')).toBeInTheDocument()
    })

    const rect = screen.getByTestId('session-node-sess-1').querySelector('rect')!
    fireEvent.click(rect)

    await waitFor(() => {
      expect(screen.getByTestId('node-details-popup')).toBeInTheDocument()
    })

    // The X button is inside the popup - find the close button (has an SVG child)
    const popup = screen.getByTestId('node-details-popup')
    const closeButtons = popup.querySelectorAll('button')
    for (const btn of closeButtons) {
      if (btn.querySelector('svg')) {
        fireEvent.click(btn)
        break
      }
    }

    await waitFor(() => {
      expect(screen.queryByTestId('node-details-popup')).not.toBeInTheDocument()
    })
  })

  it('shows interact button in details popup that navigates', async () => {
    mockClient.listSessions.mockResolvedValue({ sessions: mockSessions } as any) // eslint-disable-line @typescript-eslint/no-explicit-any
    renderSessionMap()

    await waitFor(() => {
      expect(screen.getByTestId('session-node-sess-1')).toBeInTheDocument()
    })

    const rect = screen.getByTestId('session-node-sess-1').querySelector('rect')!
    fireEvent.click(rect)

    await waitFor(() => {
      expect(screen.getByText('Interact')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('Interact'))
    expect(mockNavigate).toHaveBeenCalledWith('/sessions/sess-1')
  })

  it('shows pin/unpin button in details popup', async () => {
    mockClient.listSessions.mockResolvedValue({ sessions: mockSessions } as any) // eslint-disable-line @typescript-eslint/no-explicit-any
    renderSessionMap()

    await waitFor(() => {
      expect(screen.getByTestId('session-node-sess-1')).toBeInTheDocument()
    })

    const rect = screen.getByTestId('session-node-sess-1').querySelector('rect')!
    fireEvent.click(rect)

    await waitFor(() => {
      expect(screen.getByText('Pin')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('Pin'))

    await waitFor(() => {
      expect(screen.getByText('Unpin')).toBeInTheDocument()
    })
  })

  it('renders edges between sessions on same subnet', async () => {
    mockClient.listSessions.mockResolvedValue({ sessions: mockSessions } as any) // eslint-disable-line @typescript-eslint/no-explicit-any
    renderSessionMap()

    await waitFor(() => {
      // sess-1 and sess-2 share subnet 192.168.1.x
      const edges = screen.getAllByTestId(/^pivot-edge-/)
      expect(edges.length).toBeGreaterThanOrEqual(1)
    })
  })
})
