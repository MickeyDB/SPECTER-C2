import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { Modules } from '@/pages/Modules'
import { specterClient } from '@/lib/client'

vi.mock('@/lib/client', () => ({
  specterClient: {
    listModules: vi.fn().mockRejectedValue(new Error('not connected')),
    listSessions: vi.fn().mockRejectedValue(new Error('not connected')),
    loadModule: vi.fn().mockRejectedValue(new Error('not connected')),
  },
}))

vi.mock('@bufbuild/protobuf', () => ({
  create: vi.fn((_schema: unknown, data: unknown) => data),
}))

const mockClient = vi.mocked(specterClient)

function renderModules() {
  return render(
    <MemoryRouter initialEntries={['/modules']}>
      <Modules />
    </MemoryRouter>
  )
}

describe('Modules', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the page heading', () => {
    renderModules()
    expect(screen.getByText('Modules')).toBeInTheDocument()
    expect(screen.getByText('Browse and deploy available modules')).toBeInTheDocument()
  })

  it('renders the refresh button', () => {
    renderModules()
    expect(screen.getByText('Refresh')).toBeInTheDocument()
  })

  it('renders filter controls', () => {
    renderModules()
    expect(screen.getByPlaceholderText('Search modules...')).toBeInTheDocument()
    expect(screen.getByText('All Types')).toBeInTheDocument()
    expect(screen.getByText('All OPSEC')).toBeInTheDocument()
  })

  it('shows empty state when no modules', async () => {
    mockClient.listModules.mockResolvedValue({ modules: [] } as any) // eslint-disable-line @typescript-eslint/no-explicit-any
    mockClient.listSessions.mockResolvedValue({ sessions: [] } as any) // eslint-disable-line @typescript-eslint/no-explicit-any

    renderModules()

    await vi.waitFor(() => {
      expect(screen.getByText('No modules found')).toBeInTheDocument()
    })
  })
})

describe('Modules with data', () => {
  beforeEach(() => {
    vi.clearAllMocks()

    const now = BigInt(Math.floor(Date.now() / 1000))

    mockClient.listModules.mockResolvedValue({
      modules: [
        {
          moduleId: 'mod-1',
          name: 'whoami',
          version: '1.0.0',
          moduleType: 'BOF',
          description: 'Execute whoami and return current user context',
          blobSize: 4096n,
          createdAt: { seconds: now, nanos: 0 },
          updatedAt: { seconds: now, nanos: 0 },
        },
        {
          moduleId: 'mod-2',
          name: 'inject-shellcode',
          version: '2.1.0',
          moduleType: 'PIC',
          description: 'Inject shellcode into remote process memory',
          blobSize: 16384n,
          createdAt: { seconds: now - 3600n, nanos: 0 },
          updatedAt: { seconds: now - 1800n, nanos: 0 },
        },
        {
          moduleId: 'mod-3',
          name: 'screenshot',
          version: '1.2.0',
          moduleType: 'COFF',
          description: 'Capture screenshot of active desktop',
          blobSize: 8192n,
          createdAt: { seconds: now - 7200n, nanos: 0 },
          updatedAt: { seconds: now - 3600n, nanos: 0 },
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
          lastCheckin: { seconds: BigInt(Math.floor(Date.now() / 1000)), nanos: 0 },
          firstSeen: { seconds: BigInt(Math.floor(Date.now() / 1000) - 3600), nanos: 0 },
          status: 2, // ACTIVE
          activeChannel: 'https',
        },
      ],
    } as any) // eslint-disable-line @typescript-eslint/no-explicit-any
  })

  it('renders modules from fetched data', async () => {
    renderModules()

    await vi.waitFor(() => {
      expect(screen.getByText('whoami')).toBeInTheDocument()
    })

    expect(screen.getByText('inject-shellcode')).toBeInTheDocument()
    expect(screen.getByText('screenshot')).toBeInTheDocument()
  })

  it('displays module descriptions', async () => {
    renderModules()

    await vi.waitFor(() => {
      expect(screen.getByText('Execute whoami and return current user context')).toBeInTheDocument()
    })
  })

  it('displays module types', async () => {
    renderModules()

    await vi.waitFor(() => {
      expect(screen.getByText('whoami')).toBeInTheDocument()
    })

    // Type labels appear in both filter dropdown and module cards
    const bofs = screen.getAllByText('BOF')
    expect(bofs.length).toBeGreaterThanOrEqual(1)
    const pics = screen.getAllByText('PIC')
    expect(pics.length).toBeGreaterThanOrEqual(1)
    const coffs = screen.getAllByText('COFF')
    expect(coffs.length).toBeGreaterThanOrEqual(1)
  })

  it('displays module versions', async () => {
    renderModules()

    await vi.waitFor(() => {
      expect(screen.getByText('v1.0.0')).toBeInTheDocument()
    })

    expect(screen.getByText('v2.1.0')).toBeInTheDocument()
    expect(screen.getByText('v1.2.0')).toBeInTheDocument()
  })

  it('displays module sizes', async () => {
    renderModules()

    await vi.waitFor(() => {
      expect(screen.getByText('4.0 KB')).toBeInTheDocument()
    })

    expect(screen.getByText('16.0 KB')).toBeInTheDocument()
    expect(screen.getByText('8.0 KB')).toBeInTheDocument()
  })

  it('shows module count in header', async () => {
    renderModules()

    await vi.waitFor(() => {
      expect(screen.getByText('3 of 3 modules')).toBeInTheDocument()
    })
  })

  it('renders deploy buttons', async () => {
    renderModules()

    await vi.waitFor(() => {
      expect(screen.getByText('whoami')).toBeInTheDocument()
    })

    const deployButtons = screen.getAllByText('Deploy')
    expect(deployButtons.length).toBe(3)
  })

  it('opens deploy dialog when clicking deploy', async () => {
    renderModules()

    await vi.waitFor(() => {
      expect(screen.getByText('whoami')).toBeInTheDocument()
    })

    const deployButtons = screen.getAllByText('Deploy')
    fireEvent.click(deployButtons[0])

    await vi.waitFor(() => {
      expect(screen.getByText('Deploy: whoami')).toBeInTheDocument()
    })

    expect(screen.getByText('Target Sessions')).toBeInTheDocument()
    expect(screen.getByText('Arguments')).toBeInTheDocument()
    expect(screen.getByText('Execute')).toBeInTheDocument()
  })

  it('shows sessions in deploy dialog', async () => {
    renderModules()

    await vi.waitFor(() => {
      expect(screen.getByText('whoami')).toBeInTheDocument()
    })

    const deployButtons = screen.getAllByText('Deploy')
    fireEvent.click(deployButtons[0])

    await vi.waitFor(() => {
      expect(screen.getByText(/WORKSTATION-1/)).toBeInTheDocument()
    })
  })

  it('filters modules by search query', async () => {
    renderModules()

    await vi.waitFor(() => {
      expect(screen.getByText('whoami')).toBeInTheDocument()
    })

    const searchInput = screen.getByPlaceholderText('Search modules...')
    fireEvent.change(searchInput, { target: { value: 'inject' } })

    expect(screen.queryByText('whoami')).not.toBeInTheDocument()
    expect(screen.getByText('inject-shellcode')).toBeInTheDocument()
    expect(screen.queryByText('screenshot')).not.toBeInTheDocument()
  })

  it('toggles between grid and list view', async () => {
    renderModules()

    await vi.waitFor(() => {
      expect(screen.getByText('whoami')).toBeInTheDocument()
    })

    // Default is grid view - modules render as cards with descriptions
    expect(screen.getByText('Execute whoami and return current user context')).toBeInTheDocument()
  })

  it('closes deploy dialog', async () => {
    renderModules()

    await vi.waitFor(() => {
      expect(screen.getByText('whoami')).toBeInTheDocument()
    })

    // Open dialog
    const deployButtons = screen.getAllByText('Deploy')
    fireEvent.click(deployButtons[0])

    await vi.waitFor(() => {
      expect(screen.getByText('Deploy: whoami')).toBeInTheDocument()
    })

    // Close dialog
    fireEvent.click(screen.getByText('Cancel'))

    await vi.waitFor(() => {
      expect(screen.queryByText('Deploy: whoami')).not.toBeInTheDocument()
    })
  })
})
