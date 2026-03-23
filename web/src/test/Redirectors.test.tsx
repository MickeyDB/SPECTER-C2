import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { Redirectors } from '@/pages/Redirectors'
import { specterClient } from '@/lib/client'

vi.mock('@/lib/client', () => ({
  specterClient: {
    listRedirectors: vi.fn().mockRejectedValue(new Error('not connected')),
    listProfiles: vi.fn().mockRejectedValue(new Error('not connected')),
    deployRedirector: vi.fn().mockRejectedValue(new Error('not connected')),
    destroyRedirector: vi.fn().mockRejectedValue(new Error('not connected')),
    burnRedirector: vi.fn().mockRejectedValue(new Error('not connected')),
    getRedirectorHealth: vi.fn().mockRejectedValue(new Error('not connected')),
    addDomainToPool: vi.fn().mockRejectedValue(new Error('not connected')),
  },
}))

vi.mock('@bufbuild/protobuf', () => ({
  create: vi.fn((_schema: unknown, data: unknown) => data),
}))

const mockClient = vi.mocked(specterClient)

function renderRedirectors() {
  return render(
    <MemoryRouter initialEntries={['/redirectors']}>
      <Redirectors />
    </MemoryRouter>
  )
}

describe('Redirectors', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the page heading', () => {
    renderRedirectors()
    expect(screen.getByText('Redirectors')).toBeInTheDocument()
    expect(screen.getByText('Manage redirector infrastructure and domain pool')).toBeInTheDocument()
  })

  it('renders the deploy button', () => {
    renderRedirectors()
    expect(screen.getByText('Deploy')).toBeInTheDocument()
  })

  it('renders the refresh button', () => {
    renderRedirectors()
    expect(screen.getByText('Refresh')).toBeInTheDocument()
  })

  it('renders the search input', () => {
    renderRedirectors()
    expect(screen.getByPlaceholderText('Search redirectors...')).toBeInTheDocument()
  })

  it('renders the domain pool section', () => {
    renderRedirectors()
    expect(screen.getByText('Domain Pool')).toBeInTheDocument()
  })

  it('renders the add domain input', () => {
    renderRedirectors()
    expect(screen.getByPlaceholderText('Add domain...')).toBeInTheDocument()
  })

  it('renders the add domain button', () => {
    renderRedirectors()
    expect(screen.getByText('Add')).toBeInTheDocument()
  })

  it('shows empty state when no redirectors', async () => {
    mockClient.listRedirectors.mockResolvedValue({ redirectors: [] } as any) // eslint-disable-line @typescript-eslint/no-explicit-any
    mockClient.listProfiles.mockResolvedValue({ profiles: [] } as any) // eslint-disable-line @typescript-eslint/no-explicit-any

    renderRedirectors()

    await vi.waitFor(() => {
      expect(screen.getByText('No redirectors found')).toBeInTheDocument()
    })
  })

  it('shows error when connection fails', async () => {
    mockClient.listRedirectors.mockRejectedValue(new Error('not connected'))
    mockClient.listProfiles.mockRejectedValue(new Error('not connected'))

    renderRedirectors()

    await vi.waitFor(
      () => {
        expect(screen.getByText(/Unable to connect to teamserver/)).toBeInTheDocument()
      },
      { timeout: 3000 }
    )
  })
})

describe('Redirectors with data', () => {
  beforeEach(() => {
    vi.clearAllMocks()

    mockClient.listRedirectors.mockResolvedValue({
      redirectors: [
        {
          id: 'redir-1',
          name: 'cdn-east',
          redirectorType: 'HTTP',
          provider: 'AWS',
          domain: 'cdn-east.example.com',
          state: 'running',
          backendUrl: 'https://ts.internal:50051',
          configYaml: 'provider: AWS',
        },
        {
          id: 'redir-2',
          name: 'dns-west',
          redirectorType: 'DNS',
          provider: 'Cloudflare',
          domain: 'dns-west.example.com',
          state: 'degraded',
          backendUrl: 'https://ts.internal:50051',
          configYaml: 'provider: Cloudflare',
        },
        {
          id: 'redir-3',
          name: 'azure-eu',
          redirectorType: 'HTTP',
          provider: 'Azure',
          domain: 'azure-eu.example.com',
          state: 'stopped',
          backendUrl: 'https://ts.internal:50051',
          configYaml: 'provider: Azure',
        },
      ],
    } as any) // eslint-disable-line @typescript-eslint/no-explicit-any

    mockClient.listProfiles.mockResolvedValue({
      profiles: [
        {
          id: 'prof-1',
          name: 'default-http',
          description: 'Default HTTP profile',
          yamlContent: '',
        },
      ],
    } as any) // eslint-disable-line @typescript-eslint/no-explicit-any
  })

  it('displays redirector cards', async () => {
    renderRedirectors()

    await vi.waitFor(() => {
      expect(screen.getByText('cdn-east')).toBeInTheDocument()
      expect(screen.getByText('dns-west')).toBeInTheDocument()
      expect(screen.getByText('azure-eu')).toBeInTheDocument()
    })
  })

  it('displays redirector domains', async () => {
    renderRedirectors()

    await vi.waitFor(() => {
      expect(screen.getByText('cdn-east.example.com')).toBeInTheDocument()
      expect(screen.getByText('dns-west.example.com')).toBeInTheDocument()
    })
  })

  it('displays redirector state badges', async () => {
    renderRedirectors()

    await vi.waitFor(() => {
      expect(screen.getByText('running')).toBeInTheDocument()
      expect(screen.getByText('degraded')).toBeInTheDocument()
      expect(screen.getByText('stopped')).toBeInTheDocument()
    })
  })

  it('displays action buttons on each card', async () => {
    renderRedirectors()

    await vi.waitFor(() => {
      const healthButtons = screen.getAllByText('Health')
      const burnButtons = screen.getAllByText('Burn')
      const destroyButtons = screen.getAllByText('Destroy')
      expect(healthButtons).toHaveLength(3)
      expect(burnButtons).toHaveLength(3)
      expect(destroyButtons).toHaveLength(3)
    })
  })

  it('filters redirectors by search query', async () => {
    renderRedirectors()

    await vi.waitFor(() => {
      expect(screen.getByText('cdn-east')).toBeInTheDocument()
    })

    const searchInput = screen.getByPlaceholderText('Search redirectors...')
    fireEvent.change(searchInput, { target: { value: 'cdn' } })

    expect(screen.getByText('cdn-east')).toBeInTheDocument()
    expect(screen.queryByText('dns-west')).not.toBeInTheDocument()
  })

  it('shows burn confirmation dialog', async () => {
    renderRedirectors()

    await vi.waitFor(() => {
      expect(screen.getByText('cdn-east')).toBeInTheDocument()
    })

    const burnButtons = screen.getAllByText('Burn')
    fireEvent.click(burnButtons[0])

    expect(screen.getByText(/Burn & Replace: cdn-east/)).toBeInTheDocument()
    expect(screen.getByText(/burn the current redirector/)).toBeInTheDocument()
    expect(screen.getByText('Cancel')).toBeInTheDocument()
  })

  it('shows destroy confirmation dialog', async () => {
    renderRedirectors()

    await vi.waitFor(() => {
      expect(screen.getByText('cdn-east')).toBeInTheDocument()
    })

    const destroyButtons = screen.getAllByTitle('Destroy')
    fireEvent.click(destroyButtons[0])

    expect(screen.getByText(/Destroy: cdn-east/)).toBeInTheDocument()
    expect(screen.getByText(/permanently destroy/)).toBeInTheDocument()
  })

  it('opens deploy wizard', async () => {
    renderRedirectors()

    // The Deploy button in the header
    const deployButton = screen.getAllByText('Deploy')[0]
    fireEvent.click(deployButton)

    expect(screen.getByText('Deploy Redirector')).toBeInTheDocument()
    expect(screen.getByText('Select Provider')).toBeInTheDocument()
  })

  it('navigates deploy wizard steps', async () => {
    renderRedirectors()

    const deployButton = screen.getAllByText('Deploy')[0]
    fireEvent.click(deployButton)

    // Select AWS provider from the wizard grid
    const providerButtons = screen.getAllByText('AWS')
    // The last one is in the deploy wizard
    fireEvent.click(providerButtons[providerButtons.length - 1])

    // Click Next
    fireEvent.click(screen.getByText('Next'))

    // Should be on domain step
    expect(screen.getByPlaceholderText('redirector.example.com')).toBeInTheDocument()
  })

  it('adds domain to pool', async () => {
    renderRedirectors()

    await vi.waitFor(() => {
      expect(screen.getByText('Domain Pool')).toBeInTheDocument()
    })

    const domainInput = screen.getByPlaceholderText('Add domain...')
    fireEvent.change(domainInput, { target: { value: 'test.example.com' } })
    fireEvent.click(screen.getByText('Add'))

    await vi.waitFor(() => {
      expect(screen.getByText('test.example.com')).toBeInTheDocument()
    })
  })
})
