import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { ProfileEditor } from '@/pages/ProfileEditor'
import { specterClient } from '@/lib/client'

vi.mock('@/lib/client', () => ({
  specterClient: {
    listProfiles: vi.fn().mockRejectedValue(new Error('not connected')),
    getProfile: vi.fn().mockRejectedValue(new Error('not connected')),
    createProfile: vi.fn().mockRejectedValue(new Error('not connected')),
    compileProfile: vi.fn().mockRejectedValue(new Error('not connected')),
  },
}))

vi.mock('@bufbuild/protobuf', () => ({
  create: vi.fn((_schema: unknown, data: unknown) => data),
}))

// Mock Monaco Editor - it doesn't render in jsdom
vi.mock('@monaco-editor/react', () => ({
  default: ({
    value,
    onChange,
  }: {
    value: string
    onChange?: (v: string | undefined) => void
  }) => (
    <textarea
      data-testid="monaco-editor"
      value={value}
      onChange={(e) => onChange?.(e.target.value)}
    />
  ),
}))

const mockClient = vi.mocked(specterClient)

function renderProfileEditor() {
  return render(
    <MemoryRouter initialEntries={['/profiles']}>
      <ProfileEditor />
    </MemoryRouter>
  )
}

describe('ProfileEditor', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the page heading', () => {
    renderProfileEditor()
    expect(screen.getByText('Profile Editor')).toBeInTheDocument()
    expect(screen.getByText('Create and edit C2 communication profiles')).toBeInTheDocument()
  })

  it('renders the refresh button', () => {
    renderProfileEditor()
    expect(screen.getByText('Refresh')).toBeInTheDocument()
  })

  it('renders the save button', () => {
    renderProfileEditor()
    expect(screen.getByText('Save')).toBeInTheDocument()
  })

  it('renders the new profile button', () => {
    renderProfileEditor()
    // The + button for creating new profiles
    expect(screen.getByTitle('New Profile')).toBeInTheDocument()
  })

  it('renders the profile name input', () => {
    renderProfileEditor()
    expect(screen.getByPlaceholderText('Profile name')).toBeInTheDocument()
  })

  it('renders the description input', () => {
    renderProfileEditor()
    expect(screen.getByPlaceholderText('Description')).toBeInTheDocument()
  })

  it('renders the editor panel', () => {
    renderProfileEditor()
    expect(screen.getByTestId('editor-panel')).toBeInTheDocument()
  })

  it('renders the preview panel', () => {
    renderProfileEditor()
    expect(screen.getByTestId('preview-panel')).toBeInTheDocument()
    expect(screen.getByText('Live Preview')).toBeInTheDocument()
  })

  it('renders HTTP preview sections', () => {
    renderProfileEditor()
    expect(screen.getByText('GET Request (Check-in)')).toBeInTheDocument()
    expect(screen.getByText('POST Request (Task Results)')).toBeInTheDocument()
  })

  it('renders timing distribution section', () => {
    renderProfileEditor()
    expect(screen.getByText('Timing Distribution')).toBeInTheDocument()
  })

  it('renders JA3 hash section', () => {
    renderProfileEditor()
    expect(screen.getByText('Computed JA3 Hash')).toBeInTheDocument()
  })

  it('renders the Monaco editor mock', () => {
    renderProfileEditor()
    expect(screen.getByTestId('monaco-editor')).toBeInTheDocument()
  })

  it('shows validation status for valid content', () => {
    renderProfileEditor()
    expect(screen.getByText('Valid')).toBeInTheDocument()
  })
})

describe('ProfileEditor with data', () => {
  beforeEach(() => {
    vi.clearAllMocks()

    const now = BigInt(Math.floor(Date.now() / 1000))

    mockClient.listProfiles.mockResolvedValue({
      profiles: [
        {
          id: 'prof-1',
          name: 'default-http',
          description: 'Default HTTP profile',
          yamlContent: 'name: default-http\nhttp:\n  get:\n    uri: /check',
          createdAt: { seconds: now, nanos: 0 },
          updatedAt: { seconds: now, nanos: 0 },
        },
        {
          id: 'prof-2',
          name: 'dns-profile',
          description: 'DNS tunnel profile',
          yamlContent: 'name: dns-profile',
          createdAt: { seconds: now, nanos: 0 },
          updatedAt: { seconds: now, nanos: 0 },
        },
      ],
    } as any) // eslint-disable-line @typescript-eslint/no-explicit-any
  })

  it('displays profile list when loaded', async () => {
    renderProfileEditor()

    await vi.waitFor(() => {
      expect(screen.getByText('default-http')).toBeInTheDocument()
      expect(screen.getByText('dns-profile')).toBeInTheDocument()
    })
  })

  it('displays profile descriptions in sidebar', async () => {
    renderProfileEditor()

    await vi.waitFor(() => {
      expect(screen.getByText('Default HTTP profile')).toBeInTheDocument()
      expect(screen.getByText('DNS tunnel profile')).toBeInTheDocument()
    })
  })

  it('loads profile content on selection', async () => {
    mockClient.getProfile.mockResolvedValue({
      profile: {
        id: 'prof-1',
        name: 'default-http',
        description: 'Default HTTP profile',
        yamlContent: 'name: default-http\nhttp:\n  get:\n    uri: /check',
      },
    } as any) // eslint-disable-line @typescript-eslint/no-explicit-any

    renderProfileEditor()

    await vi.waitFor(() => {
      expect(screen.getByText('default-http')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('default-http'))

    await vi.waitFor(() => {
      expect(mockClient.getProfile).toHaveBeenCalledWith({ id: 'prof-1' })
    })
  })

  it('allows changing the profile name', () => {
    renderProfileEditor()
    const input = screen.getByPlaceholderText('Profile name')
    fireEvent.change(input, { target: { value: 'my-custom-profile' } })
    expect(input).toHaveValue('my-custom-profile')
  })
})

describe('ProfileEditor empty state', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockClient.listProfiles.mockResolvedValue({ profiles: [] } as any) // eslint-disable-line @typescript-eslint/no-explicit-any
  })

  it('shows no profiles message', async () => {
    renderProfileEditor()

    await vi.waitFor(() => {
      expect(screen.getByText('No profiles yet')).toBeInTheDocument()
    })
  })
})

describe('ProfileEditor error state', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockClient.listProfiles.mockRejectedValue(new Error('not connected'))
  })

  it('shows error when connection fails', async () => {
    renderProfileEditor()

    await vi.waitFor(
      () => {
        expect(screen.getByText('Unable to connect to teamserver')).toBeInTheDocument()
      },
      { timeout: 3000 }
    )
  })
})
