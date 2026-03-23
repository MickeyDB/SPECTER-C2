import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, act } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { TopBar } from '@/components/layout/TopBar'

// Track listeners registered on window so we can trigger them in tests.
const listeners: Record<string, Set<EventListenerOrEventListenerObject>> = {}

function captureListener(
  event: string,
  cb: EventListenerOrEventListenerObject,
) {
  if (!listeners[event]) listeners[event] = new Set()
  listeners[event].add(cb)
}

function removeListener(
  event: string,
  cb: EventListenerOrEventListenerObject,
) {
  listeners[event]?.delete(cb)
}

function fireWindowEvent(event: string) {
  listeners[event]?.forEach((cb) => {
    if (typeof cb === 'function') cb(new Event(event))
    else cb.handleEvent(new Event(event))
  })
}

// Stub navigator.onLine
let onLineValue = true
Object.defineProperty(navigator, 'onLine', {
  get: () => onLineValue,
  configurable: true,
})

beforeEach(() => {
  onLineValue = true
  Object.keys(listeners).forEach((k) => listeners[k].clear())

  vi.spyOn(window, 'addEventListener').mockImplementation(
    (event: string, cb: EventListenerOrEventListenerObject) => {
      captureListener(event, cb)
    },
  )
  vi.spyOn(window, 'removeEventListener').mockImplementation(
    (event: string, cb: EventListenerOrEventListenerObject) => {
      removeListener(event, cb)
    },
  )
})

afterEach(() => {
  vi.restoreAllMocks()
})

function renderTopBar() {
  return render(
    <MemoryRouter initialEntries={['/dashboard']}>
      <TopBar />
    </MemoryRouter>,
  )
}

describe('TopBar offline indicator', () => {
  it('does not show offline indicator when online', () => {
    onLineValue = true
    renderTopBar()
    expect(screen.queryByTestId('offline-indicator')).toBeNull()
  })

  it('shows offline indicator when navigator is offline', () => {
    onLineValue = false
    renderTopBar()
    expect(screen.getByTestId('offline-indicator')).toBeInTheDocument()
    expect(screen.getByTestId('offline-indicator')).toHaveTextContent('Offline')
  })

  it('shows indicator when going offline and hides when coming back online', () => {
    onLineValue = true
    renderTopBar()
    expect(screen.queryByTestId('offline-indicator')).toBeNull()

    // Simulate going offline
    act(() => {
      onLineValue = false
      fireWindowEvent('offline')
    })
    expect(screen.getByTestId('offline-indicator')).toBeInTheDocument()

    // Simulate going back online
    act(() => {
      onLineValue = true
      fireWindowEvent('online')
    })
    expect(screen.queryByTestId('offline-indicator')).toBeNull()
  })
})
