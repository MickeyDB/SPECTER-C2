import { describe, it, expect } from 'vitest'

describe('Web UI setup', () => {
  it('generates TypeScript from proto files', async () => {
    const { SpecterService } = await import('@/gen/specter/v1/specter_service_pb')
    expect(SpecterService).toBeDefined()
  })

  it('creates gRPC transport', async () => {
    const { transport } = await import('@/lib/transport')
    expect(transport).toBeDefined()
  })
})
