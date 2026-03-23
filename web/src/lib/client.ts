import { createClient } from '@connectrpc/connect'
import { SpecterService } from '@/gen/specter/v1/specter_service_pb'
import { transport } from './transport'

/**
 * Typed gRPC-Web client for the SPECTER teamserver.
 * Usage: `const sessions = await specterClient.listSessions({})`
 */
export const specterClient = createClient(SpecterService, transport)
