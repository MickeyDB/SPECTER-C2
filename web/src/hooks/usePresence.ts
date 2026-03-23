import { useCallback } from 'react'
import { useCollaborationStore } from '@/store/collaborationStore'
import { useGrpcStream } from './useGrpcStream'
import { create } from '@bufbuild/protobuf'
import type { Event } from '@/gen/specter/v1/specter_service_pb'
import { PresenceInfoSchema } from '@/gen/specter/v1/collaboration_pb'
import { ChatMessageSchema } from '@/gen/specter/v1/collaboration_pb'

/**
 * Hook that subscribes to operator presence updates via the
 * existing SubscribeEvents stream and updates the collaboration store.
 *
 * Presence and chat events arrive as part of the unified Event stream
 * (fields presence_update and chat_message in the Event oneof).
 */
export function usePresence(options: { enabled?: boolean } = {}) {
  const { enabled = true } = options
  const { updateOperator, addChatMessage } = useCollaborationStore()

  const handleEvent = useCallback(
    (event: Event) => {
      // Handle presence updates
      if (
        event.event.case === 'presenceUpdate' &&
        event.event.value?.presence
      ) {
        const presence = event.event.value.presence
        updateOperator(create(PresenceInfoSchema, {
          operatorId: presence.operatorId ?? '',
          username: presence.username ?? '',
          status: presence.status ?? 0,
          activeSessionId: presence.activeSessionId ?? '',
          lastActivity: presence.lastActivity,
        }))
      }

      // Handle chat messages
      if (event.event.case === 'chatMessage' && event.event.value) {
        const msg = event.event.value
        addChatMessage(create(ChatMessageSchema, {
          id: msg.id ?? '',
          senderId: msg.senderId ?? '',
          senderUsername: msg.senderUsername ?? '',
          content: msg.content ?? '',
          channel: msg.channel ?? 'global',
          timestamp: msg.timestamp,
        }))
      }
    },
    [updateOperator, addChatMessage],
  )

  const { connected } = useGrpcStream({
    enabled,
    onEvent: handleEvent,
  })

  return { connected }
}
