import { useState, useRef, useEffect } from 'react'
import { MessageSquare, X, Send } from 'lucide-react'
import { useCollaborationStore } from '@/store/collaborationStore'
import { specterClient } from '@/lib/client'

export function ChatWidget() {
  const {
    chatOpen,
    toggleChat,
    chatMessages,
    unreadCount,
  } = useCollaborationStore()

  const [input, setInput] = useState('')
  const [sending, setSending] = useState(false)
  const messagesEndRef = useRef<HTMLDivElement>(null)

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    if (chatOpen) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [chatMessages.length, chatOpen])

  const handleSend = async () => {
    if (!input.trim() || sending) return
    const content = input.trim()
    setInput('')
    setSending(true)
    try {
      await specterClient.sendChatMessage({ content, channel: 'global' })
    } catch {
      // Message will arrive via the event stream; if send fails, restore input
      setInput(content)
    } finally {
      setSending(false)
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col items-end gap-2">
      {/* Chat panel */}
      {chatOpen && (
        <div className="w-80 h-96 bg-specter-surface border border-specter-border rounded-lg shadow-xl flex flex-col overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between px-3 py-2 border-b border-specter-border">
            <span className="text-sm font-medium text-specter-text">
              Team Chat
            </span>
            <button
              onClick={toggleChat}
              className="p-1 rounded text-specter-muted hover:text-specter-text hover:bg-specter-border/50 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Messages */}
          <div className="flex-1 overflow-y-auto p-3 space-y-2">
            {chatMessages.length === 0 ? (
              <p className="text-sm text-specter-muted text-center mt-8">
                No messages yet
              </p>
            ) : (
              chatMessages.map((msg) => (
                <div key={msg.id} className="text-sm">
                  <span className="font-medium text-specter-accent">
                    {msg.senderUsername}
                  </span>
                  <span className="text-specter-muted text-xs ml-2">
                    {formatTime(msg.timestamp)}
                  </span>
                  <p className="text-specter-text mt-0.5">{msg.content}</p>
                </div>
              ))
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Input */}
          <div className="flex items-center gap-2 p-2 border-t border-specter-border">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Type a message..."
              className="flex-1 px-2 py-1 text-sm bg-specter-bg border border-specter-border rounded text-specter-text placeholder-specter-muted focus:outline-none focus:border-specter-accent"
            />
            <button
              onClick={handleSend}
              disabled={!input.trim() || sending}
              className="p-1.5 rounded text-specter-accent hover:bg-specter-accent/10 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
            >
              <Send className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Toggle button */}
      <button
        onClick={toggleChat}
        className="relative p-3 bg-specter-accent text-white rounded-full shadow-lg hover:bg-specter-accent/90 transition-colors"
      >
        <MessageSquare className="w-5 h-5" />
        {unreadCount > 0 && !chatOpen && (
          <span className="absolute -top-1 -right-1 w-5 h-5 bg-red-500 text-white text-xs rounded-full flex items-center justify-center">
            {unreadCount > 9 ? '9+' : unreadCount}
          </span>
        )}
      </button>
    </div>
  )
}

function formatTime(ts?: { seconds: bigint | number; nanos: number }): string {
  if (!ts) return ''
  const date = new Date(Number(ts.seconds) * 1000)
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}
