import { useEffect, useRef, useState } from 'react'
import { API_BASE } from '../config.js'

// ── Demo quick-prompts for live presentation ──────────────────────────────────
const DEMO_PROMPTS = [
  "What are the most critical vulnerabilities right now?",
  "Are there any actively exploited CVEs in the CISA KEV list?",
  "Summarize the ransomware activity in the last 7 days",
  "What threat actors are targeting critical infrastructure?",
  "Is there evidence of supply chain attacks this week?",
]

// ── Minimal markdown renderer (handles what ARIA actually outputs) ────────────
function renderMarkdown(text) {
  if (!text) return []

  const lines = text.split('\n')
  const elements = []
  let i = 0
  let listBuffer = []

  const flushList = () => {
    if (listBuffer.length > 0) {
      elements.push(
        <ul key={`ul-${i}`} className="aria-list">
          {listBuffer.map((item, j) => (
            <li key={j} dangerouslySetInnerHTML={{ __html: inlineFormat(item) }} />
          ))}
        </ul>
      )
      listBuffer = []
    }
  }

  const inlineFormat = (str) =>
    str
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/`([^`]+)`/g, '<code class="aria-code">$1</code>')

  while (i < lines.length) {
    const line = lines[i]

    // Table rows
    if (line.startsWith('|')) {
      flushList()
      const cells = line.split('|').filter(c => c.trim() !== '').map(c => c.trim())
      const isSeparator = cells.every(c => /^[-: ]+$/.test(c))
      if (!isSeparator) {
        // peek if the next line is a separator to determine if this is a header
        const nextIsSep = lines[i + 1] && lines[i + 1].startsWith('|') &&
          lines[i + 1].split('|').filter(c => c.trim()).every(c => /^[-: ]+$/.test(c.trim()))
        if (nextIsSep) {
          elements.push(
            <table key={`tbl-${i}`} className="aria-table">
              <thead>
                <tr>{cells.map((c, j) => <th key={j} dangerouslySetInnerHTML={{ __html: inlineFormat(c) }} />)}</tr>
              </thead>
              <tbody id={`tbody-${i}`} />
            </table>
          )
          i += 2 // skip separator
          // collect body rows
          const tbodyRows = []
          while (i < lines.length && lines[i].startsWith('|')) {
            const rowCells = lines[i].split('|').filter(c => c.trim() !== '').map(c => c.trim())
            tbodyRows.push(
              <tr key={i}>{rowCells.map((c, j) => <td key={j} dangerouslySetInnerHTML={{ __html: inlineFormat(c) }} />)}</tr>
            )
            i++
          }
          // We already pushed the table above — rebuild with body
          elements[elements.length - 1] = (
            <table key={`tbl-${i}`} className="aria-table">
              <thead>
                <tr>{cells.map((c, j) => <th key={j} dangerouslySetInnerHTML={{ __html: inlineFormat(c) }} />)}</tr>
              </thead>
              <tbody>{tbodyRows}</tbody>
            </table>
          )
          continue
        } else {
          elements.push(
            <tr key={`tr-${i}`} className="aria-table-row">
              {cells.map((c, j) => <td key={j} dangerouslySetInnerHTML={{ __html: inlineFormat(c) }} />)}
            </tr>
          )
        }
      }
      i++
      continue
    }

    // Section headings: ## Heading or **Heading** alone on a line
    if (/^#{1,3} /.test(line)) {
      flushList()
      const text = line.replace(/^#{1,3} /, '')
      elements.push(
        <div key={`h-${i}`} className="aria-section-head"
          dangerouslySetInnerHTML={{ __html: inlineFormat(text) }} />
      )
      i++
      continue
    }
    if (/^\*\*[^*]+\*\*$/.test(line.trim())) {
      flushList()
      const text = line.trim().replace(/^\*\*|\*\*$/g, '')
      elements.push(<div key={`h-${i}`} className="aria-section-head">{text}</div>)
      i++
      continue
    }

    // Bullet list
    if (/^[-*\d.] /.test(line)) {
      listBuffer.push(line.replace(/^[-*\d.] /, ''))
      i++
      continue
    }

    flushList()

    // Blank line — spacer
    if (line.trim() === '') {
      elements.push(<div key={`br-${i}`} className="aria-spacer" />)
      i++
      continue
    }

    // Regular paragraph line
    elements.push(
      <p key={`p-${i}`} className="aria-para"
        dangerouslySetInnerHTML={{ __html: inlineFormat(line) }} />
    )
    i++
  }
  flushList()
  return elements
}

// ── Component ─────────────────────────────────────────────────────────────────

function createMessage(role, content) {
  return { role, content, ts: new Date().toISOString() }
}

function ChatWidget() {
  const [open, setOpen] = useState(false)
  const [messages, setMessages] = useState([
    createMessage(
      'assistant',
      "**ARIA online.** I'm your Automated Risk Intelligence Analyst. Ask me about active CVEs, threat actors, IOC patterns, or what's changed in the last 24 hours."
    ),
  ])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [showPrompts, setShowPrompts] = useState(true)
  const bodyRef = useRef(null)

  useEffect(() => {
    if (bodyRef.current) {
      bodyRef.current.scrollTop = bodyRef.current.scrollHeight
    }
  }, [messages, loading])

  const formatTime = (ts) => {
    if (!ts) return ''
    const d = new Date(ts)
    if (Number.isNaN(d.getTime())) return ''
    return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
  }

  const sendMessage = async (overrideText) => {
    const text = (overrideText ?? input).trim()
    if (!text || loading) return
    const userMsg = createMessage('user', text)
    const nextMessages = [...messages, userMsg]
    setMessages(nextMessages)
    setInput('')
    setShowPrompts(false)
    setLoading(true)
    setError('')

    try {
      const res = await fetch(`${API_BASE}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ messages: nextMessages }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok || data.error) throw new Error(data.error || `Chat failed (${res.status})`)
      if (data.message) {
        setMessages((prev) => [...prev, createMessage('assistant', data.message.content || '')])
      }
    } catch (e) {
      setError(e.message || 'Failed to get a response')
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      <button
        type="button"
        className="chat-launcher"
        onClick={() => setOpen(v => !v)}
        aria-label="Open ARIA threat analyst"
        title="Ask ARIA"
      >
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
        </svg>
      </button>

      {open && (
        <div className="chat-panel">
          <header className="chat-header">
            <div className="chat-header-left">
              <div className="chat-header-avatar">AI</div>
              <div className="chat-header-text">
                <h3 className="chat-title">ARIA</h3>
                <p className="chat-subtitle">Automated Risk Intelligence Analyst · RAG · GPT-4o</p>
              </div>
            </div>
            <button type="button" className="chat-close" onClick={() => setOpen(false)} aria-label="Close">×</button>
          </header>

          <div className="chat-body" ref={bodyRef}>
            {messages.map((m, idx) => (
              <div key={idx} className={`chat-message chat-message--${m.role === 'user' ? 'user' : 'assistant'}`}>
                <div className="chat-message-bubble">
                  {m.role === 'assistant'
                    ? <div className="chat-message-content aria-content">{renderMarkdown(m.content)}</div>
                    : <div className="chat-message-content">{m.content}</div>
                  }
                  <div className="chat-message-meta">{formatTime(m.ts)}</div>
                </div>
              </div>
            ))}
            {error && <div className="chat-error">{error}</div>}
            {loading && (
              <div className="chat-message chat-message--assistant chat-typing">
                <div className="chat-message-bubble">
                  <span className="chat-typing-dot" /><span className="chat-typing-dot" /><span className="chat-typing-dot" />
                </div>
              </div>
            )}
          </div>

          {showPrompts && (
            <div className="chat-prompts">
              <div className="chat-prompts-label">Quick queries</div>
              {DEMO_PROMPTS.map(p => (
                <button key={p} className="chat-prompt-btn" onClick={() => sendMessage(p)}>
                  {p}
                </button>
              ))}
            </div>
          )}

          <form className="chat-input-row" onSubmit={e => { e.preventDefault(); sendMessage() }}>
            <textarea
              className="chat-input"
              rows={1}
              placeholder="Ask ARIA about CVEs, threat actors, IOCs…"
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage() } }}
            />
            <button type="submit" className="chat-send" disabled={loading || !input.trim()}>↑</button>
          </form>
        </div>
      )}
    </>
  )
}

export default ChatWidget
