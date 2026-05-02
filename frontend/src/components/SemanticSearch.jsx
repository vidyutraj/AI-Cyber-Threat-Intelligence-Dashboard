import { useState, useRef } from 'react'
import './SemanticSearch.css'

import { API_BASE } from '../config.js'

const QUICK_QUERIES = [
  'ransomware targeting critical infrastructure',
  'zero-day exploit actively exploited in the wild',
  'supply chain attack software compromise',
  'phishing campaign credential theft',
  'Chinese state-sponsored APT intrusion',
  'CISA advisory high severity vulnerability',
]

function ScoreDot({ score }) {
  const pct = Math.round(score * 100)
  const color =
    pct >= 70 ? '#7ee787' :
    pct >= 45 ? '#e3b341' :
    '#94a3b8'
  return (
    <span className="ss-score-dot" style={{ background: color }} title={`Similarity: ${pct}%`}>
      {pct}%
    </span>
  )
}

export default function SemanticSearch({ hours = 1440 }) {
  const [query, setQuery] = useState('')
  const [results, setResults] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [mode, setMode] = useState('')
  const inputRef = useRef(null)

  const search = async (q) => {
    const text = (q || query).trim()
    if (!text) return
    setLoading(true)
    setError('')
    setResults(null)
    try {
      const res = await fetch(
        `${API_BASE}/api/intel/similar?q=${encodeURIComponent(text)}&top_k=12&hours=${hours}`
      )
      const json = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(json.error || 'Search failed')
      setResults(json.results || [])
      setMode(json.mode || '')
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') search()
  }

  return (
    <div className="ss-container">
      <div className="ss-search-bar">
        <input
          ref={inputRef}
          className="ss-input"
          type="text"
          placeholder="Search threat intel semantically… e.g. 'ransomware targeting healthcare'"
          value={query}
          onChange={e => setQuery(e.target.value)}
          onKeyDown={handleKeyDown}
        />
        <button
          className="ss-btn"
          onClick={() => search()}
          disabled={loading || !query.trim()}
        >
          {loading ? (
            <span className="ss-spinner" />
          ) : (
            <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
              <path d="M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.867-3.834zm-5.242 1.156a5 5 0 1 1 0-10 5 5 0 0 1 0 10z"/>
            </svg>
          )}
        </button>
      </div>

      <div className="ss-quick-queries">
        {QUICK_QUERIES.map(q => (
          <button
            key={q}
            className="ss-quick-btn"
            onClick={() => { setQuery(q); search(q) }}
          >
            {q}
          </button>
        ))}
      </div>

      {error && <div className="ss-error">{error}</div>}

      {mode && results !== null && (
        <div className="ss-mode-badge">
          {mode === 'openai_knn'
            ? '✦ OpenAI text-embedding-3-small · cosine KNN'
            : '◈ TF-IDF cosine similarity (no API key)'}
        </div>
      )}

      {results !== null && results.length === 0 && (
        <div className="ss-empty">No articles matched this query in the corpus.</div>
      )}

      {results !== null && results.length > 0 && (
        <div className="ss-results">
          {results.map((r, i) => (
            <a
              key={r.id || i}
              href={r.url || '#'}
              className="ss-result"
              target="_blank"
              rel="noreferrer"
            >
              <div className="ss-result__head">
                <ScoreDot score={r.score} />
                <span className="ss-result__source">{r.source_label}</span>
                <span className="ss-result__date">{(r.published_at || '').slice(0, 10)}</span>
              </div>
              <div className="ss-result__title">{r.title}</div>
              {r.snippet && (
                <div className="ss-result__snippet">
                  {r.snippet.slice(0, 200)}{r.snippet.length > 200 ? '…' : ''}
                </div>
              )}
            </a>
          ))}
        </div>
      )}
    </div>
  )
}
