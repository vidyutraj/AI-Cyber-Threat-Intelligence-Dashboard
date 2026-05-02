import { useEffect, useState } from 'react'
import './KillChainView.css'

import { API_BASE } from '../config.js'

const TACTIC_COLORS = {
  'Reconnaissance':       '#64748b',
  'Resource Development': '#64748b',
  'Initial Access':       '#ef4444',
  'Execution':            '#f97316',
  'Persistence':          '#eab308',
  'Privilege Escalation': '#a855f7',
  'Defense Evasion':      '#06b6d4',
  'Credential Access':    '#ec4899',
  'Discovery':            '#3b82f6',
  'Lateral Movement':     '#8b5cf6',
  'Collection':           '#10b981',
  'C2':                   '#f59e0b',
  'Exfiltration':         '#6366f1',
  'Impact':               '#dc2626',
}

function TacticCard({ tactic, maxArticles, onClick, active }) {
  const pct = Math.max(6, (tactic.article_count / Math.max(maxArticles, 1)) * 100)
  const color = TACTIC_COLORS[tactic.tactic_label] || '#8b949e'

  return (
    <div
      className={`kc-tactic-card ${active ? 'kc-tactic-card--active' : ''}`}
      onClick={() => onClick(tactic)}
      style={{ '--tactic-color': color }}
      title={`${tactic.tactic_label}\n${tactic.article_count} articles, ${tactic.technique_count} techniques`}
    >
      <div className="kc-tactic-bar" style={{ height: `${pct}%` }} />
      <div className="kc-tactic-count">{tactic.article_count}</div>
      <div className="kc-tactic-label">{tactic.tactic_label}</div>
      <div className="kc-tactic-tech-count">{tactic.technique_count} techs</div>
    </div>
  )
}

function MultiStageArticle({ article }) {
  const phasePct = Math.min(100, (article.chain_length / 14) * 100)
  return (
    <div className="kc-ms-article">
      <div className="kc-ms-article__head">
        <a
          href={article.url || '#'}
          className="kc-ms-article__title"
          target="_blank"
          rel="noreferrer"
        >
          {article.title}
        </a>
        <span className="kc-ms-article__source">{article.source_label}</span>
      </div>
      <div className="kc-ms-chain">
        {article.tactic_labels.map((label, i) => (
          <span
            key={i}
            className="kc-ms-tactic-badge"
            style={{ background: TACTIC_COLORS[label] || '#8b949e' }}
          >
            {label}
          </span>
        ))}
      </div>
      <div className="kc-ms-coverage">
        <div
          className="kc-ms-coverage__fill"
          style={{ width: `${phasePct}%` }}
          title={`Covers ${article.chain_length} of 14 ATT&CK tactics`}
        />
        <span className="kc-ms-coverage__label">
          {article.chain_length} / 14 tactics
        </span>
      </div>
    </div>
  )
}

export default function KillChainView({ hours = 1440 }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [selected, setSelected] = useState(null)
  const [tab, setTab] = useState('heatmap')

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      setLoading(true)
      setError('')
      try {
        const res = await fetch(`${API_BASE}/api/intel/killchain?hours=${hours}`)
        const json = await res.json().catch(() => ({}))
        if (!res.ok) throw new Error(json.error || 'Kill-chain load failed')
        if (!cancelled) setData(json)
      } catch (e) {
        if (!cancelled) setError(e.message)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    return () => { cancelled = true }
  }, [hours])

  if (loading) return <div className="kc-loading">Mapping MITRE ATT&amp;CK kill chains…</div>
  if (error)   return <div className="kc-error">{error}</div>
  if (!data)   return null

  const tactics = data.tactic_coverage || []
  const maxArt = Math.max(...tactics.map(t => t.article_count), 1)

  const selectedTactic = tactics.find(t => t.tactic_id === selected)

  return (
    <div className="kc-container">
      <div className="kc-tabs">
        <button
          className={`kc-tab ${tab === 'heatmap' ? 'kc-tab--active' : ''}`}
          onClick={() => setTab('heatmap')}
        >Kill Chain Heatmap</button>
        <button
          className={`kc-tab ${tab === 'multistage' ? 'kc-tab--active' : ''}`}
          onClick={() => setTab('multistage')}
        >
          Multi-stage Campaigns
          {data.multi_stage_articles?.length > 0 && (
            <span className="kc-badge">{data.multi_stage_articles.length}</span>
          )}
        </button>
      </div>

      {tab === 'heatmap' && (
        <>
          <div className="kc-stats-row">
            <span>{data.total_articles_with_techniques} articles with MITRE techniques</span>
            <span>{data.total_techniques_seen} distinct techniques observed</span>
            <span>{tactics.length} of 14 tactics active</span>
          </div>
          <div className="kc-heatmap">
            {tactics.length === 0 ? (
              <div className="kc-empty">No MITRE ATT&amp;CK techniques found in the current time window.</div>
            ) : (
              tactics.map(t => (
                <TacticCard
                  key={t.tactic_id}
                  tactic={t}
                  maxArticles={maxArt}
                  onClick={t2 => setSelected(s => s === t2.tactic_id ? null : t2.tactic_id)}
                  active={selected === t.tactic_id}
                />
              ))
            )}
          </div>

          {selectedTactic && (
            <div className="kc-detail">
              <div className="kc-detail__head">
                <span
                  className="kc-detail__tactic"
                  style={{ color: TACTIC_COLORS[selectedTactic.tactic_label] }}
                >
                  {selectedTactic.tactic_label}
                </span>
                <span className="kc-detail__id">{selectedTactic.tactic_id}</span>
                <button className="kc-detail__close" onClick={() => setSelected(null)}>✕</button>
              </div>
              <div className="kc-detail__body">
                <div className="kc-detail__col">
                  <h4>Top techniques in corpus</h4>
                  <ul className="kc-tech-list">
                    {selectedTactic.top_techniques.map(tech => (
                      <li key={tech.id} className="kc-tech-item">
                        <a
                          href={`https://attack.mitre.org/techniques/${tech.id.replace('.', '/')}/`}
                          target="_blank"
                          rel="noreferrer"
                          className="kc-tech-link"
                        >
                          {tech.id}
                        </a>
                        <div className="kc-tech-bar-wrap">
                          <div
                            className="kc-tech-bar"
                            style={{
                              width: `${(tech.count / selectedTactic.top_techniques[0].count) * 100}%`,
                              background: TACTIC_COLORS[selectedTactic.tactic_label],
                            }}
                          />
                        </div>
                        <span className="kc-tech-count">{tech.count}</span>
                      </li>
                    ))}
                  </ul>
                </div>
                <div className="kc-detail__col">
                  <h4>Sample articles</h4>
                  {selectedTactic.sample_articles.map((a, i) => (
                    <a
                      key={i}
                      href={a.url || '#'}
                      className="kc-sample-article"
                      target="_blank"
                      rel="noreferrer"
                    >
                      <span className="kc-sample-src">{a.source_label}</span>
                      {a.title}
                    </a>
                  ))}
                </div>
              </div>
            </div>
          )}
        </>
      )}

      {tab === 'multistage' && (
        <div className="kc-multistage">
          {data.multi_stage_articles?.length === 0 ? (
            <div className="kc-empty">No multi-stage campaign articles detected in this window.</div>
          ) : (
            <>
              <p className="kc-multistage-note">
                Articles below mention MITRE techniques spanning ≥ 3 ATT&amp;CK tactics — they likely
                describe complete multi-stage campaigns rather than isolated incidents.
              </p>
              {(data.multi_stage_articles || []).map((a, i) => (
                <MultiStageArticle key={i} article={a} />
              ))}
            </>
          )}
        </div>
      )}
    </div>
  )
}
