import { useEffect, useState } from 'react'

import { API_BASE } from '../config.js'

function Pill({ tone = 'neutral', children }) {
  return <span className={`exec-pill exec-pill--${tone}`}>{children}</span>
}

function severityTone(sev) {
  const v = String(sev || '').toLowerCase()
  if (v === 'high') return 'danger'
  if (v === 'medium') return 'warn'
  if (v === 'low') return 'ok'
  return 'neutral'
}

function urgencyTone(u) {
  const v = String(u || '').toLowerCase()
  if (v === 'immediate') return 'danger'
  if (v === '24h') return 'warn'
  if (v === 'monitor') return 'neutral'
  return 'neutral'
}

function safeArray(v) {
  return Array.isArray(v) ? v : []
}

function formatUtc(iso) {
  if (!iso) return null
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return String(iso)
  return d.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC')
}

function formatAge(seconds) {
  const s = Number(seconds)
  if (!Number.isFinite(s) || s < 0) return null
  if (s < 60) return `${Math.round(s)}s`
  const m = Math.round(s / 60)
  if (m < 60) return `${m}m`
  const h = Math.round(m / 60)
  return `${h}h`
}

export default function IncidentSummaryCard({ hours = 24 }) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [data, setData] = useState(null)
  const [cached, setCached] = useState(false)
  const [effectiveHours, setEffectiveHours] = useState(hours)
  const [sourcesOpen, setSourcesOpen] = useState(false)
  const [sourcesTitle, setSourcesTitle] = useState('')
  const [selectedSourceIds, setSelectedSourceIds] = useState([])
  const [selectedClusterId, setSelectedClusterId] = useState(null)

  useEffect(() => {
    let cancelled = false

    async function load({ force = false } = {}) {
      setLoading(true)
      setError('')
      try {
        const fallbackWindows = [hours, 72, 168].filter((v, i, arr) => arr.indexOf(v) === i)
        let json = {}
        let usedHours = hours
        let success = false
        for (const windowHours of fallbackWindows) {
          const res = await fetch(`${API_BASE}/api/incidents/brief`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ hours: windowHours, force }),
          })
          json = await res.json().catch(() => ({}))
          if (!res.ok) throw new Error(json.error || `Failed to load incident brief (${res.status})`)
          usedHours = windowHours
          const sourcesAnalyzed = Number(json?.meta?.sources_analyzed ?? 0)
          if (sourcesAnalyzed > 0 || windowHours === fallbackWindows[fallbackWindows.length - 1]) {
            success = true
            break
          }
        }
        if (!success) throw new Error('Failed to load incident brief')
        if (!cancelled) {
          setData(json)
          setCached(Boolean(json.cached))
          setEffectiveHours(usedHours)
        }
      } catch (e) {
        if (!cancelled) setError(e.message || 'Failed to load incident brief')
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    load()
    return () => {
      cancelled = true
    }
  }, [hours])

  const brief = data?.brief || null
  const articles = safeArray(data?.articles)
  const clusters = safeArray(data?.clusters)
  const meta = data?.meta || {}

  const openSources = ({ title, sourceIds = [], clusterId = null }) => {
    setSourcesTitle(title || 'Sources')
    setSelectedSourceIds(sourceIds)
    setSelectedClusterId(clusterId)
    setSourcesOpen(true)
  }

  const selectedArticles = (() => {
    const ids = new Set(selectedSourceIds || [])
    let list = articles.filter((a) => ids.has(a.id))
    if (selectedClusterId) {
      const cl = clusters.find((c) => c.id === selectedClusterId)
      if (cl && Array.isArray(cl.source_ids) && cl.source_ids.length > 0) {
        const clusterIds = new Set((cl.source_ids || []).filter(Boolean))
        list = articles.filter((a) => clusterIds.has(a.id))
      }
    }
    return list
  })()

  const clusterForSelected = selectedClusterId ? clusters.find((c) => c.id === selectedClusterId) : null

  return (
    <section className="exec-brief-card">
      <header className="exec-brief-header">
        <div className="exec-brief-header__left">
          <div className="exec-brief-kicker">Executive cyber brief</div>
          <div className="exec-brief-meta">
            <Pill tone={severityTone(brief?.risk_level)}>{brief?.risk_level ? `🔥 Risk: ${brief.risk_level}` : '🔥 Risk: —'}</Pill>
            <Pill tone={urgencyTone(brief?.urgency)}>{brief?.urgency ? `⏱ Urgency: ${brief.urgency}` : '⏱ Urgency: —'}</Pill>
            <Pill tone="neutral">
              🗓 Window: {effectiveHours}h{effectiveHours !== hours ? ` (auto fallback from ${hours}h)` : ''}
            </Pill>
            {cached ? <Pill tone="neutral">Cached</Pill> : null}
          </div>
          <div className="exec-brief-freshness">
            <span>
              Generated: <strong>{formatUtc(meta.generated_at_utc) || '—'}</strong>
            </span>
            <span className="exec-dot" />
            <span>
              Latest article: <strong>{formatUtc(meta.latest_article_utc) || '—'}</strong>
            </span>
            <span className="exec-dot" />
            <span>
              Malware cache: <strong>{meta.latest_malware_first_seen || '—'}</strong>
            </span>
            <span className="exec-dot" />
            <span>
              Coverage: <strong>{meta.sources_analyzed ?? articles.length}</strong> articles,{' '}
              <strong>{meta.clusters_analyzed ?? clusters.length}</strong> clusters,{' '}
              <strong>{meta.unique_sources || '—'}</strong> sources
            </span>
            {meta.cache_ttl_seconds != null ? (
              <>
                <span className="exec-dot" />
                <span>
                  Cache: <strong>{formatAge(meta.cache_age_seconds) || '—'}</strong> /{' '}
                  <strong>{formatAge(meta.cache_ttl_seconds) || '—'}</strong>
                </span>
              </>
            ) : null}
          </div>
        </div>

        <div className="exec-brief-header__right">
          <button
            type="button"
            className="exec-brief-refresh"
            disabled={loading}
            onClick={() => {
              ;(async () => {
                setLoading(true)
                setError('')
                try {
                  const fallbackWindows = [hours, 72, 168].filter((v, i, arr) => arr.indexOf(v) === i)
                  let json = {}
                  let usedHours = hours
                  let success = false
                  for (const windowHours of fallbackWindows) {
                    const res = await fetch(`${API_BASE}/api/incidents/brief`, {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ hours: windowHours, force: true }),
                    })
                    json = await res.json().catch(() => ({}))
                    if (!res.ok) throw new Error(json.error || `Failed to regenerate brief (${res.status})`)
                    usedHours = windowHours
                    const sourcesAnalyzed = Number(json?.meta?.sources_analyzed ?? 0)
                    if (sourcesAnalyzed > 0 || windowHours === fallbackWindows[fallbackWindows.length - 1]) {
                      success = true
                      break
                    }
                  }
                  if (!success) throw new Error('Failed to regenerate brief')
                  setData(json)
                  setCached(Boolean(json.cached))
                  setEffectiveHours(usedHours)
                } catch (e) {
                  setError(e.message || 'Failed to regenerate brief')
                } finally {
                  setLoading(false)
                }
              })()
            }}
          >
            Regenerate
          </button>
        </div>
      </header>

      {error && <div className="exec-brief-error">{error}</div>}
      {loading && <div className="exec-brief-loading">Generating brief…</div>}

      {!loading && brief && (
        <div className="exec-brief-body">
          <div className="exec-bottom-line">
            <div className="exec-section-title">🧠 What’s Happening Today</div>
            <div className="exec-bottom-line__text">{brief.whats_happening_today || '—'}</div>
          </div>

          {safeArray(brief.dominant_themes).length > 0 && (
            <div className="exec-themes">
              <div className="exec-section-head">
                <div className="exec-section-title">🔥 Dominant Themes</div>
                <button
                  type="button"
                  className="exec-view-sources"
                  onClick={() =>
                    openSources({
                      title: `Dominant Themes sources`,
                      sourceIds: safeArray(brief.dominant_themes).flatMap((t) => safeArray(t.source_ids)),
                    })
                  }
                >
                  View Sources ({safeArray(brief.dominant_themes).flatMap((t) => safeArray(t.source_ids)).length || 0})
                </button>
              </div>
              <div className="exec-theme-chips">
                {safeArray(brief.dominant_themes)
                  .slice(0, 4)
                  .map((t) => (
                    <button
                      key={`${t.rank}-${t.theme}`}
                      type="button"
                      className={`exec-theme-chip exec-theme-chip--${severityTone(t.severity)}`}
                      onClick={() =>
                        openSources({
                          title: `Theme: ${t.theme}`,
                          sourceIds: safeArray(t.source_ids),
                          clusterId: safeArray(t.cluster_ids)[0] || null,
                        })
                      }
                      title={t.so_what || ''}
                    >
                      <span className="exec-theme-chip__name">{t.theme}</span>
                      <span className="exec-theme-chip__sev">{t.severity || '—'}</span>
                    </button>
                  ))}
              </div>
              {safeArray(brief.dominant_themes)[0]?.so_what ? (
                <div className="exec-theme-so-what">{safeArray(brief.dominant_themes)[0].so_what}</div>
              ) : null}
            </div>
          )}

          {safeArray(brief.affected_areas).length > 0 && (
            <div className="exec-areas">
              <div className="exec-section-title">🎯 Affected Areas</div>
              <div className="exec-area-tags">
                {safeArray(brief.affected_areas).slice(0, 6).map((a) => (
                  <span key={a} className="exec-area-tag">
                    {a}
                  </span>
                ))}
              </div>
            </div>
          )}

          <div className="exec-risks">
            <div className="exec-section-head">
              <div className="exec-section-title">⚠️ Top Risks</div>
              <button
                type="button"
                className="exec-view-sources"
                onClick={() =>
                  openSources({
                    title: `Top Risks sources`,
                    sourceIds: safeArray(brief.top_risks).flatMap((r) => safeArray(r.source_ids)),
                  })
                }
              >
                View Sources ({safeArray(brief.top_risks).flatMap((r) => safeArray(r.source_ids)).length || 0})
              </button>
            </div>

            <div className="exec-risk-grid">
              {safeArray(brief.top_risks)
                .slice(0, 3)
                .map((r) => (
                  <div key={`${r.rank}-${r.threat}`} className={`exec-risk-card exec-risk-card--${severityTone(r.severity)}`}>
                    <div className="exec-risk-card__top">
                      <div className="exec-risk-title">
                        <span className="exec-risk-rank">#{r.rank}</span> {r.threat || 'Risk'}
                      </div>
                      <div className="exec-risk-badges">
                        <Pill tone={severityTone(r.severity)}>{r.severity ? `Severity: ${r.severity}` : 'Severity: —'}</Pill>
                        <Pill tone={urgencyTone(r.urgency)}>{r.urgency ? `Urgency: ${r.urgency}` : 'Urgency: —'}</Pill>
                      </div>
                    </div>

                    <div className="exec-risk-row">
                      <div className="exec-risk-label">Business impact</div>
                      <div className="exec-risk-value">{r.business_impact || '—'}</div>
                    </div>
                  <div className="exec-risk-row">
                    <div className="exec-risk-label">Why today</div>
                    <div className="exec-risk-value">{r.why_this_matters_today || '—'}</div>
                  </div>
                    <div className="exec-risk-row">
                      <div className="exec-risk-label">Likelihood</div>
                      <div className="exec-risk-value">{r.likelihood || '—'}</div>
                    </div>

                    {safeArray(r.affected_areas).length > 0 && (
                      <div className="exec-risk-areas">
                        {safeArray(r.affected_areas)
                          .slice(0, 4)
                          .map((a) => (
                            <span key={a} className="exec-area-tag exec-area-tag--small">
                              {a}
                            </span>
                          ))}
                      </div>
                    )}

                    <div className="exec-risk-evidence">
                      <span className="exec-evidence-chip">
                        Backed by {r.evidence_indicators?.source_count ?? safeArray(r.source_ids).length} sources
                      </span>
                      {r.evidence_indicators?.active_exploitation_confirmed ? (
                        <span className="exec-evidence-chip exec-evidence-chip--danger">Active exploitation</span>
                      ) : null}
                      {r.evidence_indicators?.emerging_signal ? (
                        <span className="exec-evidence-chip">Emerging signal</span>
                      ) : null}
                    </div>

                    <div className="exec-risk-footer">
                      <button
                        type="button"
                        className="exec-view-sources exec-view-sources--inline"
                        onClick={() =>
                          openSources({
                            title: `Sources for risk #${r.rank}`,
                            sourceIds: safeArray(r.source_ids),
                            clusterId: r.cluster_id || null,
                          })
                        }
                      >
                        View Sources ({safeArray(r.source_ids).length})
                      </button>
                    </div>
                  </div>
                ))}
            </div>
          </div>

          <div className="exec-signals">
            <div className="exec-section-head">
              <div className="exec-section-title">📊 Key Signals</div>
              <button
                type="button"
                className="exec-view-sources"
                onClick={() =>
                  openSources({
                    title: `Key Signals sources`,
                    sourceIds: safeArray(brief.key_signals).flatMap((s) => safeArray(s.source_ids)),
                  })
                }
              >
                View Sources ({safeArray(brief.key_signals).flatMap((s) => safeArray(s.source_ids)).length || 0})
              </button>
            </div>
            <ul className="exec-bullets">
              {safeArray(brief.key_signals)
                .slice(0, 4)
                .map((s, idx) => (
                  <li key={`${idx}-${s.bullet}`}>
                    <span className="exec-signal-main">{s.bullet || '—'}</span>
                    {s.so_what ? <span className="exec-signal-so-what"> — {s.so_what}</span> : null}
                    {s.act_now ? (
                      <span className={`exec-signal-act exec-signal-act--${urgencyTone(s.act_now)}`}>
                        {s.act_now === 'yes' ? 'Act now' : s.act_now === 'monitor' ? 'Monitor' : 'No action'}
                      </span>
                    ) : null}{' '}
                    {safeArray(s.source_ids).length ? (
                      <button
                        type="button"
                        className="exec-inline-link"
                        onClick={() =>
                          openSources({
                            title: `Sources for signal`,
                            sourceIds: safeArray(s.source_ids),
                            clusterId: s.cluster_id || null,
                          })
                        }
                      >
                        Sources ({safeArray(s.source_ids).length})
                      </button>
                    ) : null}
                  </li>
                ))}
            </ul>
          </div>

          <div className="exec-confidence">
            <div className="exec-section-title">🧪 Confidence + Coverage</div>
            <div className="exec-confidence-grid">
              <div className="exec-confidence-item">
                <div className="exec-confidence-label">Confidence</div>
                <div className="exec-confidence-value">{brief.confidence_coverage?.confidence || '—'}</div>
              </div>
              <div className="exec-confidence-item">
                <div className="exec-confidence-label">Sources analyzed</div>
                <div className="exec-confidence-value">{brief.confidence_coverage?.sources_analyzed ?? articles.length}</div>
              </div>
            </div>
            {safeArray(brief.confidence_coverage?.gaps).length > 0 && (
              <ul className="exec-bullets exec-bullets--compact">
                {safeArray(brief.confidence_coverage.gaps).slice(0, 2).map((g) => (
                  <li key={g}>{g}</li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}

      {sourcesOpen && (
        <div className="exec-sources-overlay" role="dialog" aria-modal="true">
          <div className="exec-sources-panel">
            <header className="exec-sources-header">
              <div>
                <div className="exec-sources-title">{sourcesTitle}</div>
                {clusterForSelected ? (
                  <div className="exec-sources-subtitle">
                    Cluster: {clusterForSelected.label} • {clusterForSelected.source_count} sources •{' '}
                    {clusterForSelected.timeline?.first_seen
                      ? `${clusterForSelected.timeline.first_seen} → ${clusterForSelected.timeline.last_update}`
                      : ''}
                  </div>
                ) : null}
              </div>
              <button type="button" className="exec-sources-close" onClick={() => setSourcesOpen(false)}>
                Close
              </button>
            </header>

            <div className="exec-sources-body">
              {selectedArticles.length === 0 ? (
                <div className="exec-sources-empty">No sources available.</div>
              ) : (
                <ul className="exec-sources-list">
                  {selectedArticles.map((a) => {
                    const summaries = safeArray(brief?.article_summaries)
                    const one = summaries.find((s) => s.id === a.id)?.summary
                    const cves = safeArray(a.extracted_entities?.cves)
                    const tags = safeArray(a.extracted_entities?.threat_tags)
                    return (
                      <li key={a.id} className="exec-source-item">
                        <div className="exec-source-title">{a.title || 'Untitled'}</div>
                        <div className="exec-source-meta">
                          <span>{a.source}</span>
                          {a.timestamp ? <span>{a.timestamp}</span> : null}
                        </div>
                        {one ? <div className="exec-source-summary">{one}</div> : null}
                        {(cves.length > 0 || tags.length > 0) && (
                          <div className="exec-source-entities">
                            {cves.slice(0, 4).map((c) => (
                              <span key={c} className="exec-entity-chip">
                                {c}
                              </span>
                            ))}
                            {tags.slice(0, 4).map((t) => (
                              <span key={t} className="exec-entity-chip exec-entity-chip--muted">
                                {String(t).replaceAll('_', ' ')}
                              </span>
                            ))}
                          </div>
                        )}
                        {a.url ? (
                          <a className="exec-source-link" href={a.url} target="_blank" rel="noreferrer">
                            Open article
                          </a>
                        ) : null}
                      </li>
                    )
                  })}
                </ul>
              )}
            </div>
          </div>
          <div className="exec-sources-backdrop" onClick={() => setSourcesOpen(false)} />
        </div>
      )}
    </section>
  )
}

