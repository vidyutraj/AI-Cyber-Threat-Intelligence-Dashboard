import { useEffect, useMemo, useState, useCallback } from 'react'
import IOCGraph from './IOCGraph'
import KillChainView from './KillChainView'
import SemanticSearch from './SemanticSearch'
import './ThreatIntelligenceView.css'

import { API_BASE } from '../config.js'

function severityBadge(sev) {
  const v = String(sev || '').toUpperCase()
  const cls =
    v === 'CRITICAL' ? 'ti-pill ti-pill--critical'
    : v === 'HIGH'   ? 'ti-pill ti-pill--high'
    : v === 'MEDIUM' ? 'ti-pill ti-pill--medium'
    : v === 'LOW'    ? 'ti-pill ti-pill--low'
    :                  'ti-pill ti-pill--muted'
  return <span className={cls}>{v || '—'}</span>
}

function ScoreBar({ value, max = 1 }) {
  const pct = Math.max(0, Math.min(100, (value / max) * 100))
  return (
    <div className="ti-scorebar" title={`Score: ${value.toFixed(3)}`}>
      <div className="ti-scorebar__fill" style={{ width: `${pct}%` }} />
      <span className="ti-scorebar__label">{value.toFixed(3)}</span>
    </div>
  )
}

function Sparkline({ points, width = 120, height = 28 }) {
  if (!points || points.length < 2) return <span className="ti-sparkline-empty">—</span>
  const values = points.map((p) => (typeof p === 'number' ? p : p.count || 0))
  const max = Math.max(...values, 1)
  const stepX = width / (values.length - 1)
  const path = values
    .map((v, i) => `${i === 0 ? 'M' : 'L'} ${(i * stepX).toFixed(1)} ${(height - (v / max) * height).toFixed(1)}`)
    .join(' ')
  return (
    <svg className="ti-sparkline" viewBox={`0 0 ${width} ${height}`} width={width} height={height}>
      <path d={path} fill="none" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  )
}

function useApi(path) {
  const [state, setState] = useState({ loading: true, error: '', data: null })
  useEffect(() => {
    let cancelled = false
    const run = async () => {
      setState((s) => ({ ...s, loading: true, error: '' }))
      try {
        const res = await fetch(`${API_BASE}${path}`)
        const json = await res.json().catch(() => ({}))
        if (!res.ok) throw new Error(json.error || `Request failed (${res.status})`)
        if (!cancelled) setState({ loading: false, error: '', data: json })
      } catch (e) {
        if (!cancelled) setState({ loading: false, error: e.message || 'Request failed', data: null })
      }
    }
    run()
    return () => { cancelled = true }
  }, [path])
  return state
}

function RankedCveCard({ cve, maxScore }) {
  const [showReasons, setShowReasons] = useState(false)
  const hasReasons = cve.reasons && cve.reasons.length > 0
  return (
    <div className="ti-cve-card">
      <div className="ti-cve-card__head">
        <div className="ti-cve-card__title">
          <a
            className="ti-cve-id ti-cve-id--link"
            href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
            target="_blank"
            rel="noreferrer"
          >{cve.cve_id}</a>
          {cve.in_kev && <span className="ti-pill ti-pill--kev">KEV</span>}
          {severityBadge(cve.cvss_v3_severity)}
        </div>
        <ScoreBar value={cve.score} max={Math.max(maxScore || 1, 0.001)} />
      </div>
      <div className="ti-cve-card__metrics">
        <div className="ti-metric">
          <span className="ti-metric__label">CVSS</span>
          <span className="ti-metric__value">{cve.cvss_v3_score != null ? cve.cvss_v3_score.toFixed(1) : '—'}</span>
        </div>
        <div className="ti-metric">
          <span className="ti-metric__label">EPSS</span>
          <span className="ti-metric__value">{cve.epss_score != null ? cve.epss_score.toFixed(3) : '—'}</span>
        </div>
        <div className="ti-metric">
          <span className="ti-metric__label">Trend z</span>
          <span className="ti-metric__value">{cve.trend_z ? cve.trend_z.toFixed(1) : '—'}</span>
        </div>
        <div className="ti-metric">
          <span className="ti-metric__label">Degree</span>
          <span className="ti-metric__value">{cve.graph_degree}</span>
        </div>
        <div className="ti-metric">
          <span className="ti-metric__label">Sources</span>
          <span className="ti-metric__value">{cve.source_breadth}</span>
        </div>
      </div>
      {hasReasons && (
        <>
          <button
            className="ti-cve-reasons-toggle"
            onClick={() => setShowReasons(r => !r)}
          >
            {showReasons ? '▲ Hide scoring rationale' : '▼ Why this score?'}
          </button>
          {showReasons && (
            <ul className="ti-cve-reasons">
              {cve.reasons.map((r) => <li key={r}>{r}</li>)}
            </ul>
          )}
        </>
      )}
    </div>
  )
}

function TrendingRow({ signal }) {
  return (
    <div className="ti-trend-row">
      <div className="ti-trend-row__left">
        <span className={`ti-type-tag ti-type-tag--${signal.ioc_type}`}>{signal.ioc_type}</span>
        <span className="ti-trend-value">{signal.value}</span>
      </div>
      <div className="ti-trend-row__mid">
        <Sparkline points={signal.history} />
      </div>
      <div className="ti-trend-row__right">
        <div className="ti-trend-stat">
          <span className="ti-trend-stat__label">today</span>
          <span className="ti-trend-stat__value">{signal.today_count}</span>
        </div>
        <div className="ti-trend-stat">
          <span className="ti-trend-stat__label">baseline</span>
          <span className="ti-trend-stat__value">{signal.baseline.toFixed(2)}</span>
        </div>
        <div className="ti-trend-stat ti-trend-stat--z">
          <span className="ti-trend-stat__label">z</span>
          <span className="ti-trend-stat__value">{signal.z_score.toFixed(1)}</span>
        </div>
      </div>
    </div>
  )
}

function ClusterCard({ cluster }) {
  return (
    <div className="ti-cluster-card">
      <div className="ti-cluster-head">
        <span className="ti-cluster-size">{cluster.article_ids.length} articles</span>
        <span className="ti-cluster-jaccard">Jaccard ≥ {cluster.max_jaccard.toFixed(2)}</span>
        <span className="ti-cluster-sources">{cluster.sources.join(' • ')}</span>
      </div>
      <ul className="ti-cluster-titles">
        {cluster.titles.map((t, idx) => <li key={idx}>{t}</li>)}
      </ul>
    </div>
  )
}

const ORIGIN_COLORS = {
  Russia: '#ef4444', China: '#f59e0b', 'North Korea': '#8b5cf6',
  Iran: '#ec4899', Western: '#3b82f6',
}

function ActorCard({ actor }) {
  const [open, setOpen] = useState(false)
  const color = ORIGIN_COLORS[actor.origin] || '#94a3b8'
  return (
    <div className="ti-actor-card" style={{ borderLeftColor: color }}>
      <div className="ti-actor-head" onClick={() => setOpen(o => !o)} role="button">
        <div className="ti-actor-main">
          <span className="ti-actor-name">{actor.actor}</span>
          <span className="ti-actor-origin" style={{ color }}>{actor.origin}</span>
          <span className="ti-actor-count">{actor.article_count} articles</span>
          <span className="ti-actor-breadth">{actor.source_breadth} sources</span>
        </div>
        <div className="ti-actor-motives">
          {(actor.motives || []).map(m => (
            <span key={m} className="ti-type-tag">{m.replace(/_/g, ' ')}</span>
          ))}
        </div>
        <span className="ti-actor-toggle">{open ? '▲' : '▼'}</span>
      </div>
      {open && (
        <div className="ti-actor-body">
          <p className="ti-actor-desc">{actor.description}</p>
          <div className="ti-actor-sections">
            {actor.cves.length > 0 && (
              <div className="ti-actor-section">
                <div className="ti-actor-section-label">CVEs</div>
                <div className="ti-actor-tags">
                  {actor.cves.slice(0, 10).map(c => <span key={c} className="ti-cve-chip">{c}</span>)}
                </div>
              </div>
            )}
            {actor.mitre_techniques.length > 0 && (
              <div className="ti-actor-section">
                <div className="ti-actor-section-label">MITRE Techniques</div>
                <div className="ti-actor-tags">
                  {actor.mitre_techniques.slice(0, 8).map(t => (
                    <span key={t} className="ti-type-tag ti-type-tag--mitre">{t}</span>
                  ))}
                </div>
              </div>
            )}
            {actor.sample_articles.length > 0 && (
              <div className="ti-actor-section">
                <div className="ti-actor-section-label">Recent articles</div>
                <ul className="ti-actor-articles">
                  {actor.sample_articles.map((a, i) => (
                    <li key={i}>
                      <a href={a.url} target="_blank" rel="noreferrer">{a.title}</a>
                      <span className="ti-actor-art-meta">{a.source_label} · {a.published_at}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function DedupSection({ clusters, duplicates }) {
  const [open, setOpen] = useState(false)
  const count = (clusters.data?.clusters || []).length
  return (
    <section className="ti-section">
      <div className="ti-section-head" style={{ cursor: 'pointer' }} onClick={() => setOpen(o => !o)}>
        <h3 className="ti-section-title">
          Near-duplicate Deduplication
          {duplicates > 0 && <span className="ti-section-badge">{duplicates} removed</span>}
        </h3>
        <span className="ti-section-note">MinHash + banded LSH · {open ? 'hide ▲' : 'show clusters ▼'}</span>
      </div>
      {open && (
        clusters.loading ? (
          <div className="ti-loading">Computing clusters…</div>
        ) : count === 0 ? (
          <div className="ti-empty">No duplicate stories detected.</div>
        ) : (
          <div className="ti-cluster-grid">
            {(clusters.data.clusters || []).map((c) => (
              <ClusterCard key={c.cluster_id} cluster={c} />
            ))}
          </div>
        )
      )}
    </section>
  )
}

const TABS = [
  { id: 'overview',    label: 'Overview' },
  { id: 'graph',       label: 'IOC Graph' },
  { id: 'killchain',   label: 'Kill Chain' },
  { id: 'actors',      label: 'Threat Actors' },
  { id: 'search',      label: 'Semantic Search' },
]

export default function ThreatIntelligenceView() {
  const [hours, setHours] = useState(168)
  const [innerTab, setInnerTab] = useState('overview')

  const overview = useApi(`/api/intel/overview?hours=${hours}`)
  const clusters = useApi(`/api/intel/clusters?hours=${hours}`)
  const actors   = useApi(`/api/intel/actors?hours=${Math.max(hours, 720)}`)

  const maxScore = useMemo(() => {
    const ranked = overview.data?.ranked_cves || []
    return ranked.length ? Math.max(...ranked.map((c) => c.score)) : 1
  }, [overview.data])

  return (
    <div className="ti-container">
      <header className="ti-header">
        <div>
          <h2 className="ti-title">Threat Intelligence</h2>
          <p className="ti-subtitle">
            CVSS/EPSS/KEV enrichment · eigenvector centrality graph · MinHash dedup · EWMA trend detection · MITRE ATT&amp;CK kill chains · semantic KNN search
          </p>
        </div>
        <div className="ti-header-actions" style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <a
            className="ti-stix-btn"
            href={`${API_BASE}/api/intel/stix?hours=${hours}`}
            download
            title="Download STIX 2.1 Bundle — compatible with Splunk, QRadar, Elastic SIEM"
          >
            ↓ STIX 2.1
          </a>
          <a
            className="ti-stix-btn ti-stix-btn--secondary"
            href={`${API_BASE}/api/iocs/export`}
            download
            title="Download IOC CSV for SIEM ingestion"
          >
            ↓ IOC CSV
          </a>
        </div>
        <div className="ti-window-switch">
          {[24, 72, 168, 336, 720, 1440].map((h) => (
            <button
              key={h}
              type="button"
              className={`ti-window-btn ${hours === h ? 'ti-window-btn--active' : ''}`}
              onClick={() => setHours(h)}
            >
              {h >= 24 ? `${Math.round(h / 24)}d` : `${h}h`}
            </button>
          ))}
        </div>
      </header>

      {/* Inner tab bar */}
      <div className="ti-inner-tabs">
        {TABS.map(t => (
          <button
            key={t.id}
            className={`ti-inner-tab ${innerTab === t.id ? 'ti-inner-tab--active' : ''}`}
            onClick={() => setInnerTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* ── OVERVIEW tab ─────────────────────────────────────── */}
      {innerTab === 'overview' && (
        <>
          {overview.error && <div className="ti-alert">{overview.error}</div>}
          {overview.loading && <div className="ti-loading">Running enrichment + scoring pipeline…</div>}

          {overview.data && (
            <>
              <section className="ti-section">
                <div className="ti-section-head">
                  <h3 className="ti-section-title">Prioritized CVEs</h3>
                  <span className="ti-section-note">
                    score = 0.20·CVSS + 0.20·EPSS + 0.25·KEV + 0.15·centrality + 0.15·trend + 0.05·breadth
                  </span>
                </div>
                {overview.data.ranked_cves.length === 0 ? (
                  <div className="ti-empty">No CVEs in the current window.</div>
                ) : (
                  <div className="ti-cve-grid">
                    {overview.data.ranked_cves.map((cve) => (
                      <RankedCveCard key={cve.cve_id} cve={cve} maxScore={maxScore} />
                    ))}
                  </div>
                )}
              </section>

              <div className="ti-two-col">
                <section className="ti-section">
                  <div className="ti-section-head">
                    <h3 className="ti-section-title">Trending IOCs</h3>
                    <span className="ti-section-note">EWMA z-score spike detection</span>
                  </div>
                  {overview.data.trending.length === 0 ? (
                    <div className="ti-empty">No IOCs are spiking right now.</div>
                  ) : (
                    <div className="ti-trend-list">
                      {overview.data.trending.map((s) => (
                        <TrendingRow key={`${s.ioc_type}:${s.value}`} signal={s} />
                      ))}
                    </div>
                  )}
                </section>

                <DedupSection clusters={clusters} duplicates={overview.data.n_duplicates} />
              </div>
            </>
          )}
        </>
      )}

      {/* ── IOC GRAPH tab ────────────────────────────────────── */}
      {innerTab === 'graph' && (
        <section className="ti-section" style={{ padding: 0 }}>
          <div className="ti-section-head" style={{ padding: '14px 16px 0' }}>
            <h3 className="ti-section-title">IOC Correlation Graph</h3>
            <span className="ti-section-note">
              co-occurrence edges · eigenvector centrality · label-propagation communities
            </span>
          </div>
          <IOCGraph hours={hours} />
        </section>
      )}

      {/* ── KILL CHAIN tab ───────────────────────────────────── */}
      {innerTab === 'killchain' && (
        <section className="ti-section">
          <div className="ti-section-head">
            <h3 className="ti-section-title">MITRE ATT&amp;CK Kill Chain</h3>
            <span className="ti-section-note">
              tactic coverage heatmap · multi-stage campaign detection
            </span>
          </div>
          <KillChainView hours={hours} />
        </section>
      )}

      {/* ── THREAT ACTORS tab ────────────────────────────────── */}
      {innerTab === 'actors' && (
        <section className="ti-section">
          <div className="ti-section-head">
            <h3 className="ti-section-title">Threat Actors</h3>
            <span className="ti-section-note">
              alias matching · {(actors.data?.actors || []).length} actors detected in corpus
            </span>
          </div>
          {actors.loading && <div className="ti-loading">Scanning for threat actor mentions…</div>}
          {actors.error && <div className="ti-alert">{actors.error}</div>}
          {!actors.loading && (actors.data?.actors || []).length === 0 && (
            <div className="ti-empty">No known threat actors detected in the current window.</div>
          )}
          <div className="ti-actor-list">
            {(actors.data?.actors || []).map(a => (
              <ActorCard key={a.actor} actor={a} />
            ))}
          </div>
        </section>
      )}

      {/* ── SEMANTIC SEARCH tab ──────────────────────────────── */}
      {innerTab === 'search' && (
        <section className="ti-section">
          <div className="ti-section-head">
            <h3 className="ti-section-title">Semantic Search</h3>
            <span className="ti-section-note">
              OpenAI text-embedding-3-small · cosine KNN · TF-IDF fallback
            </span>
          </div>
          <SemanticSearch hours={hours} />
        </section>
      )}
    </div>
  )
}
