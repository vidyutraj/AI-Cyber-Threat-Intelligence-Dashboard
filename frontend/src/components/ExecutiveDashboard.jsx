/**
 * Executive Dashboard — redesigned for speed-to-insight.
 *
 * Fuses two data streams:
 *   1. AI incident brief  (/api/incidents/brief)  — narrative, risks, themes
 *   2. Intel overview     (/api/intel/overview)   — CVE scores, KEV, trending
 *
 * Layout designed around the "BLUF" principle (Bottom Line Up Front):
 *   - Threat level banner: one glance tells the executive how serious today is
 *   - 5 KPI tiles: numbers an exec can repeat in a meeting
 *   - Left column: AI narrative + key signals (the "story")
 *   - Right column: top CVEs with real scores + top risks (the "evidence")
 */
import { useCallback, useEffect, useState } from 'react'
import './ExecutiveDashboard.css'

import { API_BASE } from '../config.js'

// ── helpers ───────────────────────────────────────────────────────────────

function safeArr(v) { return Array.isArray(v) ? v : [] }

function formatUtcShort(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  if (isNaN(d)) return String(iso).slice(0, 16)
  return d.toLocaleString('en-US', {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
    timeZone: 'UTC', timeZoneName: 'short',
  })
}

function timeAgo(iso) {
  if (!iso) return null
  const ms = Date.now() - new Date(iso).getTime()
  if (isNaN(ms) || ms < 0) return null
  const m = Math.round(ms / 60000)
  if (m < 60) return `${m}m ago`
  const h = Math.round(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.round(h / 24)}d ago`
}

const LEVEL = {
  high:   { label: 'HIGH',   cls: 'lvl-high',   icon: '▲' },
  medium: { label: 'MEDIUM', cls: 'lvl-medium',  icon: '◆' },
  low:    { label: 'LOW',    cls: 'lvl-low',     icon: '▼' },
}

function threatLevel(riskStr) {
  const r = String(riskStr || '').toLowerCase()
  if (r === 'high' || r === 'critical') return LEVEL.high
  if (r === 'medium') return LEVEL.medium
  return LEVEL.low
}

// ── sub-components ────────────────────────────────────────────────────────

function MiniSparkline({ data = [] }) {
  if (!data || data.length < 2) return null
  const max = Math.max(...data, 1)
  const w = 80, h = 22
  const step = w / (data.length - 1)
  const pts = data.map((v, i) => `${(i * step).toFixed(1)},${(h - (v / max) * h).toFixed(1)}`).join(' ')
  return (
    <svg className="ed-sparkline" viewBox={`0 0 ${w} ${h}`} width={w} height={h} aria-hidden="true">
      <polyline points={pts} fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  )
}

function KpiTile({ value, label, highlight, sub, sparkData }) {
  return (
    <div className={`ed-kpi ${highlight ? 'ed-kpi--highlight' : ''}`}>
      <div className="ed-kpi__value">{value ?? '—'}</div>
      <div className="ed-kpi__label">{label}</div>
      {sub && <div className="ed-kpi__sub">{sub}</div>}
      {sparkData && <MiniSparkline data={sparkData} />}
    </div>
  )
}

function RiskCard({ risk, rank, onSources }) {
  const sev = String(risk.severity || '').toLowerCase()
  const cls = sev === 'high' || sev === 'critical' ? 'danger' : sev === 'medium' ? 'warn' : 'ok'
  const nsrc = safeArr(risk.source_ids).length
  return (
    <div className={`ed-risk ed-risk--${cls}`}>
      <div className="ed-risk__head">
        <span className="ed-risk__rank">#{rank}</span>
        <span className="ed-risk__name">{risk.threat || 'Unknown threat'}</span>
        <span className={`ed-risk__sev ed-risk__sev--${cls}`}>{risk.severity || '—'}</span>
      </div>
      {risk.business_impact && (
        <div className="ed-risk__impact">{risk.business_impact}</div>
      )}
      {risk.why_this_matters_today && (
        <div className="ed-risk__why">{risk.why_this_matters_today}</div>
      )}
      <div className="ed-risk__footer">
        {risk.evidence_indicators?.active_exploitation_confirmed && (
          <span className="ed-badge ed-badge--danger">Active exploitation</span>
        )}
        {risk.evidence_indicators?.emerging_signal && (
          <span className="ed-badge">Emerging signal</span>
        )}
        {risk.urgency && (
          <span className={`ed-badge ${risk.urgency === 'Immediate' ? 'ed-badge--danger' : ''}`}>
            {risk.urgency}
          </span>
        )}
        {nsrc > 0 && (
          <button className="ed-src-btn" onClick={() => onSources && onSources(risk)}>
            {nsrc} source{nsrc > 1 ? 's' : ''}
          </button>
        )}
      </div>
    </div>
  )
}

function CveRow({ cve }) {
  const sev = String(cve.cvss_v3_severity || '').toLowerCase()
  const cls = sev === 'critical' ? 'danger' : sev === 'high' ? 'warn' : 'ok'
  const epss = cve.epss_score != null ? `${Math.round(cve.epss_score * 100)}%` : null
  return (
    <div className="ed-cve">
      <div className="ed-cve__left">
        <a
          className="ed-cve__id"
          href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
          target="_blank"
          rel="noreferrer"
        >{cve.cve_id}</a>
        <div className="ed-cve__badges">
          {cve.in_kev && <span className="ed-badge ed-badge--danger">KEV</span>}
          {cve.cvss_v3_severity && (
            <span className={`ed-badge ed-badge--${cls}`}>{cve.cvss_v3_severity}</span>
          )}
        </div>
      </div>
      <div className="ed-cve__scores">
        {cve.cvss_v3_score != null && (
          <div className="ed-cve__score">
            <span className="ed-cve__score-val">{cve.cvss_v3_score.toFixed(1)}</span>
            <span className="ed-cve__score-lbl">CVSS</span>
          </div>
        )}
        {epss && (
          <div className="ed-cve__score">
            <span className="ed-cve__score-val">{epss}</span>
            <span className="ed-cve__score-lbl">exploit prob</span>
          </div>
        )}
        <div className="ed-cve__score">
          <span className="ed-cve__score-val ed-cve__score-val--pri">
            {(cve.score * 100).toFixed(0)}
          </span>
          <span className="ed-cve__score-lbl">priority</span>
        </div>
      </div>
    </div>
  )
}

function SignalRow({ signal }) {
  const act = String(signal.act_now || '').toLowerCase()
  const actCls = act === 'yes' ? 'danger' : act === 'monitor' ? 'warn' : ''
  const actLabel = act === 'yes' ? 'Act Now' : act === 'monitor' ? 'Monitor' : null
  return (
    <li className="ed-signal">
      <div className="ed-signal__bullet">{signal.bullet || '—'}</div>
      {signal.so_what && <div className="ed-signal__sowhat">{signal.so_what}</div>}
      {actLabel && (
        <span className={`ed-badge ${actCls ? `ed-badge--${actCls}` : ''}`}>{actLabel}</span>
      )}
    </li>
  )
}

function SourcesModal({ title, articles, onClose }) {
  return (
    <div className="ed-modal-overlay" onClick={onClose}>
      <div className="ed-modal" onClick={e => e.stopPropagation()}>
        <div className="ed-modal__head">
          <span className="ed-modal__title">{title}</span>
          <button className="ed-modal__close" onClick={onClose}>✕</button>
        </div>
        <div className="ed-modal__body">
          {articles.length === 0 ? (
            <p className="ed-modal__empty">No sources available.</p>
          ) : (
            <ul className="ed-modal__list">
              {articles.map(a => (
                <li key={a.id} className="ed-modal__item">
                  <div className="ed-modal__art-title">{a.title}</div>
                  <div className="ed-modal__art-meta">
                    <span>{a.source}</span>
                    {a.timestamp && <span>{a.timestamp}</span>}
                  </div>
                  {a.url && (
                    <a href={a.url} className="ed-modal__art-link" target="_blank" rel="noreferrer">
                      Read article →
                    </a>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  )
}

// ── main component ────────────────────────────────────────────────────────

export default function ExecutiveDashboard({ onThreatLevel }) {
  const [brief, setBrief]           = useState(null)
  const [intel, setIntel]           = useState(null)
  const [loadingBrief, setLB]       = useState(false)
  const [loadingIntel, setLI]       = useState(false)
  const [briefError, setBriefErr]   = useState('')
  const [intelError, setIntelErr]   = useState('')
  const [effectiveHours, setEH]     = useState(24)
  const [cached, setCached]         = useState(false)
  const [modal, setModal]           = useState(null)  // { title, articles }

  // ── fetch incident brief with auto-fallback ───────────────────────────
  const fetchBrief = useCallback(async (force = false) => {
    setLB(true)
    setBriefErr('')
    try {
      const windows = [24, 72, 168]
      for (const h of windows) {
        const res = await fetch(`${API_BASE}/api/incidents/brief`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ hours: h, force }),
        })
        const json = await res.json().catch(() => ({}))
        if (!res.ok) throw new Error(json.error || `HTTP ${res.status}`)
        const analyzed = Number(json?.meta?.sources_analyzed ?? 0)
        if (analyzed > 0 || h === windows[windows.length - 1]) {
        setBrief(json)
        setCached(Boolean(json.cached))
        setEH(h)
        if (onThreatLevel) onThreatLevel(json?.brief?.risk_level || null)
        break
        }
      }
    } catch (e) {
      setBriefErr(e.message || 'Failed to load brief')
    } finally {
      setLB(false)
    }
  }, [])

  // ── fetch intel overview ──────────────────────────────────────────────
  const fetchIntel = useCallback(async () => {
    setLI(true)
    setIntelErr('')
    try {
      const res = await fetch(`${API_BASE}/api/intel/overview?hours=1440`)
      const json = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(json.error || `HTTP ${res.status}`)
      setIntel(json)
    } catch (e) {
      setIntelErr(e.message || '')
    } finally {
      setLI(false)
    }
  }, [])

  useEffect(() => { fetchBrief(); fetchIntel() }, [fetchBrief, fetchIntel])

  // ── derived values ────────────────────────────────────────────────────
  const b        = brief?.brief || null
  const articles = safeArr(brief?.articles)
  const meta     = brief?.meta || {}
  const level    = threatLevel(b?.risk_level)
  const risks    = safeArr(b?.top_risks).slice(0, 3)
  const signals  = safeArr(b?.key_signals).slice(0, 5)
  const themes   = safeArr(b?.dominant_themes).slice(0, 4)
  const rankedCves = safeArr(intel?.ranked_cves).filter(c => c.cvss_v3_score != null).slice(0, 6)

  const openSources = (title, sourceIds) => {
    const ids = new Set(safeArr(sourceIds))
    const arts = articles.filter(a => ids.has(a.id))
    setModal({ title, articles: arts })
  }

  const isLoading = loadingBrief || loadingIntel

  // ── render ────────────────────────────────────────────────────────────
  return (
    <div className="ed-root">

      {/* ── THREAT STATUS BANNER ── */}
      <div className={`ed-banner ${level.cls}`}>
        <div className="ed-banner__left">
          <span className="ed-banner__icon">{level.icon}</span>
          <span className="ed-banner__label">THREAT LEVEL</span>
          <span className="ed-banner__level">{level.label}</span>
          {b?.urgency && (
            <span className="ed-banner__urgency">
              Urgency: <strong>{b.urgency}</strong>
            </span>
          )}
        </div>
        <div className="ed-banner__right">
          {meta.generated_at_utc && (
            <span className="ed-banner__ts">
              Brief generated {timeAgo(meta.generated_at_utc)}
              {cached && ' · Cached'}
            </span>
          )}
          {effectiveHours !== 24 && (
            <span className="ed-banner__ts">Window: {effectiveHours}h (auto-expanded)</span>
          )}
          <button
            className="ed-banner__regen"
            disabled={isLoading}
            onClick={() => fetchBrief(true)}
          >
            {loadingBrief ? (
              <span className="ed-spinner" />
            ) : (
              <>↻ Regenerate</>
            )}
          </button>
        </div>
      </div>

      {/* ── ERRORS ── */}
      {briefError && <div className="ed-error">{briefError}</div>}
      {intelError && <div className="ed-error ed-error--soft">Intel data unavailable: {intelError}</div>}

      {/* ── KPI STRIP ── */}
      <div className="ed-kpis">
        <KpiTile
          value={meta.sources_analyzed ?? articles.length}
          label="Articles Analyzed"
          sub={meta.unique_sources ? `${meta.unique_sources} sources` : null}
          sparkData={intel?.sparklines?.articles}
        />
        <KpiTile
          value={intel?.n_cves_total ?? '—'}
          label="CVEs Detected"
          sub={`${intel?.n_cves_enriched ?? 0} enriched`}
          sparkData={intel?.sparklines?.cves}
        />
        <KpiTile
          value={intel?.n_kev ?? '—'}
          label="In CISA KEV"
          highlight={intel?.n_kev > 0}
          sub="Active exploitation confirmed"
          sparkData={intel?.sparklines?.kev}
        />
        <KpiTile
          value={intel?.n_clusters ?? '—'}
          label="Story Clusters"
          sub={intel?.n_duplicates ? `${intel.n_duplicates} duplicates removed` : null}
        />
        <KpiTile
          value={meta.clusters_analyzed ?? safeArr(brief?.clusters).length}
          label="Threat Clusters"
          sub={`${effectiveHours}h window`}
        />
      </div>

      {/* ── MAIN CONTENT ── */}
      {(b || rankedCves.length > 0) ? (
        <div className="ed-body">

          {/* ── LEFT COLUMN: NARRATIVE ── */}
          <div className="ed-col-left">

            {/* BOTTOM LINE UP FRONT */}
            {b?.whats_happening_today && (
              <div className="ed-bluf">
                <div className="ed-bluf__label">Situation Summary</div>
                <p className="ed-bluf__text">{b.whats_happening_today}</p>
              </div>
            )}

            {/* DOMINANT THEMES */}
            {themes.length > 0 && (
              <div className="ed-card">
                <div className="ed-card__head">
                  <span className="ed-card__title">Dominant Themes</span>
                  <button
                    className="ed-link"
                    onClick={() => openSources(
                      'Theme sources',
                      themes.flatMap(t => safeArr(t.source_ids))
                    )}
                  >
                    {themes.flatMap(t => safeArr(t.source_ids)).length} sources
                  </button>
                </div>
                <div className="ed-themes">
                  {themes.map((t, i) => {
                    const sev = String(t.severity || '').toLowerCase()
                    const cls = sev === 'high' || sev === 'critical' ? 'danger' : sev === 'medium' ? 'warn' : 'ok'
                    return (
                      <button
                        key={i}
                        className={`ed-theme ed-theme--${cls}`}
                        onClick={() => openSources(`Theme: ${t.theme}`, safeArr(t.source_ids))}
                        title={t.so_what || ''}
                      >
                        <span className="ed-theme__name">{t.theme}</span>
                        {t.severity && <span className="ed-theme__sev">{t.severity}</span>}
                      </button>
                    )
                  })}
                </div>
                {themes[0]?.so_what && (
                  <p className="ed-themes__sowhat">{themes[0].so_what}</p>
                )}
              </div>
            )}

            {/* KEY SIGNALS */}
            {signals.length > 0 && (
              <div className="ed-card">
                <div className="ed-card__head">
                  <span className="ed-card__title">Key Intelligence Signals</span>
                  <button
                    className="ed-link"
                    onClick={() => openSources(
                      'Signal sources',
                      signals.flatMap(s => safeArr(s.source_ids))
                    )}
                  >
                    {signals.flatMap(s => safeArr(s.source_ids)).length} sources
                  </button>
                </div>
                <ul className="ed-signals">
                  {signals.map((s, i) => <SignalRow key={i} signal={s} />)}
                </ul>
              </div>
            )}

            {/* AFFECTED AREAS */}
            {safeArr(b?.affected_areas).length > 0 && (
              <div className="ed-card ed-card--compact">
                <div className="ed-card__title">Affected Sectors</div>
                <div className="ed-areas">
                  {safeArr(b.affected_areas).slice(0, 8).map(a => (
                    <span key={a} className="ed-area">{a}</span>
                  ))}
                </div>
              </div>
            )}

            {/* CONFIDENCE */}
            {b?.confidence_coverage && (
              <div className="ed-card ed-card--compact">
                <div className="ed-card__head">
                  <span className="ed-card__title">Confidence &amp; Coverage</span>
                  <span className="ed-confidence-val">
                    {b.confidence_coverage.confidence || '—'}
                  </span>
                </div>
                {safeArr(b.confidence_coverage.gaps).length > 0 && (
                  <ul className="ed-gaps">
                    {safeArr(b.confidence_coverage.gaps).slice(0, 2).map((g, i) => (
                      <li key={i}>{g}</li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>

          {/* ── RIGHT COLUMN: EVIDENCE ── */}
          <div className="ed-col-right">

            {/* TOP PRIORITY CVEs */}
            {rankedCves.length > 0 && (
              <div className="ed-card">
                <div className="ed-card__head">
                  <span className="ed-card__title">Priority CVEs</span>
                  <span className="ed-card__sub">CVSS · EPSS · KEV · graph · trend</span>
                </div>
                <div className="ed-cves">
                  {rankedCves.map(c => <CveRow key={c.cve_id} cve={c} />)}
                </div>
              </div>
            )}

            {/* TOP RISKS */}
            {risks.length > 0 && (
              <div className="ed-card">
                <div className="ed-card__head">
                  <span className="ed-card__title">Top Risks</span>
                  <button
                    className="ed-link"
                    onClick={() => openSources(
                      'Risk sources',
                      risks.flatMap(r => safeArr(r.source_ids))
                    )}
                  >
                    {risks.flatMap(r => safeArr(r.source_ids)).length} sources
                  </button>
                </div>
                <div className="ed-risks">
                  {risks.map((r, i) => (
                    <RiskCard
                      key={i}
                      risk={r}
                      rank={r.rank ?? i + 1}
                      onSources={r2 => openSources(`Sources for risk #${r2.rank}`, safeArr(r2.source_ids))}
                    />
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      ) : loadingBrief ? (
        <div className="ed-loading">
          <span className="ed-spinner ed-spinner--lg" />
          <span>Generating executive brief — analyzing threat corpus…</span>
        </div>
      ) : null}

      {/* ── SOURCES MODAL ── */}
      {modal && (
        <SourcesModal
          title={modal.title}
          articles={modal.articles}
          onClose={() => setModal(null)}
        />
      )}
    </div>
  )
}
