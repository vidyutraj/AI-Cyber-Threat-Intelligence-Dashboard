import { useEffect, useState } from 'react'
import { API_BASE } from '../config.js'

function timeAgo(epochMs) {
  if (!epochMs) return null
  const s = Math.round((Date.now() / 1000) - epochMs)
  if (s < 60) return `${s}s ago`
  const m = Math.round(s / 60)
  if (m < 60) return `${m}m ago`
  return `${Math.round(m / 60)}h ago`
}

function FeedHeader({
  title,
  subtitle,
  feedSubtitle,
  sourceLabel,
  siteUrl,
  csvFile,
  source,
  onSourceChange,
  sources,
  refreshing,
  onRefresh,
  onExportIocs,
}) {
  const [sourceMeta, setSourceMeta] = useState(null)

  useEffect(() => {
    fetch(`${API_BASE}/api/feed/sources`)
      .then(r => r.json())
      .catch(() => null)
      .then(data => { if (data) setSourceMeta(data) })
  }, [])

  const cur = sourceMeta?.[source]
  const scrapeAge = cur ? timeAgo(cur.last_scraped_at) : null

  return (
    <header className="feed-header">
      <div className="feed-header-brand">
        <h1 className="feed-header-title">{title}</h1>
        <p className="feed-header-subtitle">{subtitle}</p>
        <p className="feed-header-feed-subtitle">
          {feedSubtitle} <code>{csvFile}</code>.
        </p>
      </div>
      <div className="feed-header-right">
        <div className="feed-header-actions">
          <label className="feed-header-source-label">
            <span className="feed-header-source-text">Source</span>
            <select
              className="feed-header-select"
              value={source}
              onChange={(e) => onSourceChange(e.target.value)}
            >
              {Object.entries(sources).map(([key, meta]) => (
                <option key={key} value={key}>{meta.label}</option>
              ))}
            </select>
          </label>
          {onExportIocs && (
            <button type="button" className="feed-header-export" onClick={onExportIocs}>
              Export indicators
            </button>
          )}
          <button
            type="button"
            className="feed-header-refresh"
            onClick={onRefresh}
            disabled={refreshing}
          >
            {refreshing ? 'Refreshing…' : 'Refresh feed'}
          </button>
        </div>
        {cur && (
          <div className="feed-freshness-bar">
            <span className={`feed-freshness-dot ${cur.scraper_running ? 'feed-freshness-dot--running' : ''}`} />
            {cur.scraper_running
              ? <span>Scraping now…</span>
              : scrapeAge
                ? <span>Scraped <strong>{scrapeAge}</strong></span>
                : <span>Not yet scraped</span>
            }
            {cur.article_count > 0 && (
              <span className="feed-freshness-sep">·</span>
            )}
            {cur.article_count > 0 && (
              <span><strong>{cur.article_count}</strong> articles</span>
            )}
            {cur.last_error && (
              <span className="feed-freshness-error" title={cur.last_error}>⚠ scrape error</span>
            )}
          </div>
        )}
      </div>
    </header>
  )
}

export default FeedHeader
