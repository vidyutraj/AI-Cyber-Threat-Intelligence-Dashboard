import { useEffect, useState, useMemo } from 'react'
import './App.css'

import DashboardLayout from './components/DashboardLayout'
import FeedHeader from './components/FeedHeader'
import ArticleCard from './components/ArticleCard'
import SidebarPanel from './components/SidebarPanel'
import DashboardTabs from './components/DashboardTabs'
import MalwareSamplesView from './components/MalwareSamplesView'
import ChatWidget from './components/ChatWidget'
import ExecutiveHome from './components/ExecutiveHome'
import ArticleSearchBar from './components/ArticleSearchBar'
import ThreatIntelligenceView from './components/ThreatIntelligenceView'


import { API_BASE } from './config.js'

const SOURCE_META = {
  thn: {
    label: 'The Hacker News',
    siteUrl: 'https://thehackernews.com/',
    csvFile: 'thehackernews_rss_articles.csv',
  },
  darkreading: {
    label: 'Dark Reading',
    siteUrl: 'https://www.darkreading.com/',
    csvFile: 'darkreading_rss_articles.csv',
  },
  krebs: {
    label: 'Krebs on Security',
    siteUrl: 'https://krebsonsecurity.com/',
    csvFile: 'krebs_rss_articles.csv',
  },
  bleepingcomputer: {
    label: 'BleepingComputer',
    siteUrl: 'https://www.bleepingcomputer.com/',
    csvFile: 'bleepingcomputer_rss_articles.csv',
  },
  cisa: {
    label: 'CISA Advisories',
    siteUrl: 'https://www.cisa.gov/',
    csvFile: 'cisa_rss_articles.csv',
  },
}

function App() {
  const [activeTab, setActiveTab] = useState('home') // 'home' | 'feed' | 'malware'
  const [source, setSource] = useState('thn')
  const [articles, setArticles] = useState([])
  const [loading, setLoading] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState('')
  const [relatedValue, setRelatedValue] = useState('')
  const [relatedLoading, setRelatedLoading] = useState(false)
  const [relatedError, setRelatedError] = useState('')
  const [relatedArticles, setRelatedArticles] = useState([])
  const [relatedSamples, setRelatedSamples] = useState([])

  const [searchQuery, setSearchQuery] = useState('')
  const [activeCategory, setActiveCategory] = useState('')
  const [activeIocFilters, setActiveIocFilters] = useState(new Set())
  const [activeDays, setActiveDays] = useState(0)
  const [threatLevel, setThreatLevel] = useState(null)
  const [feedUpdated, setFeedUpdated] = useState(false)

  // SSE: subscribe to background scraper updates for the current source
  useEffect(() => {
    const es = new EventSource(`${API_BASE}/api/feed/stream?source=${source}`)
    es.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data)
        if (msg.event === 'update') {
          setFeedUpdated(true)
          // If user is already on the feed tab for this source, reload silently
          if (activeTab === 'feed') {
            fetch(`${API_BASE}/articles?source=${source}`)
              .then(r => r.json())
              .then(json => { if (json.articles) setArticles(json.articles) })
              .catch(() => {})
          }
        }
      } catch (_) {}
    }
    return () => es.close()
  }, [source, activeTab])

  // Clear the "new content" dot when user visits the feed tab
  useEffect(() => {
    if (activeTab === 'feed') setFeedUpdated(false)
  }, [activeTab])
  
  const handleSourceChange = (newSource) => {
    setSource(newSource)
    setSearchQuery('')
    setActiveCategory('')
    setActiveIocFilters(new Set())
    setActiveDays(0)
  }
 
  const categories = useMemo(() => {
    const seen = new Set()
    articles.forEach((a) => {
      const raw = a.categories || ''
      raw.split(/[/,]/).forEach((c) => {
        const t = c.trim()
        if (t) seen.add(t)
      })
    })
    return [...seen].sort()
  }, [articles])
 
  const filteredArticles = useMemo(() => {
    let result = articles
 
    const q = searchQuery.trim().toLowerCase()
    if (q) {
      result = result.filter((a) =>
        ['title', 'description', 'categories', 'cves', 'domains', 'ips', 'hashes'].some((field) =>
          (a[field] || '').toLowerCase().includes(q),
        ),
      )
    }
 
    if (activeCategory) {
      result = result.filter((a) =>
        (a.categories || '').toLowerCase().includes(activeCategory.toLowerCase()),
      )
    }
 
    if (activeIocFilters.size > 0) {
      result = result.filter((a) => {
        if (activeIocFilters.has('cve') && !(a.cves && a.cves.trim())) return false
        if (activeIocFilters.has('ip') && !(a.ips && a.ips.trim())) return false
        if (activeIocFilters.has('domain') && !(a.domains && a.domains.trim())) return false
        if (activeIocFilters.has('hash') && !(a.hashes && a.hashes.trim())) return false
        return true
      })
    }
 
    if (activeDays > 0) {
      const cutoff = new Date()
      cutoff.setDate(cutoff.getDate() - activeDays)
      result = result.filter((a) => {
        if (!a.published_at) return false
        return new Date(a.published_at) >= cutoff
      })
    }
 
    return result
  }, [articles, searchQuery, activeCategory, activeIocFilters, activeDays])
 
  const hasActiveFilters =
    searchQuery.trim() !== '' || activeCategory !== '' || activeIocFilters.size > 0 || activeDays > 0
 
  const clearFilters = () => {
    setSearchQuery('')
    setActiveCategory('')
    setActiveIocFilters(new Set())
    setActiveDays(0)
  }

  const fetchArticles = async (activeSource = source) => {
    setLoading(true)
    setError('')
    try {
      const res = await fetch(`${API_BASE}/articles?source=${encodeURIComponent(activeSource)}`)
      if (!res.ok) {
        throw new Error(`Failed to load articles (${res.status})`)
      }
      const data = await res.json()
      setArticles(data.articles || [])
    } catch (err) {
      setError(err.message || 'Failed to load articles')
    } finally {
      setLoading(false)
    }
  }

  const refreshArticles = async () => {
    setRefreshing(true)
    setError('')
    try {
      const res = await fetch(
        `${API_BASE}/refresh?source=${encodeURIComponent(source)}`,
        { method: 'POST' },
      )
      if (!res.ok) {
        throw new Error(`Failed to refresh articles (${res.status})`)
      }
      const data = await res.json()
      setArticles(data.articles || [])
    } catch (err) {
      setError(err.message || 'Failed to refresh articles')
    } finally {
      setRefreshing(false)
    }
  }

  useEffect(() => {
    fetchArticles()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [source])

  const meta = SOURCE_META[source]

  const buildVirusTotalUrl = (value) => {
    if (!value) return null
    const v = String(value).trim()
    if (!v) return null
    // Very lightweight type detection: hash vs IP vs domain vs CVE.
    const isHash = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(v)
    const isIpv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(v)
    const looksLikeDomain = !isIpv4 && /^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(v)
    if (isHash) return `https://www.virustotal.com/gui/file/${encodeURIComponent(v)}`
    if (isIpv4) return `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(v)}`
    if (looksLikeDomain) return `https://www.virustotal.com/gui/domain/${encodeURIComponent(v)}`
    return null
  }

  const openRelatedPanel = async (raw) => {
    const values = Array.isArray(raw) ? raw.filter(Boolean) : [raw].filter(Boolean)
    if (!values.length) return

    const display =
      values.length === 1 ? values[0] : `${values[0]} +${values.length - 1}`

    setRelatedValue(display)
    setRelatedLoading(true)
    setRelatedError('')
    try {
      const res = await fetch(
        `${API_BASE}/api/iocs/related?values=${encodeURIComponent(values.join(','))}`,
      )
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        throw new Error(data.error || `Failed to load related items (${res.status})`)
      }
      setRelatedArticles(data.articles || [])
      setRelatedSamples(data.malware_samples || [])
    } catch (e) {
      setRelatedError(e.message || 'Failed to load related items')
      setRelatedArticles([])
      setRelatedSamples([])
    } finally {
      setRelatedLoading(false)
    }
  }

  const header = (
    <div className="header-stack">
      <header className="app-top-header">
        <div className="app-top-brand">
          <svg
            className="app-top-logo"
            viewBox="0 0 24 24"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
            aria-hidden="true"
          >
            <path
              d="M12 2 L4 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-8-3z"
              stroke="currentColor"
              strokeWidth="1.25"
              strokeLinejoin="round"
              fill="rgba(59, 130, 246, 0.12)"
            />
          </svg>
          <h1 className="app-top-title">Threat Intelligence Dashboard</h1>
        </div>
      </header>
      <DashboardTabs
        activeTab={activeTab}
        onChange={setActiveTab}
        threatLevel={threatLevel}
        feedUpdated={feedUpdated}
      />
      {activeTab === 'feed' && (
        <FeedHeader
          title="Threat Intelligence Feed"
          subtitle={
            <>
              Articles from{' '}
              <a href={meta.siteUrl} target="_blank" rel="noreferrer">
                {meta.label}
              </a>
            </>
          }
          feedSubtitle="RSS feed stored in"
          csvFile={meta.csvFile}
          source={source}
          onSourceChange={handleSourceChange}
          sources={SOURCE_META}
          refreshing={refreshing}
          onRefresh={refreshArticles}
          onExportIocs={() => {
            window.open(`${API_BASE}/api/iocs/export`, '_blank')
          }}
        />
      )}
    </div>
  )

  const sidebar =
    activeTab === 'feed' ? (
      <>
        <SidebarPanel articles={articles} sourceLabel={meta.label} />
        {relatedValue && (
          <section className="related-ioc-panel">
            <header className="related-ioc-header">
              <div>
                <h3 className="related-ioc-title">Related to: {relatedValue}</h3>
                {relatedError && (
                  <p className="related-ioc-error">{relatedError}</p>
                )}
              </div>
              <div className="related-ioc-header-actions">
                {buildVirusTotalUrl(relatedValue) && (
                  <a
                    href={buildVirusTotalUrl(relatedValue)}
                    className="related-ioc-vt-link"
                    target="_blank"
                    rel="noreferrer"
                  >
                    VirusTotal
                  </a>
                )}
                <button
                  type="button"
                  className="related-ioc-close"
                  onClick={() => {
                    setRelatedValue('')
                    setRelatedArticles([])
                    setRelatedSamples([])
                    setRelatedError('')
                  }}
                >
                  Close
                </button>
              </div>
            </header>
            {relatedLoading ? (
              <div className="related-ioc-loading">Loading related items…</div>
            ) : (
              <div className="related-ioc-body">
                <div className="related-ioc-column">
                  <h4 className="related-ioc-subtitle">Articles</h4>
                  {relatedArticles.length === 0 ? (
                    <p className="related-ioc-empty">No related articles found.</p>
                  ) : (
                    <ul className="related-ioc-list">
                      {relatedArticles.map((a) => (
                        <li key={`${a.source}-${a.url || a.title}`}>
                          <div className="related-ioc-article-title">
                            {a.title || 'Untitled'}
                          </div>
                          <div className="related-ioc-article-meta">
                            <span>{a.source_label}</span>
                            {a.published_at && <span>{a.published_at}</span>}
                          </div>
                          {a.url && (
                            <a
                              href={a.url}
                              className="related-ioc-link"
                              target="_blank"
                              rel="noreferrer"
                            >
                              Open article
                            </a>
                          )}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
                <div className="related-ioc-column">
                  <h4 className="related-ioc-subtitle">Malware samples</h4>
                  {relatedSamples.length === 0 ? (
                    <p className="related-ioc-empty">No related malware samples found.</p>
                  ) : (
                    <ul className="related-ioc-list">
                      {relatedSamples.map((s) => {
                        const sha = s.sha256_hash
                        const url = sha
                          ? `https://bazaar.abuse.ch/sample/${encodeURIComponent(sha)}/`
                          : null
                        return (
                          <li key={sha || `${s.file_name}-${s.first_seen}`}>
                            <div className="related-ioc-article-title">
                              {s.signature || s.file_name || 'Sample'}
                            </div>
                            <div className="related-ioc-article-meta">
                              {s.first_seen && <span>{s.first_seen}</span>}
                              {s.file_type && <span>{s.file_type}</span>}
                            </div>
                            {sha && (
                              <div className="related-ioc-sample-hash">
                                <span className="related-ioc-hash-label">SHA256:</span>
                                <span className="related-ioc-hash-value">{sha}</span>
                              </div>
                            )}
                            {url && (
                              <a
                                href={url}
                                className="related-ioc-link"
                                target="_blank"
                                rel="noreferrer"
                              >
                                View on MalwareBazaar
                              </a>
                            )}
                          </li>
                        )
                      })}
                    </ul>
                  )}
                </div>
              </div>
            )}
          </section>
        )}
      </>
    ) : null

  const feedContent =
    loading && !articles.length ? (
      <div className="dashboard-loading">Loading articles…</div>
    ) : articles.length === 0 ? (
      <p className="dashboard-empty">
        No data yet. Click <strong>Refresh feed</strong> to fetch the latest items.
      </p>
    ) : (
      <>
        <ArticleSearchBar
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          categories={categories}
          activeCategory={activeCategory}
          onCategoryChange={setActiveCategory}
          activeIocFilters={activeIocFilters}
          onIocFilterChange={(val) => {
            setActiveIocFilters((prev) => {
              const next = new Set(prev)
              if (next.has(val)) next.delete(val)
              else next.add(val)
              return next
            })
          }}
          activeDays={activeDays}
          onDaysChange={setActiveDays}
          totalCount={articles.length}
          filteredCount={filteredArticles.length}
          hasActiveFilters={hasActiveFilters}
          onClearFilters={clearFilters}
        />
        {filteredArticles.length === 0 ? (
          <div className="search-no-results">
            <span className="search-no-results-icon">⌕</span>
            <p className="search-no-results-text">No articles match your filters.</p>
            <button type="button" className="search-clear-btn" onClick={clearFilters}>
              Clear all filters
            </button>
          </div>
        ) : (
          <div className="article-cards">
            {filteredArticles.map((article, idx) => (
              <ArticleCard
                key={article.url || idx}
                article={article}
                sourceLabel={meta.label}
                onIndicatorClick={openRelatedPanel}
              />
            ))}
          </div>
        )}
      </>
    )

  return (
    <>
      <DashboardLayout
        header={header}
        error={activeTab === 'feed' ? error : ''}
        sidebar={activeTab === 'feed' ? sidebar : null}
      >
        {activeTab === 'home' ? (
          <ExecutiveHome onThreatLevel={setThreatLevel} />
        ) : activeTab === 'feed' ? (
          <>
            <div className="dashboard-feed-header">
              <h2 className="dashboard-feed-title">
                {meta.label}{' '}
                <span className="dashboard-feed-count">({articles.length})</span>
              </h2>
            </div>
            {feedContent}
          </>
        ) : activeTab === 'intel' ? (
          <ThreatIntelligenceView />
        ) : (
          <MalwareSamplesView />
        )}
      </DashboardLayout>
      <ChatWidget />
    </>
  )
}

export default App
