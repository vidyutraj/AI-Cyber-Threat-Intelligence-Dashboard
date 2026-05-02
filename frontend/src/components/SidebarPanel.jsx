function countArticleIndicators(article) {
  let n = 0
  // Only count true IOCs here (same set used for "Most common indicator")
  if (article.cves) n += String(article.cves).split(',').filter(Boolean).length
  if (article.ips) n += String(article.ips).split(',').filter(Boolean).length
  if (article.ipv6) n += String(article.ipv6).split(',').filter(Boolean).length
  if (article.domains) n += String(article.domains).split(',').filter(Boolean).length
  if (article.hashes) n += String(article.hashes).split(',').filter(Boolean).length
  if (article.email) n += String(article.email).split(',').filter(Boolean).length
  if (article.malware_tools) {
    n += String(article.malware_tools).split(',').filter(Boolean).length
  }
  return n
}

function getMostCommonIndicatorType(articles) {
  const counts = {
    cve: 0,
    ip: 0,
    domain: 0,
    hash: 0,
    email: 0,
    malware: 0,
  }
  for (const a of articles || []) {
    if (a.cves) counts.cve += String(a.cves).split(',').filter(Boolean).length
    if (a.ips) counts.ip += String(a.ips).split(',').filter(Boolean).length
    if (a.ipv6) counts.ip += String(a.ipv6).split(',').filter(Boolean).length
    if (a.domains) counts.domain += String(a.domains).split(',').filter(Boolean).length
    if (a.hashes) counts.hash += String(a.hashes).split(',').filter(Boolean).length
    if (a.email) counts.email += String(a.email).split(',').filter(Boolean).length
    if (a.malware_tools) counts.malware += String(a.malware_tools).split(',').filter(Boolean).length
  }
  const entries = Object.entries(counts).filter(([, v]) => v > 0)
  if (entries.length === 0) return 'NONE'
  entries.sort((a, b) => b[1] - a[1])
  const labels = {
    cve: 'CVE',
    ip: 'IP',
    domain: 'Domain',
    hash: 'Hash',
    email: 'Email',
    malware: 'Malware',
  }
  return labels[entries[0][0]] || entries[0][0]
}

function SidebarPanel({ articles, sourceLabel }) {
  const list = articles || []
  const withIndicators = list.filter(
    (a) =>
      a.cves ||
      a.ips ||
      a.ipv6 ||
      a.domains ||
      a.hashes ||
      a.email ||
      a.urls ||
      a.mitre_techniques ||
      a.malware_tools
  )
  const totalIndicators = list.reduce((sum, a) => sum + countArticleIndicators(a), 0)
  const mostCommon = getMostCommonIndicatorType(list)

  return (
    <aside className="sidebar-panel sidebar-panel--threat-summary">
      <div className="sidebar-panel-inner">
        <h3 className="sidebar-panel-title">Threat Summary</h3>
        {sourceLabel && (
          <p className="sidebar-panel-source">Source: {sourceLabel}</p>
        )}
        <div className="sidebar-panel-metrics">
          <div className="sidebar-metric">
            <span className="sidebar-metric-value">{list.length}</span>
            <span className="sidebar-metric-label">Total articles</span>
          </div>
          <div className="sidebar-metric">
            <span className="sidebar-metric-value">{totalIndicators}</span>
            <span className="sidebar-metric-label">Indicators detected</span>
          </div>
          <div className="sidebar-metric">
            <span className="sidebar-metric-value">{withIndicators.length}</span>
            <span className="sidebar-metric-label">Articles with IOCs</span>
          </div>
          <div className="sidebar-metric sidebar-metric--highlight">
            <span className="sidebar-metric-value">{mostCommon}</span>
            <span className="sidebar-metric-label">Most common indicator</span>
          </div>
        </div>
        <p className="sidebar-panel-hint">
          Select a source and refresh to load the latest threat intelligence feed.
        </p>
      </div>
    </aside>
  )
}

export default SidebarPanel
