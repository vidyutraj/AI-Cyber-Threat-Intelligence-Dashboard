import IndicatorBadge from './IndicatorBadge'
import { CategoryTags } from './CategoryTag'

function countIndicators(article) {
  let n = 0
  if (article.cves) n += String(article.cves).split(',').filter(Boolean).length
  if (article.ips) n += String(article.ips).split(',').filter(Boolean).length
  if (article.domains) n += String(article.domains).split(',').filter(Boolean).length
  if (article.hashes) n += String(article.hashes).split(',').filter(Boolean).length
  if (article.email) n += String(article.email).split(',').filter(Boolean).length
  if (article.ipv6) n += String(article.ipv6).split(',').filter(Boolean).length
  if (article.urls) n += String(article.urls).split(',').filter(Boolean).length
  if (article.mitre_techniques) n += String(article.mitre_techniques).split(',').filter(Boolean).length
  if (article.malware_tools) n += String(article.malware_tools).split(',').filter(Boolean).length
  return n
}

function formatMetaTime(publishedAt) {
  if (!publishedAt) return ''
  const [datePart, timePart] = String(publishedAt).split('T')
  if (!datePart) return ''
  const time = timePart ? timePart.replace(/\+[\d:]+/, '').slice(0, 8) : ''
  return time ? `${datePart} ${time} UTC` : datePart
}

function ArticleCard({ article, sourceLabel, onIndicatorClick }) {
  const hasIndicators =
    article.cves ||
    article.ips ||
    article.ipv6 ||
    article.domains ||
    article.hashes ||
    article.email ||
    article.urls ||
    article.mitre_techniques ||
    article.malware_tools
  const indicatorCount = countIndicators(article)
  const fullDescription = article.description ? String(article.description).trim() : ''
  const dateStr = formatMetaTime(article.published_at)

  return (
    <article className="article-card">
      <div className="article-card-inner">
        <h3 className="article-card-title">{article.title || 'Untitled'}</h3>
        <div className="article-card-meta-row">
          {[
            dateStr && <span key="t" className="article-card-meta-time">{dateStr}</span>,
            sourceLabel && <span key="s" className="article-card-meta-source">{sourceLabel}</span>,
            <span key="i" className="article-card-meta-indicators">{indicatorCount === 0 ? 'No indicators' : `${indicatorCount} indicator${indicatorCount !== 1 ? 's' : ''}`}</span>,
          ]
            .filter(Boolean)
            .reduce((out, el, i) => (i === 0 ? [el] : [...out, <span key={`sep-${i}`} className="article-card-meta-sep"> • </span>, el]), [])}
        </div>
        <CategoryTags categories={article.categories} />
        {article.tags && (
          <div className="article-card-tags">
            <span className="article-card-tags-label">Tags:</span>
            <CategoryTags categories={article.tags} />
          </div>
        )}
        {fullDescription && (
          <div className="article-card-description-wrap">
            <p className="article-card-description">
              {fullDescription}
            </p>
          </div>
        )}
        {hasIndicators && (
          <div className="article-card-indicators">
            <IndicatorBadge type="cve" value={article.cves} onClickValue={onIndicatorClick} />
            <IndicatorBadge type="ip" value={article.ips} onClickValue={onIndicatorClick} />
            <IndicatorBadge type="ipv6" value={article.ipv6} onClickValue={onIndicatorClick} />
            <IndicatorBadge type="domain" value={article.domains} onClickValue={onIndicatorClick} />
            <IndicatorBadge type="email" value={article.email} onClickValue={onIndicatorClick} />
            <IndicatorBadge type="url" value={article.urls} onClickValue={onIndicatorClick} />
            <IndicatorBadge
              type="mitre"
              value={article.mitre_techniques}
              onClickValue={onIndicatorClick}
            />
            <IndicatorBadge
              type="malware"
              value={article.malware_tools}
              onClickValue={onIndicatorClick}
            />
            <IndicatorBadge type="hash" value={article.hashes} onClickValue={onIndicatorClick} />
          </div>
        )}
        <div className="article-card-actions">
          {article.url ? (
            <a
              href={article.url}
              target="_blank"
              rel="noreferrer"
              className="article-card-link"
              aria-label="Open article in new tab"
            >
              Open
            </a>
          ) : (
            <span className="article-card-link-disabled">—</span>
          )}
        </div>
      </div>
    </article>
  )
}

export default ArticleCard
