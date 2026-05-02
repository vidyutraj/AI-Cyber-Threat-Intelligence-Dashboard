import { useState } from 'react'

function IndicatorBadge({ type, value, onClickValue }) {
  if (!value || !String(value).trim()) return null
  const labels = {
    cve: 'CVE',
    ip: 'IP',
    ipv6: 'IPv6',
    domain: 'Domain',
    email: 'Email',
    url: 'URL',
    mitre: 'MITRE',
    malware: 'Malware/Tool',
    hash: 'Hash',
  }
  const label = labels[type] || type
  const items = String(value)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
  if (items.length === 0) return null

  const [expanded, setExpanded] = useState(false)

  const displayValue = expanded
    ? items.join(', ')
    : items[0] + (items.length > 1 ? ` +${items.length - 1}` : '')

  const hasMore = items.length > 1

  const handleClick = () => {
    if (hasMore) {
      // Toggle expanded view to reveal individual values
      setExpanded((e) => !e)
    } else if (onClickValue) {
      // Single-value badge: drill down on that one IOC
      onClickValue(items[0])
    }
  }

  return (
    <button
      type="button"
      className={`indicator-badge indicator-badge--${type}`}
      data-type={type}
      onClick={handleClick}
      title={expanded ? 'Click to collapse' : hasMore ? 'Click to view all values' : undefined}
    >
      <span className="indicator-badge-label">{label}</span>
      {hasMore && expanded ? (
        <span className="indicator-badge-values">
          {items.map((item) => (
            <button
              key={item}
              type="button"
              className="indicator-badge-chip"
              onClick={(e) => {
                e.stopPropagation()
                onClickValue && onClickValue(item)
              }}
            >
              {item}
            </button>
          ))}
        </span>
      ) : (
        <span className="indicator-badge-value">
          {items[0] + (hasMore ? ` +${items.length - 1}` : '')}
        </span>
      )}
    </button>
  )
}

export default IndicatorBadge
