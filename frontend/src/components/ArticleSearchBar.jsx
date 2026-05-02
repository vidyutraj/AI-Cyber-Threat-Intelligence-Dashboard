const IOC_OPTIONS = [
  { value: 'cve',    label: 'CVE'    },
  { value: 'ip',     label: 'IP'     },
  { value: 'domain', label: 'Domain' },
  { value: 'hash',   label: 'Hash'   },
]
 
const DAY_OPTIONS = [
  { value: 7,  label: '7d'  },
  { value: 14, label: '14d' },
  { value: 30, label: '30d' },
]
 
export default function ArticleSearchBar({
  searchQuery,
  onSearchChange,
  categories,
  activeCategory,
  onCategoryChange,
  activeIocFilters,
  onIocFilterChange,
  activeDays,
  onDaysChange,
  totalCount,
  filteredCount,
  hasActiveFilters,
  onClearFilters,
}) {

const iocSet = activeIocFilters instanceof Set ? activeIocFilters : new Set()
  const handleSearchKey = (e) => {
    if (e.key === 'Escape') onSearchChange('')
  }
 
  return (
    <div className="asb-root">
      <div className="asb-top-row">
        <div className="asb-search-wrap">
          <span className="asb-search-icon" aria-hidden="true">⌕</span>
          <input
            className="asb-search-input"
            type="search"
            placeholder="Search titles, descriptions, CVEs, domains…"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            onKeyDown={handleSearchKey}
            aria-label="Search articles"
            spellCheck={false}
          />
          {searchQuery && (
            <button
              type="button"
              className="asb-search-clear"
              onClick={() => onSearchChange('')}
              aria-label="Clear search"
            >
              ✕
            </button>
          )}
        </div>
 
        <div className="asb-result-count">
          {hasActiveFilters ? (
            <>
              <span className="asb-count-filtered">{filteredCount}</span>
              <span className="asb-count-sep">/</span>
              <span className="asb-count-total">{totalCount}</span>
              <span className="asb-count-label">articles</span>
            </>
          ) : (
            <>
              <span className="asb-count-total">{totalCount}</span>
              <span className="asb-count-label">articles</span>
            </>
          )}
          {hasActiveFilters && (
            <button type="button" className="asb-clear-all" onClick={onClearFilters}>
              Clear all
            </button>
          )}
        </div>
      </div>
 
      <div className="asb-filters-row">
        <div className="asb-filter-group">
          <span className="asb-filter-label">IOC</span>
          <div className="asb-chip-group">
            {IOC_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                type="button"
                className={`asb-chip asb-chip--ioc asb-chip--ioc-${opt.value}${iocSet.has(opt.value) ? ' asb-chip--active' : ''}`}
                onClick={() => onIocFilterChange(opt.value)}
                aria-pressed={iocSet.has(opt.value)}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>
 
        <div className="asb-filter-divider" aria-hidden="true" />
 
        <div className="asb-filter-group">
          <span className="asb-filter-label">Date</span>
          <div className="asb-chip-group">
            {DAY_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                type="button"
                className={`asb-chip asb-chip--date${activeDays === opt.value ? ' asb-chip--active' : ''}`}
                onClick={() => onDaysChange(activeDays === opt.value ? 0 : opt.value)}
                aria-pressed={activeDays === opt.value}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>
 
        {categories.length > 0 && (
          <>
            <div className="asb-filter-divider" aria-hidden="true" />
            <div className="asb-filter-group asb-filter-group--categories">
              <span className="asb-filter-label">Category</span>
              <div className="asb-chip-group asb-chip-group--wrap">
                {categories.map((cat) => (
                  <button
                    key={cat}
                    type="button"
                    className={`asb-chip asb-chip--cat${activeCategory === cat ? ' asb-chip--active' : ''}`}
                    onClick={() => onCategoryChange(activeCategory === cat ? '' : cat)}
                    aria-pressed={activeCategory === cat}
                  >
                    {cat}
                  </button>
                ))}
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}