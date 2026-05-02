function DashboardTabs({ activeTab, onChange, threatLevel, feedUpdated }) {
  const dot = (show, cls) => show
    ? <span className={`tab-dot tab-dot--${cls}`} aria-label="New activity" />
    : null

  return (
    <div className="dashboard-tabs" role="tablist" aria-label="Dashboard views">
      <button
        type="button"
        role="tab"
        aria-selected={activeTab === 'home'}
        className={`dashboard-tab ${activeTab === 'home' ? 'dashboard-tab--active' : ''}`}
        onClick={() => onChange('home')}
      >
        Executive Dashboard
        {dot(threatLevel === 'high' || threatLevel === 'High', 'danger')}
      </button>
      <button
        type="button"
        role="tab"
        aria-selected={activeTab === 'feed'}
        className={`dashboard-tab ${activeTab === 'feed' ? 'dashboard-tab--active' : ''}`}
        onClick={() => onChange('feed')}
      >
        Threat Intel Feed
        {dot(feedUpdated && activeTab !== 'feed', 'info')}
      </button>
      <button
        type="button"
        role="tab"
        aria-selected={activeTab === 'intel'}
        className={`dashboard-tab ${activeTab === 'intel' ? 'dashboard-tab--active' : ''}`}
        onClick={() => onChange('intel')}
      >
        Threat Intelligence
      </button>
      <button
        type="button"
        role="tab"
        aria-selected={activeTab === 'malware'}
        className={`dashboard-tab ${activeTab === 'malware' ? 'dashboard-tab--active' : ''}`}
        onClick={() => onChange('malware')}
      >
        Malware Samples
      </button>
    </div>
  )
}

export default DashboardTabs
