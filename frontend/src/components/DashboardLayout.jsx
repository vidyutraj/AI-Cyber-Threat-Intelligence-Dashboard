function DashboardLayout({ header, error, children, sidebar }) {
  const hasSidebar = Boolean(sidebar)
  return (
    <div className="dashboard-layout">
      {header}
      {error && <div className="dashboard-alert dashboard-alert-error">{error}</div>}
      <div className={`dashboard-main ${hasSidebar ? '' : 'dashboard-main--single'}`}>
        <div className="dashboard-feed">{children}</div>
        {sidebar && <div className="dashboard-sidebar">{sidebar}</div>}
      </div>
    </div>
  )
}

export default DashboardLayout
