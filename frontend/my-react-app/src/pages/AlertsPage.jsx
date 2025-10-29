import React, { useMemo } from 'react'
import './Styles/Dashboard.css'

function StatCard({ title, value, sub, icon }) {
  return (
    <div className="card stat-card">
      <div className="stat-icon">{icon}</div>
      <div className="stat-content">
        <div className="card-title">{title}</div>
        <div className="card-value">{value}</div>
        {sub ? <div className="card-sub">{sub}</div> : null}
      </div>
    </div>
  )
}

function StatusPill({ status }) {
  const cls = `pill pill-${status}`
  return <span className={cls}>{status}</span>
}

function AlertsPage({ alerts }) {
  const stats = useMemo(() => {
    const totalAlerts = alerts.length
    const delivered = alerts.filter(a => a.status === 'delivered').length
    const failed = alerts.filter(a => a.status === 'failed').length
    const partial = alerts.filter(a => a.status === 'partial').length
    const pending = alerts.filter(a => a.status === 'pending' || a.status === 'sending').length
    const acknowledged = alerts.reduce((sum, a) => sum + (a.acknowledgedCount || 0), 0)
    
    return { totalAlerts, delivered, failed, partial, pending, acknowledged }
  }, [alerts])

  return (
    <div className="page-content">
      <div className="page-header">
        <h1>📊 Dashboard & Active Alerts</h1>
        <p>Monitor alert statistics and view active notifications</p>
      </div>

      <div className="grid stats">
        <StatCard 
          title="Total Alerts" 
          value={stats.totalAlerts} 
          icon="📈"
        />
        <StatCard 
          title="Delivered" 
          value={stats.delivered} 
          sub={`${stats.totalAlerts > 0 ? Math.round((stats.delivered / stats.totalAlerts) * 100) : 0}% success rate`}
          icon="✅"
        />
        <StatCard 
          title="Partial" 
          value={stats.partial} 
          icon="⚠️"
        />
        <StatCard 
          title="Failed" 
          value={stats.failed} 
          icon="❌"
        />
        <StatCard 
          title="Pending/Sending" 
          value={stats.pending} 
          icon="⏳"
        />
        <StatCard 
          title="Acknowledged" 
          value={stats.acknowledged} 
          icon="👥"
        />
      </div>

      <div className="card">
        <div className="card-title">🚨 Active Alerts</div>
        <div className="table-container">
          <table className="table">
            <thead>
              <tr>
                <th>Title</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Targets</th>
                <th>Acknowledged</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map(a => (
                <tr key={a.id}>
                  <td className="alert-title">{a.title}</td>
                  <td><StatusPill status={a.severity} /></td>
                  <td><StatusPill status={a.status} /></td>
                  <td>{a.totalTargets ?? 0}</td>
                  <td>{a.acknowledgedCount ?? 0}</td>
                  <td>{new Date(a.createdAt).toLocaleString()}</td>
                </tr>
              ))}
              {alerts.length === 0 && (
                <tr>
                  <td colSpan="6" className="muted">
                    <div className="empty-state">
                      <div className="empty-icon">📭</div>
                      <div>No alerts yet</div>
                      <div className="empty-sub">Create your first alert using the Trigger page</div>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {alerts.length > 0 && (
        <div className="card">
          <div className="card-title">📈 Alert Performance</div>
          <div className="performance-grid">
            <div className="performance-item">
              <div className="performance-label">Delivery Rate</div>
              <div className="performance-value">
                {stats.totalAlerts > 0 ? Math.round((stats.delivered / stats.totalAlerts) * 100) : 0}%
              </div>
            </div>
            <div className="performance-item">
              <div className="performance-label">Failure Rate</div>
              <div className="performance-value">
                {stats.totalAlerts > 0 ? Math.round((stats.failed / stats.totalAlerts) * 100) : 0}%
              </div>
            </div>
            <div className="performance-item">
              <div className="performance-label">Acknowledgment Rate</div>
              <div className="performance-value">
                {stats.totalAlerts > 0 ? Math.round((stats.acknowledged / stats.totalAlerts) * 100) : 0}%
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default AlertsPage
