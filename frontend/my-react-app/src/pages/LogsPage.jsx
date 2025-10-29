import React, { useState, useMemo } from 'react'
import './Styles/Dashboard.css'

function StatusPill({ status }) {
  const cls = `pill pill-${status}`
  return <span className={cls}>{status}</span>
}

function LogsPage({ logs }) {
  const [filter, setFilter] = useState('all')
  const [searchTerm, setSearchTerm] = useState('')

  const filteredLogs = useMemo(() => {
    let filtered = logs

    // Filter by status
    if (filter !== 'all') {
      filtered = filtered.filter(log => log.status === filter)
    }

    // Filter by search term
    if (searchTerm) {
      filtered = filtered.filter(log => 
        log.alertId.toLowerCase().includes(searchTerm.toLowerCase()) ||
        log.deviceToken.toLowerCase().includes(searchTerm.toLowerCase()) ||
        log.detail.toLowerCase().includes(searchTerm.toLowerCase())
      )
    }

    return filtered
  }, [logs, filter, searchTerm])

  const logStats = useMemo(() => {
    const total = logs.length
    const successful = logs.filter(l => l.status === 'delivered').length
    const failed = logs.filter(l => l.status === 'failed').length
    const pending = logs.filter(l => l.status === 'pending' || l.status === 'sending').length
    
    return { total, successful, failed, pending }
  }, [logs])

  const clearLogs = () => {
    if (confirm('Are you sure you want to clear all logs? This action cannot be undone.')) {
      // This would need to be implemented in the backend
      alert('Clear logs functionality needs to be implemented in the backend')
    }
  }

  return (
    <div className="page-content">
      <div className="page-header">
        <h1>📋 Delivery Logs</h1>
        <p>Monitor alert delivery status and troubleshoot issues</p>
      </div>

      <div className="grid stats">
        <div className="card stat-card">
          <div className="stat-icon">📊</div>
          <div className="stat-content">
            <div className="card-title">Total Logs</div>
            <div className="card-value">{logStats.total}</div>
          </div>
        </div>
        <div className="card stat-card">
          <div className="stat-icon">✅</div>
          <div className="stat-content">
            <div className="card-title">Successful</div>
            <div className="card-value">{logStats.successful}</div>
            <div className="card-sub">
              {logStats.total > 0 ? Math.round((logStats.successful / logStats.total) * 100) : 0}% success rate
            </div>
          </div>
        </div>
        <div className="card stat-card">
          <div className="stat-icon">❌</div>
          <div className="stat-content">
            <div className="card-title">Failed</div>
            <div className="card-value">{logStats.failed}</div>
          </div>
        </div>
        <div className="card stat-card">
          <div className="stat-icon">⏳</div>
          <div className="stat-content">
            <div className="card-title">Pending</div>
            <div className="card-value">{logStats.pending}</div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div className="card-title">📋 Delivery Logs</div>
          <div className="card-actions">
            <button onClick={clearLogs} className="danger-button small">
              Clear Logs
            </button>
          </div>
        </div>
        
        <div className="filters">
          <div className="filter-group">
            <label htmlFor="status-filter">Filter by Status:</label>
            <select 
              id="status-filter"
              value={filter} 
              onChange={e => setFilter(e.target.value)}
              className="filter-select"
            >
              <option value="all">All Statuses</option>
              <option value="delivered">Delivered</option>
              <option value="failed">Failed</option>
              <option value="pending">Pending</option>
              <option value="sending">Sending</option>
            </select>
          </div>
          
          <div className="filter-group">
            <label htmlFor="search-log">Search:</label>
            <input
              id="search-log"
              type="text"
              placeholder="Search by alert ID, device token, or detail..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              className="search-input"
            />
          </div>
        </div>

        <div className="table-container">
          <table className="table">
            <thead>
              <tr>
                <th>Alert ID</th>
                <th>Device Token</th>
                <th>Status</th>
                <th>Timestamp</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {filteredLogs.map(l => (
                <tr key={l.id} className={`log-row log-${l.status}`}>
                  <td className="alert-id">{l.alertId}</td>
                  <td className="device-token mono">{l.deviceToken}</td>
                  <td><StatusPill status={l.status} /></td>
                  <td className="timestamp">{new Date(l.timestamp).toLocaleString()}</td>
                  <td className="detail">{l.detail || '-'}</td>
                </tr>
              ))}
              {filteredLogs.length === 0 && (
                <tr>
                  <td colSpan="5" className="muted">
                    <div className="empty-state">
                      <div className="empty-icon">📭</div>
                      <div>
                        {logs.length === 0 ? 'No logs available' : 'No logs match your filters'}
                      </div>
                      {logs.length === 0 && (
                        <div className="empty-sub">Logs will appear here when alerts are sent</div>
                      )}
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {filteredLogs.length > 0 && (
          <div className="table-footer">
            <div className="pagination-info">
              Showing {filteredLogs.length} of {logs.length} logs
            </div>
          </div>
        )}
      </div>

      {logs.length > 0 && (
        <div className="card">
          <div className="card-title">🔍 Log Analysis</div>
          <div className="analysis-grid">
            <div className="analysis-item">
              <div className="analysis-label">Most Common Failure Reason</div>
              <div className="analysis-value">
                {(() => {
                  const failureReasons = logs
                    .filter(l => l.status === 'failed' && l.detail)
                    .map(l => l.detail)
                    .reduce((acc, detail) => {
                      acc[detail] = (acc[detail] || 0) + 1
                      return acc
                    }, {})
                  
                  const mostCommon = Object.entries(failureReasons)
                    .sort(([,a], [,b]) => b - a)[0]
                  
                  return mostCommon ? mostCommon[0] : 'No failures recorded'
                })()}
              </div>
            </div>
            <div className="analysis-item">
              <div className="analysis-label">Average Delivery Time</div>
              <div className="analysis-value">
                {(() => {
                  const deliveredLogs = logs.filter(l => l.status === 'delivered')
                  if (deliveredLogs.length === 0) return 'N/A'
                  
                  // This is a simplified calculation - in reality you'd need to track creation time
                  return 'N/A (requires alert creation timestamp)'
                })()}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default LogsPage
