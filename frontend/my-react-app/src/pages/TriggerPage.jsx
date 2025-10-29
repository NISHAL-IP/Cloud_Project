import React, { useState } from 'react'
import './Styles/Dashboard.css'

function TriggerPage({ API_BASE }) {
  const [newAlert, setNewAlert] = useState({ 
    title: '', 
    message: '', 
    severity: 'info', 
    target: 'all' 
  })
  const [loading, setLoading] = useState(false)

  const triggerAlert = async (e) => {
    e.preventDefault()
    setLoading(true)
    try {
      const res = await fetch(`${API_BASE}/admin/alerts`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newAlert)
      })
      if (!res.ok) throw new Error('Failed to create alert')
      setNewAlert({ title: '', message: '', severity: 'info', target: 'all' })
      alert('Alert triggered successfully!')
    } catch (e) {
      alert('Failed to trigger alert')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="page-content">
      <div className="page-header">
        <h1>🚨 Trigger Emergency Alert</h1>
        <p>Send emergency notifications to users and devices</p>
      </div>

      <div className="card trigger-card">
        <div className="card-title">Create New Alert</div>
        <form onSubmit={triggerAlert} className="form">
          <div className="form-group">
            <label htmlFor="title">Alert Title</label>
            <input 
              id="title"
              placeholder="Enter alert title" 
              value={newAlert.title} 
              onChange={e => setNewAlert({ ...newAlert, title: e.target.value })} 
              required 
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="message">Alert Message</label>
            <textarea 
              id="message"
              placeholder="Enter detailed alert message" 
              value={newAlert.message} 
              onChange={e => setNewAlert({ ...newAlert, message: e.target.value })} 
              required 
            />
          </div>
          
          <div className="form-row">
            <div className="form-group">
              <label htmlFor="severity">Severity Level</label>
              <select 
                id="severity"
                value={newAlert.severity} 
                onChange={e => setNewAlert({ ...newAlert, severity: e.target.value })}
              >
                <option value="info">ℹ️ Info</option>
                <option value="warning">⚠️ Warning</option>
                <option value="critical">🚨 Critical</option>
              </select>
            </div>
            
            <div className="form-group">
              <label htmlFor="target">Target Audience</label>
              <input 
                id="target"
                placeholder="Enter email or 'all' for everyone" 
                value={newAlert.target} 
                onChange={e => setNewAlert({ ...newAlert, target: e.target.value })} 
              />
            </div>
          </div>
          
          <button type="submit" disabled={loading} className="trigger-button">
            {loading ? 'Sending Alert...' : '🚨 Send Emergency Alert'}
          </button>
        </form>
      </div>

      <div className="card info-card">
        <div className="card-title">📋 Alert Guidelines</div>
        <div className="guidelines">
          <div className="guideline-item">
            <strong>Info:</strong> General notifications, updates, or announcements
          </div>
          <div className="guideline-item">
            <strong>Warning:</strong> Important notices that require attention
          </div>
          <div className="guideline-item">
            <strong>Critical:</strong> Emergency situations requiring immediate action
          </div>
          <div className="guideline-item">
            <strong>Target:</strong> Use 'all' to send to everyone, or specify an email address
          </div>
        </div>
      </div>
    </div>
  )
}

export default TriggerPage
