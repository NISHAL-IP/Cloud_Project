import React from 'react'
import { useAuth } from '../contexts/AuthContext'
import './Navigation.css'

function Navigation({ activePage, onPageChange }) {
  const { user, logout } = useAuth()
  const pages = [
    { id: 'trigger', label: 'Trigger Alerts', icon: '🚨' },
    { id: 'dashboard', label: 'dashboard & Alerts', icon: '📊' },
    { id: 'management', label: 'Manage Devices & Users', icon: '⚙️' },
    { id: 'logs', label: 'Delivery Logs', icon: '📋' }
  ]

  return (
    <nav className="dashboard-nav">
      <div className="nav-header">
        <div className="nav-title-section">
          <h2>dashboard</h2>
          <div className="user-info">
            <span className="user-name">{user?.username}</span>
            <span className="user-role">{user?.role}</span>
          </div>
        </div>
        <button onClick={logout} className="logout-button">
          Logout
        </button>
      </div>
      <div className="nav-tabs">
        {pages.map(page => (
          <button
            key={page.id}
            className={`nav-tab ${activePage === page.id ? 'active' : ''}`}
            onClick={() => onPageChange(page.id)}
          >
            <span className="nav-icon">{page.icon}</span>
            <span className="nav-label">{page.label}</span>
          </button>
        ))}
      </div>
    </nav>
  )
}

export default Navigation
