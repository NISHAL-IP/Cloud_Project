import React, { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import Navigation from '../components/Navigation'
import TriggerPage from './TriggerPage'
import AlertsPage from './AlertsPage'
import ManagementPage from './ManagementPage'
import LogsPage from './LogsPage'
import './Styles/Dashboard.css'

function Dashboard() {
  const API_BASE = useMemo(() => 'http://localhost:3000', [])
  const { user, getAuthHeaders, loading: authLoading } = useAuth()
  const navigate = useNavigate()

  const [alerts, setAlerts] = useState([])
  const [users, setUsers] = useState([])
  const [devices, setDevices] = useState([])
  const [logs, setLogs] = useState([])
  const [activePage, setActivePage] = useState('dashboard')

  // Redirect if not authenticated
  useEffect(() => {
    if (!authLoading && !user) {
      navigate('/')
    }
  }, [user, authLoading, navigate])

  // Initial fetch
  useEffect(() => {
    const load = async () => {
      try {
        const [a, u, d, l] = await Promise.all([
          fetch(`${API_BASE}/admin/alerts`).then(r => r.json()),
          fetch(`${API_BASE}/admin/users`).then(r => r.json()),
          fetch(`${API_BASE}/admin/devices`).then(r => r.json()),
          fetch(`${API_BASE}/admin/logs`).then(r => r.json())
        ])
        setAlerts(a.alerts || [])
        setUsers(u.users || [])
        setDevices(d.devices || [])
        setLogs(l.logs || [])
      } catch (e) {
        console.error('Initial load failed', e)
      }
    }
    load()
  }, [API_BASE])

  // Live updates via SSE
  useEffect(() => {
    const es = new EventSource(`${API_BASE}/admin/stream`)

    es.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data)
        if (data.type === 'snapshot') {
          setAlerts(data.alerts || [])
          setUsers(data.users || [])
          setDevices(data.devices || [])
        }
        if (data.type === 'alert_created') {
          setAlerts(prev => [data.alert, ...prev])
        }
        if (data.type === 'alert_status') {
          setAlerts(prev => prev.map(a => a.id === data.alertId ? { ...a, status: data.status, totalTargets: data.totalTargets ?? a.totalTargets } : a))
        }
        if (data.type === 'delivery_log') {
          setLogs(prev => [data.log, ...prev].slice(0, 500))
        }
        if (data.type === 'alert_acknowledged') {
          setAlerts(prev => prev.map(a => a.id === data.alertId ? { ...a, acknowledgedCount: data.acknowledgedCount } : a))
        }
        if (data.type === 'user_created') setUsers(prev => [data.user, ...prev])
        if (data.type === 'user_deleted') setUsers(prev => prev.filter(u => u.id !== data.id))
        if (data.type === 'device_registered') setDevices(prev => [data.device, ...prev])
        if (data.type === 'device_toggled') setDevices(prev => prev.map(d => d.id === data.device.id ? data.device : d))
      } catch (e) {
        console.error('SSE parse error', e)
      }
    }

    es.onerror = () => {
      // auto-reconnect handled by browser; no-op
    }

    return () => es.close()
  }, [API_BASE])

  const renderActivePage = () => {
    switch (activePage) {
      case 'trigger':
        return <TriggerPage API_BASE={API_BASE} user={user} getAuthHeaders={getAuthHeaders} />
      case 'dashboard':
        return <AlertsPage alerts={alerts} user={user} />
      case 'management':
        return <ManagementPage API_BASE={API_BASE} users={users} devices={devices} user={user} getAuthHeaders={getAuthHeaders} />
      case 'logs':
        return <LogsPage logs={logs} user={user} />
      default:
        return <AlertsPage alerts={alerts} user={user} />
    }
  }

  // Show loading while checking authentication
  if (authLoading) {
    return (
      <div className="dash-wrap">
        <div style={{ textAlign: 'center', padding: '50px' }}>
          <div>Loading...</div>
        </div>
      </div>
    )
  }

  // Don't render if not authenticated (will redirect)
  if (!user) {
    return null
  }

  return (
    <div className="dash-wrap">
      <Navigation activePage={activePage} onPageChange={setActivePage} />
      {renderActivePage()}
    </div>
  )
}

export default Dashboard
