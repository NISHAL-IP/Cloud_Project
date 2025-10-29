import React from 'react'
import './Styles/Dashboard.css'

function StatusPill({ status }) {
  const cls = `pill pill-${status}`
  return <span className={cls}>{status}</span>
}

function ManagementPage({ API_BASE, users, devices, user, getAuthHeaders }) {
  const isAdmin = user && user.role === 'admin'
  const createUser = async (e) => {
    e.preventDefault()
    if (!isAdmin) {
      alert('Only administrators can add users')
      return
    }
    
    const form = new FormData(e.currentTarget)
    const payload = { 
      name: form.get('name'), 
      email: form.get('email'), 
      role: form.get('role') 
    }
    const res = await fetch(`${API_BASE}/admin/users`, { 
      method: 'POST', 
      headers: { 
        'Content-Type': 'application/json',
        ...getAuthHeaders()
      }, 
      body: JSON.stringify(payload) 
    })
    if (!res.ok) {
      const error = await res.json()
      alert(error.message || 'Failed to create user')
    } else {
      alert('User created successfully')
    }
    e.currentTarget.reset()
  }

  const deleteUser = async (id) => {
    if (!isAdmin) {
      alert('Only administrators can delete users')
      return
    }
    
    if (!confirm('Are you sure you want to delete this user?')) return
    const res = await fetch(`${API_BASE}/admin/users/${id}`, { 
      method: 'DELETE',
      headers: getAuthHeaders()
    })
    if (!res.ok) {
      const error = await res.json()
      alert(error.message || 'Failed to delete user')
    } else {
      alert('User deleted successfully')
    }
  }

  const registerDevice = async (e) => {
    e.preventDefault()
    if (!isAdmin) {
      alert('Only administrators can register devices')
      return
    }
    
    const form = new FormData(e.currentTarget)
    const payload = { 
      userEmail: form.get('userEmail'), 
      platform: form.get('platform'), 
      token: form.get('token') 
    }
    const res = await fetch(`${API_BASE}/admin/devices`, { 
      method: 'POST', 
      headers: { 
        'Content-Type': 'application/json',
        ...getAuthHeaders()
      }, 
      body: JSON.stringify(payload) 
    })
    if (!res.ok) {
      const error = await res.json()
      alert(error.message || 'Failed to register device')
    } else {
      alert('Device registered successfully')
    }
    e.currentTarget.reset()
  }

  const toggleDevice = async (id) => {
    if (!isAdmin) {
      alert('Only administrators can toggle devices')
      return
    }
    
    const res = await fetch(`${API_BASE}/admin/devices/${id}/toggle`, { 
      method: 'PATCH',
      headers: getAuthHeaders()
    })
    if (!res.ok) {
      const error = await res.json()
      alert(error.message || 'Failed to toggle device')
    } else {
      alert('Device status updated successfully')
    }
  }

  return (
    <div className="page-content">
      <div className="page-header">
        <h1>⚙️ Manage Devices & Users</h1>
        <p>Add, edit, and manage user accounts and device registrations</p>
        {!isAdmin && (
          <div className="admin-warning">
            <span className="warning-icon">⚠️</span>
            <span>You are viewing in read-only mode. Only administrators can add, edit, or delete users and devices.</span>
          </div>
        )}
      </div>

      <div className="grid two">
        <div className="card">
          <div className="card-title">👥 User Management</div>
          <form onSubmit={createUser} className="form" style={{ opacity: isAdmin ? 1 : 0.6 }}>
            <div className="form-group">
              <label htmlFor="user-name">Name</label>
              <input id="user-name" name="name" placeholder="Enter full name" required />
            </div>
            <div className="form-group">
              <label htmlFor="user-email">Email</label>
              <input id="user-email" name="email" placeholder="Enter email address" type="email" required />
            </div>
            <div className="form-group">
              <label htmlFor="user-role">Role</label>
              <select id="user-role" name="role" defaultValue="student">
                <option value="student">Student</option>
                <option value="staff">Staff</option>
                <option value="admin">Admin</option>
              </select>
            </div>
            <button type="submit" className="primary-button" disabled={!isAdmin}>
              {isAdmin ? 'Add User' : 'Admin Only'}
            </button>
          </form>
          
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Email</th>
                  <th>Role</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map(u => (
                  <tr key={u.id}>
                    <td>{u.name}</td>
                    <td>{u.email}</td>
                    <td><StatusPill status={u.role} /></td>
                    <td>{new Date(u.createdAt).toLocaleString()}</td>
                    <td>
                      <button 
                        onClick={() => deleteUser(u.id)} 
                        className="danger-button small"
                        disabled={!isAdmin}
                      >
                        {isAdmin ? 'Delete' : 'Admin Only'}
                      </button>
                    </td>
                  </tr>
                ))}
                {users.length === 0 && (
                  <tr>
                    <td colSpan="5" className="muted">
                      <div className="empty-state">
                        <div className="empty-icon">👤</div>
                        <div>No users found</div>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="card">
          <div className="card-title">📱 Device Management</div>
          <form onSubmit={registerDevice} className="form" style={{ opacity: isAdmin ? 1 : 0.6 }}>
            <div className="form-group">
              <label htmlFor="device-user">User Email</label>
              <input id="device-user" name="userEmail" placeholder="Enter user email" type="email" required />
            </div>
            <div className="form-group">
              <label htmlFor="device-platform">Platform</label>
              <select id="device-platform" name="platform" defaultValue="web">
                <option value="web">Web</option>
                <option value="ios">iOS</option>
                <option value="android">Android</option>
              </select>
            </div>
            <div className="form-group">
              <label htmlFor="device-token">Device Token</label>
              <input id="device-token" name="token" placeholder="Enter device token" required />
            </div>
            <button type="submit" className="primary-button" disabled={!isAdmin}>
              {isAdmin ? 'Register Device' : 'Admin Only'}
            </button>
          </form>
          
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>User</th>
                  <th>Platform</th>
                  <th>Active</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {devices.map(d => (
                  <tr key={d.id}>
                    <td>{d.userEmail}</td>
                    <td><StatusPill status={d.platform} /></td>
                    <td>
                      <span className={`status-indicator ${d.active ? 'active' : 'inactive'}`}>
                        {d.active ? '✅ Yes' : '❌ No'}
                      </span>
                    </td>
                    <td>{new Date(d.createdAt).toLocaleString()}</td>
                    <td>
                      <button 
                        onClick={() => toggleDevice(d.id)} 
                        className="secondary-button small"
                        disabled={!isAdmin}
                      >
                        {isAdmin ? 'Toggle' : 'Admin Only'}
                      </button>
                    </td>
                  </tr>
                ))}
                {devices.length === 0 && (
                  <tr>
                    <td colSpan="5" className="muted">
                      <div className="empty-state">
                        <div className="empty-icon">📱</div>
                        <div>No devices registered</div>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-title">📊 Management Summary</div>
        <div className="summary-grid">
          <div className="summary-item">
            <div className="summary-label">Total Users</div>
            <div className="summary-value">{users.length}</div>
          </div>
          <div className="summary-item">
            <div className="summary-label">Active Devices</div>
            <div className="summary-value">{devices.filter(d => d.active).length}</div>
          </div>
          <div className="summary-item">
            <div className="summary-label">Total Devices</div>
            <div className="summary-value">{devices.length}</div>
          </div>
          <div className="summary-item">
            <div className="summary-label">Admin Users</div>
            <div className="summary-value">{users.filter(u => u.role === 'admin').length}</div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default ManagementPage
