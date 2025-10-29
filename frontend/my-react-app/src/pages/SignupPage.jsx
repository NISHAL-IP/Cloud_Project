import React, { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'

function SignupPage() {
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [phone, setPhone] = useState('')
  const [role, setRole] = useState('student')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  const handleSignup = async (e) => {
    e.preventDefault()
    setLoading(true)

    try {
      const res = await fetch('http://localhost:3000/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email, password, phone, role })
      })

      const data = await res.json()
      if (res.ok) {
        alert(data.message)
        navigate('/') // back to login
      } else {
        alert(data.message || 'Signup failed')
      }
    } catch (err) {
      console.error('Signup fetch error:', err)
      alert('Server error, check backend')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-container">
      <div className="login-card">
        <h2>Sign Up</h2>
        <form onSubmit={handleSignup}>
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />

          <input
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />

          <input
            type="tel"
            placeholder="Phone (E.164, e.g. +15551234567)"
            value={phone}
            onChange={(e) => setPhone(e.target.value)}
          />

          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />

          <select
            value={role}
            onChange={(e) => setRole(e.target.value)}
            required
          >
            <option value="student">Student</option>
            <option value="staff">Staff</option>
            <option value="admin">Admin</option>
          </select>

          <button type="submit" disabled={loading}>
            {loading ? 'Signing up...' : 'Sign Up'}
          </button>
        </form>

        <p className="signup-text">
          Already have an account?{' '}
          <Link to="/" className="signup-link">
            Login
          </Link>
        </p>
      </div>
    </div>
  )
}

export default SignupPage
