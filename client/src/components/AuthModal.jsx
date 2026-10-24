import React, { useState } from 'react';
import { X, Lock, Mail, User, AlertCircle, ShieldCheck } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function AuthModal({ isOpen, onClose }) {
  const { login, register, quickSwitchDemoRole } = useAuth();
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [systemRole, setSystemRole] = useState('document_owner');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      if (isRegister) {
        await register(email, password, fullName, systemRole);
      } else {
        await login(email, password);
      }
      onClose();
    } catch (err) {
      setError(err.message || 'Authentication failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleDemoSwitch = async (roleKey) => {
    setLoading(true);
    setError(null);
    try {
      await quickSwitchDemoRole(roleKey);
      onClose();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '18px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{ padding: '8px', background: 'rgba(6, 182, 212, 0.15)', borderRadius: '8px', color: 'var(--cyan-light)' }}>
              <Lock size={20} />
            </div>
            <div>
              <h2 style={{ fontSize: '1.25rem', color: 'var(--text-primary)' }}>
                {isRegister ? 'Register Enterprise Account' : 'Enterprise Identity Sign In'}
              </h2>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Supabase Auth & Zero-Trust Session Gateway
              </div>
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>

        {error && (
          <div style={{ padding: '10px 14px', background: 'rgba(244, 63, 94, 0.15)', border: '1px solid rgba(244, 63, 94, 0.4)', borderRadius: 'var(--radius-md)', color: '#FDA4AF', fontSize: '0.825rem', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <AlertCircle size={16} />
            <span>{error}</span>
          </div>
        )}

        {/* Tab Toggle */}
        <div style={{ display: 'flex', background: 'rgba(11, 17, 32, 0.6)', padding: '4px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)', marginBottom: '18px' }}>
          <button
            type="button"
            className="btn"
            style={{
              flex: 1,
              padding: '6px',
              fontSize: '0.825rem',
              background: !isRegister ? 'rgba(6, 182, 212, 0.2)' : 'transparent',
              color: !isRegister ? 'var(--cyan-light)' : 'var(--text-muted)'
            }}
            onClick={() => { setIsRegister(false); setError(null); }}
          >
            Sign In
          </button>
          <button
            type="button"
            className="btn"
            style={{
              flex: 1,
              padding: '6px',
              fontSize: '0.825rem',
              background: isRegister ? 'rgba(6, 182, 212, 0.2)' : 'transparent',
              color: isRegister ? 'var(--cyan-light)' : 'var(--text-muted)'
            }}
            onClick={() => { setIsRegister(true); setError(null); }}
          >
            Register
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit}>
          {isRegister && (
            <div className="form-group">
              <label className="form-label">Full Name</label>
              <input
                className="form-input"
                type="text"
                placeholder="e.g. Robert Vance"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                required
              />
            </div>
          )}

          <div className="form-group">
            <label className="form-label">Email Address</label>
            <input
              className="form-input"
              type="email"
              placeholder="e.g. user@trustvault.internal"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label className="form-label">Password (Min 8 Characters)</label>
            <input
              className="form-input"
              type="password"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>

          {isRegister && (
            <div className="form-group">
              <label className="form-label">Requested Enterprise Role</label>
              <select
                className="form-select"
                value={systemRole}
                onChange={(e) => setSystemRole(e.target.value)}
              >
                <option value="document_owner">Document Owner (Can upload & manage files)</option>
                <option value="viewer">Viewer (Read-only shared collaborator)</option>
              </select>
            </div>
          )}

          <button
            type="submit"
            className="btn btn-primary"
            style={{ width: '100%', marginTop: '12px' }}
            disabled={loading}
          >
            {loading ? 'Authenticating...' : (isRegister ? 'Create Account' : 'Sign In')}
          </button>
        </form>

        {/* 1-Click Fast Evaluator Logins */}
        <div style={{ marginTop: '22px', paddingTop: '16px', borderTop: '1px solid var(--border-subtle)' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '10px', textTransform: 'uppercase', letterSpacing: '0.04em', display: 'flex', alignItems: 'center', gap: '5px' }}>
            <ShieldCheck size={14} color="var(--cyan-light)" /> 1-Click Evaluator Personas
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '8px' }}>
            <button
              type="button"
              className="btn btn-secondary"
              style={{ padding: '7px 8px', fontSize: '0.75rem', justifyContent: 'flex-start' }}
              onClick={() => handleDemoSwitch('administrator')}
            >
              👑 Admin
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              style={{ padding: '7px 8px', fontSize: '0.75rem', justifyContent: 'flex-start' }}
              onClick={() => handleDemoSwitch('document_owner')}
            >
              📁 Document Owner
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              style={{ padding: '7px 8px', fontSize: '0.75rem', justifyContent: 'flex-start' }}
              onClick={() => handleDemoSwitch('secondary_owner')}
            >
              👥 Alice (Owner 2)
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              style={{ padding: '7px 8px', fontSize: '0.75rem', justifyContent: 'flex-start' }}
              onClick={() => handleDemoSwitch('viewer')}
            >
              👁️ Viewer (Guest)
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
