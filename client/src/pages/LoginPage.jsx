import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useRouter } from '../context/RouterContext';
import {
  ShieldCheck, Lock, User, Key, UserPlus, AlertCircle,
  ArrowRight, Shield, CheckCircle2, Eye, EyeOff
} from 'lucide-react';

export default function LoginPage({ onNavigate }) {
  const { login, register, quickSwitchDemoRole, error: authError, clearError } = useAuth();
  const { navigate: routerNavigate } = useRouter();
  const navigate = onNavigate || routerNavigate;
  const [mode, setMode] = useState('login'); // 'login' or 'register'
  
  // Login & Register fields
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  
  // Register-only fields
  const [fullName, setFullName] = useState('');
  const [regRole, setRegRole] = useState('document_owner');
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  const resetErrors = () => {
    setError(null);
    if (clearError) clearError();
  };

  const handleTabSwitch = (newMode) => {
    setMode(newMode);
    resetErrors();
    setSuccessMsg(null);
  };

  const demoAccounts = [
    {
      role: 'administrator',
      title: 'Security Administrator',
      email: 'admin@trustvault.internal',
      icon: '👑',
      desc: 'Audit trail inspection, hash chain verification, user governance'
    },
    {
      role: 'document_owner',
      title: 'Primary Document Owner',
      email: 'owner@trustvault.internal',
      icon: '📂',
      desc: 'Uploads, edits, deletes, and delegates document permissions'
    },
    {
      role: 'secondary_owner',
      title: 'Alice Cooper (Collaborator)',
      email: 'alice@trustvault.internal',
      icon: '👥',
      desc: 'Owner of distinct documents; recipient of delegated grants'
    },
    {
      role: 'viewer',
      title: 'External Audit Viewer',
      email: 'viewer@trustvault.internal',
      icon: '👁️',
      desc: 'Strict read-only access to explicitly delegated documents'
    }
  ];

  async function handleDemoSwitch(roleKey) {
    resetErrors();
    setSuccessMsg(null);
    setLoading(true);
    try {
      await quickSwitchDemoRole(roleKey);
      navigate('/dashboard');
    } catch (err) {
      setError(err.message || 'Failed to authenticate demo persona');
    } finally {
      setLoading(false);
    }
  }

  function handleAutofillDemo(targetEmail) {
    handleTabSwitch('login');
    setEmail(targetEmail);
    setPassword('password123');
    setSuccessMsg(`Populated credentials for ${targetEmail}`);
  }

  async function handleSubmit(e) {
    e.preventDefault();
    resetErrors();
    setSuccessMsg(null);
    setLoading(true);

    try {
      if (mode === 'login') {
        if (!email.trim() || !password) {
          throw new Error('Email and password are required.');
        }
        await login(email.trim(), password);
      } else {
        if (!fullName.trim() || !email.trim() || !password) {
          throw new Error('All fields are required for registration.');
        }
        if (password.length < 8) {
          throw new Error('Password must be at least 8 characters in length.');
        }
        await register(email.trim(), password, fullName.trim(), regRole);
      }
      navigate('/dashboard');
    } catch (err) {
      setError(err.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ maxWidth: '960px', margin: '40px auto', padding: '0 20px', width: '100%' }}>
      {/* Brand Header */}
      <div style={{ textAlign: 'center', marginBottom: '32px' }}>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
          <div style={{ width: '40px', height: '40px', borderRadius: '8px', background: 'var(--navy-dark)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#ffffff' }}>
            <ShieldCheck size={24} />
          </div>
          <h1 style={{ fontSize: '1.85rem', color: 'var(--navy-dark)' }}>TrustVault</h1>
        </div>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
          Enterprise Document Security & Cryptographic Access Control Gateway
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '24px', alignItems: 'start' }}>
        {/* Left: Interactive Demo Evaluation Personas */}
        <div className="card" style={{ borderTop: '3px solid var(--blue-primary)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
            <Shield size={18} color="var(--blue-primary)" />
            <h2 style={{ fontSize: '1.1rem' }}>Snovasys Evaluation Personas</h2>
          </div>
          <p style={{ fontSize: '0.825rem', color: 'var(--text-muted)', marginBottom: '16px' }}>
            Click any persona for <strong>instant 1-click login</strong>, or copy their credentials to test manual sign-in:
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {demoAccounts.map((persona) => (
              <div
                key={persona.role}
                style={{
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-md)',
                  padding: '10px 12px',
                  background: 'var(--bg-surface)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '8px'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: 1, minWidth: 0 }}>
                  <span style={{ fontSize: '1.3rem' }}>{persona.icon}</span>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontWeight: 600, color: 'var(--navy-dark)', fontSize: '0.85rem' }}>
                      {persona.title}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      {persona.email}
                    </div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
                      {persona.desc}
                    </div>
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', flexShrink: 0 }}>
                  <button
                    type="button"
                    id={`btn-demo-login-${persona.role}`}
                    className="btn btn-primary"
                    style={{ padding: '4px 10px', fontSize: '0.72rem', whiteSpace: 'nowrap' }}
                    onClick={() => handleDemoSwitch(persona.role)}
                    disabled={loading}
                    title="Instant 1-Click Evaluation Login"
                  >
                    1-Click In <ArrowRight size={12} style={{ marginLeft: '4px' }} />
                  </button>
                  <button
                    type="button"
                    id={`btn-demo-fill-${persona.role}`}
                    className="btn btn-secondary"
                    style={{ padding: '3px 8px', fontSize: '0.68rem', whiteSpace: 'nowrap' }}
                    onClick={() => handleAutofillDemo(persona.email)}
                    title="Fill into Sign In form to test password authentication"
                  >
                    Autofill Form
                  </button>
                </div>
              </div>
            ))}
          </div>

          <div style={{ marginTop: '16px', padding: '10px 12px', background: 'var(--bg-subtle)', borderRadius: 'var(--radius-md)', fontSize: '0.75rem', color: 'var(--text-muted)', lineHeight: '1.4' }}>
            <div>🔑 <strong>Demo Password:</strong> <code>password123</code> (valid for all 4 demo accounts)</div>
            <div style={{ marginTop: '4px' }}>🔒 <strong>Zero-Trust Architecture:</strong> Each persona is strictly isolated at the server level. Administrators cannot bypass private document authorization.</div>
          </div>
        </div>

        {/* Right: Traditional Credentials Form */}
        <div className="card" style={{ borderTop: '3px solid var(--navy-dark)' }}>
          <div style={{ display: 'flex', borderBottom: '1px solid var(--border-subtle)', marginBottom: '20px' }}>
            <button
              type="button"
              id="tab-btn-login"
              className="btn"
              style={{
                flex: 1,
                borderRadius: '0',
                borderBottom: mode === 'login' ? '2px solid var(--blue-primary)' : '2px solid transparent',
                color: mode === 'login' ? 'var(--blue-primary)' : 'var(--text-muted)',
                fontWeight: mode === 'login' ? 700 : 500
              }}
              onClick={() => handleTabSwitch('login')}
            >
              Sign In
            </button>
            <button
              type="button"
              id="tab-btn-register"
              className="btn"
              style={{
                flex: 1,
                borderRadius: '0',
                borderBottom: mode === 'register' ? '2px solid var(--blue-primary)' : '2px solid transparent',
                color: mode === 'register' ? 'var(--blue-primary)' : 'var(--text-muted)',
                fontWeight: mode === 'register' ? 700 : 500
              }}
              onClick={() => handleTabSwitch('register')}
            >
              Register New Account
            </button>
          </div>

          {(error || authError) && (
            <div className="alert alert-danger" style={{ marginBottom: '16px' }}>
              <AlertCircle size={16} style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>{error || authError}</div>
            </div>
          )}

          {successMsg && !error && (
            <div className="alert alert-success" style={{ marginBottom: '16px' }}>
              <CheckCircle2 size={16} style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>{successMsg}</div>
            </div>
          )}

          <form onSubmit={handleSubmit}>
            {mode === 'register' && (
              <>
                <div className="form-group">
                  <label className="form-label" htmlFor="register-full-name">Full Name *</label>
                  <input
                    id="register-full-name"
                    name="fullName"
                    className="form-input"
                    type="text"
                    required
                    placeholder="e.g. Jane Doe"
                    value={fullName}
                    onChange={(e) => { setFullName(e.target.value); resetErrors(); }}
                    autoComplete="name"
                  />
                </div>

                <div className="form-group">
                  <label className="form-label" htmlFor="register-role">System Role *</label>
                  <select
                    id="register-role"
                    name="systemRole"
                    className="form-select"
                    value={regRole}
                    onChange={(e) => setRegRole(e.target.value)}
                  >
                    <option value="document_owner">Document Owner (Can upload and manage documents)</option>
                    <option value="viewer">Viewer (Can only read documents shared with them)</option>
                  </select>
                  <div className="form-hint">
                    Administrator roles cannot be self-assigned and must be provisioned by an administrator.
                  </div>
                </div>
              </>
            )}

            <div className="form-group">
              <label className="form-label" htmlFor="auth-email-input">Email Address *</label>
              <input
                id="auth-email-input"
                name="email"
                className="form-input"
                type="email"
                required
                placeholder="name@trustvault.internal"
                value={email}
                onChange={(e) => { setEmail(e.target.value); resetErrors(); }}
                autoComplete="email"
              />
            </div>

            <div className="form-group">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <label className="form-label" htmlFor="auth-password-input">Password *</label>
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '0.72rem', display: 'flex', alignItems: 'center', gap: '4px', padding: 0 }}
                >
                  {showPassword ? <EyeOff size={13} /> : <Eye size={13} />}
                  <span>{showPassword ? 'Hide' : 'Show'}</span>
                </button>
              </div>
              <input
                id="auth-password-input"
                name="password"
                className="form-input"
                type={showPassword ? 'text' : 'password'}
                required
                placeholder="••••••••••••"
                value={password}
                onChange={(e) => { setPassword(e.target.value); resetErrors(); }}
                autoComplete={mode === 'register' ? 'new-password' : 'current-password'}
              />
              <div className="form-hint">Minimum 8 characters. Passwords are never logged in audit trails.</div>
            </div>

            <button
              id="btn-auth-submit"
              type="submit"
              className="btn btn-primary"
              style={{ width: '100%', marginTop: '12px', padding: '10px' }}
              disabled={loading}
            >
              {loading
                ? 'Authenticating...'
                : mode === 'login'
                ? 'Sign In to TrustVault'
                : 'Complete Registration'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
