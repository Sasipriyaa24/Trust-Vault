import React from 'react';
import { ShieldCheck, ShieldAlert, FileText, Lock, Users, Upload, LogOut, CheckCircle2, User, Key } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useRouter } from '../context/RouterContext';

export default function Navbar() {
  const { user, logout, quickSwitchDemoRole } = useAuth();
  const { currentPath, navigate } = useRouter();

  const demoRoles = [
    { key: 'administrator', label: '👑 Administrator', email: 'admin@trustvault.internal' },
    { key: 'document_owner', label: '📂 Document Owner', email: 'owner@trustvault.internal' },
    { key: 'secondary_owner', label: '👥 Alice (Collaborator)', email: 'alice@trustvault.internal' },
    { key: 'viewer', label: '👁️ Viewer (Restricted)', email: 'viewer@trustvault.internal' }
  ];

  const isAdmin = user?.system_role === 'administrator';
  const canUpload = ['document_owner', 'administrator'].includes(user?.system_role);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <header style={{ position: 'sticky', top: 0, zIndex: 100, borderBottom: '1px solid var(--border-subtle)', background: 'var(--bg-surface)' }}>
      {/* Hiring Challenge Demo Switcher Ribbon */}
      <div className="persona-switcher-bar">
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: '5px', color: '#93c5fd', fontWeight: 700 }}>
            <Lock size={12} /> Evaluation Switcher:
          </span>
          <span style={{ color: '#94a3b8', fontSize: '0.72rem' }}>
            Switch active persona in 1-click to test multi-role security:
          </span>
        </div>

        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
          {demoRoles.map((item) => {
            const isActive = user && user.email === item.email;
            return (
              <button
                key={item.key}
                id={`demo-switch-${item.key}`}
                className={`persona-pill ${isActive ? 'active' : ''}`}
                onClick={() => quickSwitchDemoRole(item.key)}
                title={`Switch session to ${item.email}`}
              >
                {item.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Main Navbar Bar */}
      <div style={{ maxWidth: '1440px', margin: '0 auto', padding: '10px 20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '16px' }}>
        {/* Brand */}
        <div
          id="nav-brand"
          style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}
          onClick={() => navigate('/dashboard')}
        >
          <div style={{ width: '36px', height: '36px', borderRadius: '8px', background: 'var(--navy-dark)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#ffffff' }}>
            <ShieldCheck size={22} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ fontSize: '1.2rem', fontWeight: 800, color: 'var(--navy-dark)', letterSpacing: '-0.02em' }}>
                TrustVault
              </span>
              <span className="badge badge-blue" style={{ fontSize: '0.62rem', padding: '1px 5px' }}>
                ZERO-TRUST
              </span>
            </div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
              Enterprise Cryptographic Vault
            </div>
          </div>
        </div>

        {/* Navigation Links */}
        <nav style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
          <button
            id="nav-link-dashboard"
            className={`btn ${currentPath === '/' || currentPath === '/dashboard' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ padding: '6px 12px', fontSize: '0.8rem' }}
            onClick={() => navigate('/dashboard')}
          >
            Dashboard
          </button>

          <button
            id="nav-link-documents"
            className={`btn ${currentPath.startsWith('/documents') && currentPath !== '/documents/upload' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ padding: '6px 12px', fontSize: '0.8rem' }}
            onClick={() => navigate('/documents')}
          >
            <FileText size={14} /> My Documents
          </button>

          {canUpload && (
            <button
              id="nav-link-upload"
              className={`btn ${currentPath === '/documents/upload' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ padding: '6px 12px', fontSize: '0.8rem' }}
              onClick={() => navigate('/documents/upload')}
            >
              <Upload size={14} /> Upload
            </button>
          )}

          {isAdmin && (
            <>
              <button
                id="nav-link-audit"
                className={`btn ${currentPath === '/audit' ? 'btn-navy' : 'btn-secondary'}`}
                style={{ padding: '6px 12px', fontSize: '0.8rem' }}
                onClick={() => navigate('/audit')}
              >
                <ShieldAlert size={14} /> Audit Activity
              </button>

              <button
                id="nav-link-users"
                className={`btn ${currentPath === '/users' ? 'btn-navy' : 'btn-secondary'}`}
                style={{ padding: '6px 12px', fontSize: '0.8rem' }}
                onClick={() => navigate('/users')}
              >
                <Users size={14} /> User Governance
              </button>
            </>
          )}
        </nav>

        {/* Identity & Actions */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          {user ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '4px 10px', background: 'var(--bg-subtle)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                <div style={{ width: '28px', height: '28px', borderRadius: '50%', background: 'var(--navy-dark)', color: '#ffffff', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: '0.75rem' }}>
                  {user.full_name?.charAt(0) || 'U'}
                </div>
                <div style={{ textAlign: 'left', lineHeight: '1.2' }}>
                  <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--navy-dark)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <span>{user.full_name}</span>
                    <span className={`badge ${isAdmin ? 'badge-rose' : canUpload ? 'badge-blue' : 'badge-gray'}`} style={{ fontSize: '0.6rem', padding: '1px 4px' }}>
                      {user.system_role}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                    {user.email}
                  </div>
                </div>
                <button
                  id="btn-nav-logout"
                  onClick={handleLogout}
                  style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: '4px', marginLeft: '4px' }}
                  title="Logout"
                >
                  <LogOut size={15} />
                </button>
              </div>
            </div>
          ) : (
            <button
              id="btn-nav-signin"
              className="btn btn-primary"
              style={{ padding: '6px 14px', fontSize: '0.8rem' }}
              onClick={() => navigate('/login')}
            >
              Sign In
            </button>
          )}
        </div>
      </div>
    </header>
  );
}
