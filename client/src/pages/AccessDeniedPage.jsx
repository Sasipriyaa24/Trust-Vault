import React from 'react';
import { ShieldAlert, ArrowLeft, Users, Lock } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useRouter } from '../context/RouterContext';

export default function AccessDeniedPage({ message, requiredRole }) {
  const { user, quickSwitchDemoRole } = useAuth();
  const { navigate } = useRouter();

  return (
    <div style={{ maxWidth: '680px', margin: '60px auto', padding: '0 20px', width: '100%' }}>
      <div className="card" style={{ borderTop: '4px solid var(--rose-danger)', textAlign: 'center', padding: '40px 24px' }}>
        <div
          style={{
            width: '64px',
            height: '64px',
            borderRadius: '50%',
            background: 'var(--rose-bg)',
            border: '1px solid var(--rose-border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 16px',
            color: 'var(--rose-danger)'
          }}
        >
          <ShieldAlert size={34} />
        </div>

        <h1 style={{ fontSize: '1.5rem', color: 'var(--navy-dark)', marginBottom: '8px' }}>
          403 — Access Denied
        </h1>

        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', maxWidth: '500px', margin: '0 auto 20px' }}>
          {message || 'You do not have the required privileges to view this resource or perform this security operation.'}
        </p>

        {/* Current Identity Box */}
        <div
          style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-md)',
            padding: '14px 18px',
            maxWidth: '460px',
            margin: '0 auto 24px',
            textAlign: 'left',
            fontSize: '0.825rem'
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
            <span style={{ color: 'var(--text-muted)' }}>Current Identity:</span>
            <span style={{ fontWeight: 600, color: 'var(--navy-dark)' }}>{user?.full_name || 'Anonymous User'}</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
            <span style={{ color: 'var(--text-muted)' }}>Email:</span>
            <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>{user?.email || 'N/A'}</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span style={{ color: 'var(--text-muted)' }}>System Role:</span>
            <span className="badge badge-rose">{user?.system_role || 'none'}</span>
          </div>
          {requiredRole && (
            <div style={{ marginTop: '8px', paddingTop: '8px', borderTop: '1px solid var(--border-subtle)', color: 'var(--rose-danger)', fontSize: '0.78rem' }}>
              Required authorization: <strong>{requiredRole}</strong>
            </div>
          )}
        </div>

        {/* Zero-Trust Notice */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px', fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '24px' }}>
          <Lock size={13} />
          <span>Security Policy: Fail-Closed authorization enforced strictly on the Express backend.</span>
        </div>

        {/* Action Buttons */}
        <div style={{ display: 'flex', justifyContent: 'center', gap: '12px', flexWrap: 'wrap' }}>
          <button
            id="btn-access-denied-back"
            className="btn btn-secondary"
            onClick={() => navigate('/dashboard')}
          >
            <ArrowLeft size={15} /> Return to Dashboard
          </button>
          
          <button
            id="btn-access-denied-switch-admin"
            className="btn btn-navy"
            onClick={async () => {
              await quickSwitchDemoRole('administrator');
              navigate('/audit');
            }}
          >
            👑 Switch to Administrator
          </button>
        </div>
      </div>
    </div>
  );
}
