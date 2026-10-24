import React from 'react';
import { FileQuestion, ArrowLeft, Home } from 'lucide-react';
import { useRouter } from '../context/RouterContext';

export default function NotFoundPage() {
  const { navigate } = useRouter();

  return (
    <div style={{ maxWidth: '600px', margin: '80px auto', padding: '0 20px', width: '100%', textAlign: 'center' }}>
      <div className="card" style={{ padding: '40px 24px', borderTop: '4px solid var(--border-medium)' }}>
        <div
          style={{
            width: '60px',
            height: '60px',
            borderRadius: '50%',
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-medium)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 16px',
            color: 'var(--text-muted)'
          }}
        >
          <FileQuestion size={32} />
        </div>

        <h1 style={{ fontSize: '1.5rem', color: 'var(--navy-dark)', marginBottom: '8px' }}>
          404 — Page Not Found
        </h1>

        <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginBottom: '24px' }}>
          The requested page or resource could not be found. It may have been moved, deleted, or does not exist.
        </p>

        <div style={{ display: 'flex', justifyContent: 'center', gap: '12px' }}>
          <button
            id="btn-not-found-dashboard"
            className="btn btn-primary"
            onClick={() => navigate('/dashboard')}
          >
            <Home size={15} /> Return to Dashboard
          </button>
        </div>
      </div>
    </div>
  );
}
