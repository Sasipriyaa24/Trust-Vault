import React from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { RouterProvider, useRouter } from './context/RouterContext';
import Navbar from './components/Navbar';
import LoginPage from './pages/LoginPage';
import DashboardView from './pages/DashboardView';
import DocumentsView from './pages/DocumentsView';
import UploadView from './pages/UploadView';
import DocumentDetailsView from './pages/DocumentDetailsView';
import PermissionsView from './pages/PermissionsView';
import AuditActivityView from './pages/AuditActivityView';
import UserManagementView from './pages/UserManagementView';
import AccessDeniedPage from './pages/AccessDeniedPage';
import NotFoundPage from './pages/NotFoundPage';
import { ShieldCheck, CheckCircle2, RefreshCw } from 'lucide-react';

function PageRouter() {
  const { currentPath, navigate } = useRouter();
  const { user, loading } = useAuth();

  // 1. Session verification spinner while loading initial auth token
  if (loading) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '60vh', gap: '16px' }}>
        <RefreshCw size={32} className="spinning" color="var(--blue-primary)" />
        <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem', fontWeight: 500 }}>
          Verifying security session...
        </div>
      </div>
    );
  }

  // 2. Unauthenticated Gate: If not logged in, enforce login page
  if (!user) {
    return <LoginPage onNavigate={navigate} />;
  }

  // 3. Authenticated user visiting /login gets redirected to dashboard
  if (currentPath === '/login') {
    return <DashboardView />;
  }

  // Route 2: Dashboard
  if (currentPath === '/' || currentPath === '/dashboard') {
    return <DashboardView />;
  }

  // Route 3: My Documents (List, Search, Filter)
  if (currentPath === '/documents') {
    return <DocumentsView />;
  }

  // Route 4: Upload Document
  if (currentPath === '/documents/upload') {
    return <UploadView />;
  }

  // Route 6: Sharing & Permissions for Document (:id/permissions)
  const permissionsMatch = currentPath.match(/^\/documents\/([a-zA-Z0-9_\-]+)\/permissions$/);
  if (permissionsMatch) {
    return <PermissionsView documentId={permissionsMatch[1]} />;
  }

  // Route 5: Document Details (:id)
  const documentMatch = currentPath.match(/^\/documents\/([a-zA-Z0-9_\-]+)$/);
  if (documentMatch) {
    return <DocumentDetailsView documentId={documentMatch[1]} />;
  }

  // Route 7: Audit Activity (Admin)
  if (currentPath === '/audit') {
    return <AuditActivityView />;
  }

  // Route 8: User Management & Governance (Admin)
  if (currentPath === '/users') {
    return <UserManagementView />;
  }

  // Route 9a: Explicit Access Denied
  if (currentPath === '/access-denied') {
    return <AccessDeniedPage />;
  }

  // Route 9b: 404 Not Found
  return <NotFoundPage />;
}

function MainLayout() {
  const { currentPath } = useRouter();
  const { user } = useAuth();

  // If unauthenticated or on login route, don't show internal navbar
  const showNavbar = Boolean(user && currentPath !== '/login');

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', background: 'var(--bg-app)' }}>
      {showNavbar && <Navbar />}

      <main style={{ flex: 1 }}>
        <PageRouter />
      </main>

      {/* Enterprise Security Footer */}
      <footer style={{ borderTop: '1px solid var(--border-subtle)', background: 'var(--bg-surface)', padding: '20px 24px', marginTop: 'auto' }}>
        <div style={{ maxWidth: '1440px', margin: '0 auto', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <ShieldCheck size={16} color="var(--blue-primary)" />
            <span><strong>TrustVault</strong> Enterprise Security Architecture • Zero-Trust Access Gateway</span>
          </div>

          <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap', fontSize: '0.75rem' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
              <CheckCircle2 size={12} color="var(--emerald-success)" /> No Blanket Admin Bypass
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
              <CheckCircle2 size={12} color="var(--emerald-success)" /> Authenticated Streaming Proxy
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
              <CheckCircle2 size={12} color="var(--emerald-success)" /> HMAC-SHA256 Audit Ledger
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
              <CheckCircle2 size={12} color="var(--emerald-success)" /> Strict Object ACLs
            </span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <RouterProvider>
        <MainLayout />
      </RouterProvider>
    </AuthProvider>
  );
}
