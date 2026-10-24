// API Client Service with automatic token injection and error handling

const rawBase = import.meta.env.VITE_API_URL || '';
const API_BASE = rawBase ? `${rawBase.replace(/\/$/, '')}/api` : '/api';

/**
 * Helper to get active JWT from localStorage
 */
export function getAuthToken() {
  return localStorage.getItem('trustvault_token');
}

/**
 * Helper to save active JWT
 */
export function setAuthToken(token) {
  if (token) {
    localStorage.setItem('trustvault_token', token);
  } else {
    localStorage.removeItem('trustvault_token');
  }
}

/**
 * Universal JSON Fetch Wrapper
 */
export async function apiRequest(endpoint, { method = 'GET', body = null, headers = {} } = {}) {
  const token = getAuthToken();
  const reqHeaders = {
    ...headers
  };

  if (token) {
    reqHeaders['Authorization'] = `Bearer ${token}`;
  }

  const options = {
    method,
    headers: reqHeaders
  };

  if (body && !(body instanceof FormData)) {
    reqHeaders['Content-Type'] = 'application/json';
    options.body = JSON.stringify(body);
  } else if (body instanceof FormData) {
    // Let browser set Content-Type with boundary for multipart/form-data
    options.body = body;
  }

  let res;
  try {
    res = await fetch(`${API_BASE}${endpoint}`, options);
  } catch (netErr) {
    throw new Error('Unable to connect to TrustVault Security Gateway (port 5000). Please ensure the backend server is running (`npm run server`).');
  }

  // Handle unauthorized or deactivated account
  if (res.status === 401) {
    const errorData = await res.json().catch(() => ({}));
    // Clear token on authentication failure so stale tokens don't lock the UI
    setAuthToken(null);
    window.dispatchEvent(new Event('auth_token_expired'));
    throw new Error(errorData.error || 'Authentication required. Please sign in.');
  }

  // Handle 403 Forbidden, 400 Bad Request, or Gateway Errors
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    let errorMsg = errorData.error;
    if (!errorMsg) {
      if (res.status === 502 || res.status === 504 || (res.status === 500 && endpoint.startsWith('/auth/'))) {
        errorMsg = 'Backend Security Gateway is unreachable on port 5000. Please ensure the backend server is running (`npm run server`).';
      } else {
        errorMsg = `Request failed with status ${res.status}`;
      }
    }
    const err = new Error(errorMsg);
    err.status = res.status;
    err.code = errorData.code;
    throw err;
  }

  return res.json();
}

/**
 * Downloads a document as a blob through the secure streaming proxy
 */
export async function downloadDocumentStream(documentId, filename) {
  const token = getAuthToken();
  const res = await fetch(`${API_BASE}/documents/${documentId}/download`, {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.error || 'Failed to download document');
  }

  const blob = await res.blob();
  const downloadUrl = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = downloadUrl;
  a.download = filename || 'document.pdf';
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(downloadUrl);
  a.remove();
}
