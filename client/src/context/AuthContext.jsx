import React, { createContext, useContext, useState, useEffect } from 'react';
import { apiRequest, setAuthToken, getAuthToken } from '../services/api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    async function initAuth() {
      const token = getAuthToken();
      if (token) {
        try {
          const res = await apiRequest('/auth/me');
          setUser(res.user);
        } catch (err) {
          console.warn('Session expired or invalid. Clearing token.');
          setAuthToken(null);
          setUser(null);
        }
      } else {
        setUser(null);
      }
      setLoading(false);
    }

    initAuth();

    const handleExpired = () => {
      setUser(null);
      setAuthToken(null);
    };
    window.addEventListener('auth_token_expired', handleExpired);
    return () => window.removeEventListener('auth_token_expired', handleExpired);
  }, []);

  async function login(email, password) {
    setError(null);
    try {
      const res = await apiRequest('/auth/login', {
        method: 'POST',
        body: { email, password }
      });
      setAuthToken(res.token);
      setUser(res.user);
      return res.user;
    } catch (err) {
      setError(err.message);
      throw err;
    }
  }

  async function register(email, password, full_name, system_role) {
    setError(null);
    try {
      const res = await apiRequest('/auth/register', {
        method: 'POST',
        body: { email, password, full_name, system_role }
      });
      setAuthToken(res.token);
      setUser(res.user);
      return res.user;
    } catch (err) {
      setError(err.message);
      throw err;
    }
  }

  async function quickSwitchDemoRole(role) {
    setError(null);
    try {
      const res = await apiRequest('/auth/demo-switch', {
        method: 'POST',
        body: { role }
      });
      setAuthToken(res.token);
      setUser(res.user);
      return res.user;
    } catch (err) {
      setError(err.message);
      throw err;
    }
  }

  const clearError = () => setError(null);

  function logout() {
    setAuthToken(null);
    setUser(null);
    setError(null);
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        error,
        clearError,
        login,
        register,
        logout,
        quickSwitchDemoRole
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
