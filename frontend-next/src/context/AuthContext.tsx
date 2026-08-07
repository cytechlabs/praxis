import { createContext, useContext, useEffect, useState, useCallback, useRef } from 'react';
import type { ReactNode } from 'react';
import { formatApiError } from '../utils/api';

export interface AuthUser {
  id: number;
  username: string;
  email: string;
  is_active: boolean;
  roles: string[];
}

interface AuthContextType {
  user: AuthUser | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<{ ok: boolean; error?: string }>;
  logout: () => Promise<void>;
  refresh: () => Promise<boolean>;
  isAdmin: boolean;
  isMaintainer: boolean;
  isAuditor: boolean;
  canWrite: boolean;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);
  const refreshPromise = useRef<Promise<boolean> | null>(null);

  const tryRefresh = useCallback(async (): Promise<boolean> => {
    if (refreshPromise.current) {
      return refreshPromise.current;
    }
    refreshPromise.current = (async () => {
      try {
        const res = await fetch('/api/auth/refresh', { method: 'POST' });
        return res.ok;
      } catch {
        return false;
      } finally {
        refreshPromise.current = null;
      }
    })();
    return refreshPromise.current;
  }, []);

  const fetchUser = useCallback(async () => {
    try {
      let res = await fetch('/api/auth/me');
      if (res.status === 401) {
        const refreshed = await tryRefresh();
        if (refreshed) {
          res = await fetch('/api/auth/me');
        }
      }
      if (res.ok) {
        setUser(await res.json());
      } else {
        setUser(null);
      }
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, [tryRefresh]);

  useEffect(() => {
    fetchUser();
  }, [fetchUser]);

  const login = useCallback(async (username: string, password: string) => {
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        return { ok: false, error: formatApiError(data, 'Login failed') };
      }

      const userData = await res.json();
      setUser(userData);
      return { ok: true };
    } catch {
      return { ok: false, error: 'Network error' };
    }
  }, []);

  const logout = useCallback(async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
    } catch {
      // Clear state even if request fails
    }
    setUser(null);
  }, []);

  const refresh = useCallback(async () => {
    const ok = await tryRefresh();
    if (ok) {
      await fetchUser();
    } else {
      setUser(null);
    }
    return ok;
  }, [tryRefresh, fetchUser]);

  const roles = user?.roles ?? [];
  const isAdmin = roles.includes('admin');
  const isMaintainer = roles.includes('maintainer');
  const isAuditor = roles.includes('auditor');
  const canWrite = isAdmin || isMaintainer;

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, refresh, isAdmin, isMaintainer, isAuditor, canWrite }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
