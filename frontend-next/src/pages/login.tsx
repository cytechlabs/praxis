import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/router';
import { toast } from 'sonner';
import { useAuth } from '../context/AuthContext';
import { safeLoginReturnUrl } from '../utils/redirect';
import { Button } from '@/components/ui';
import { BrandWordmark } from '@/components/ui/BrandLogo';
import BrandedLoadingScreen from '@/components/layout/BrandedLoadingScreen';
import { Shield } from 'lucide-react';
import Head from 'next/head';

interface OIDCStatus {
  enabled: boolean;
  provider_name?: string;
}

const LoginPage: React.FC = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [ssoStatus, setSsoStatus] = useState<OIDCStatus | null>(null);
  const [ssoLoading, setSsoLoading] = useState(false);
  const router = useRouter();
  const { user, loading, login } = useAuth();

  useEffect(() => {
    if (!loading && user) {
      // PRA-250: returnUrl is attacker-controlled query data - sanitize it to a
      // safe same-origin path before redirecting, or fall back to "/".
      const returnUrl = safeLoginReturnUrl(router.query.returnUrl);
      router.push(returnUrl);
    }
  }, [loading, user, router]);

  // Check if SSO is available
  useEffect(() => {
    const checkSSO = async () => {
      try {
        const res = await fetch('/api/backend/auth/oidc/status');
        if (res.ok) {
          setSsoStatus(await res.json());
        }
      } catch {
        // SSO check is non-critical
      }
    };
    checkSSO();
  }, []);

  // Surface a non-sensitive SSO error returned by the backend callback.
  useEffect(() => {
    if (router.isReady && router.query.oidc_error) {
      setError('SSO login failed. Please try again or contact an administrator.');
    }
  }, [router.isReady, router.query.oidc_error]);

  // Complete the OIDC flow. The backend callback redirects here with the
  // tokens in the URL *fragment* (#oidc_token=...&oidc_refresh=...), which is
  // never sent to servers / logged. We exchange them for httpOnly cookies via
  // the oidc-complete API route, then strip the fragment from the URL.
  useEffect(() => {
    const handleOIDCCallback = async () => {
      if (typeof window === 'undefined' || !window.location.hash) return;
      const params = new URLSearchParams(window.location.hash.replace(/^#/, ''));
      const oidc_token = params.get('oidc_token');
      const oidc_refresh = params.get('oidc_refresh');
      if (!oidc_token || !oidc_refresh) return;

      // Remove tokens from the address bar immediately.
      window.history.replaceState(null, '', window.location.pathname + window.location.search);

      try {
        const res = await fetch('/api/auth/oidc-complete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            access_token: oidc_token,
            refresh_token: oidc_refresh,
          }),
        });
        if (res.ok) {
          window.location.href = '/';
        } else {
          setError('SSO login failed');
        }
      } catch {
        setError('SSO login failed');
      }
    };
    handleOIDCCallback();
  }, []);

  if (loading) {
    // PRA-272: branded, full-viewport auth transition - never a bare "Loading..."
    // or an unexplained blank/black screen while auth resolves.
    return (
      <>
        <Head>
          <title>Login | Praxis</title>
        </Head>
        <BrandedLoadingScreen label="Signing in" />
      </>
    );
  }

  const handleLogin = async (event: React.FormEvent) => {
    event.preventDefault();
    setError('');

    const result = await login(username, password);
    if (!result.ok) {
      const errorMsg = result.error || 'Login failed. Please check your credentials and try again.';
      setError(errorMsg);
      setPassword('');
      toast.error(errorMsg);
    }
  };

  const handleSSO = async () => {
    setSsoLoading(true);
    try {
      const res = await fetch('/api/backend/auth/oidc/login');
      if (res.ok) {
        const data = await res.json();
        window.location.href = data.auth_url;
      } else {
        toast.error('Failed to initiate SSO login');
      }
    } catch {
      toast.error('Failed to initiate SSO login');
    } finally {
      setSsoLoading(false);
    }
  };

  return (
    <>
      <Head><title>Login | Praxis</title></Head>
      <div className="min-h-screen flex items-center justify-center bg-surface p-4 relative overflow-hidden">
        {/* Subtle background glow */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-red-950/20 rounded-full blur-[120px] pointer-events-none" />

        <div className="w-full max-w-sm relative z-10">
          {/* PRA-272: official brand wordmark (replaces the hand-rolled text mark). */}
          <div className="mb-8 flex flex-col items-center text-center">
            <BrandWordmark height={34} />
            <p className="mt-2 text-xs uppercase tracking-widest text-content-subtle">
              Fleet Operations Platform
            </p>
          </div>

          <div className="bg-surface-raised border border-border/60 rounded-xl p-8 shadow-2xl">
            {error && (
              <div className="mb-4 px-3 py-2 bg-red-500/10 border border-red-500/20 rounded-md text-red-400 text-sm text-center">
                {error}
              </div>
            )}

            {ssoStatus?.enabled && (
              <>
                <Button
                  variant="outline"
                  size="lg"
                  onClick={handleSSO}
                  disabled={ssoLoading}
                  loading={ssoLoading}
                  icon={<Shield className="w-4 h-4" />}
                  className="w-full mb-4"
                >
                  {ssoLoading ? 'Redirecting...' : `Sign in with ${ssoStatus.provider_name || 'SSO'}`}
                </Button>
                <div className="flex items-center gap-3 mb-4">
                  <div className="flex-1 h-px bg-surface-overlay" />
                  <span className="text-xs text-content-subtle">or</span>
                  <div className="flex-1 h-px bg-surface-overlay" />
                </div>
              </>
            )}

            <form onSubmit={handleLogin} className="space-y-4">
              <div>
                <label htmlFor="username" className="block text-xs font-medium text-content-muted uppercase tracking-wider mb-1.5">Username</label>
                <input
                  type="text"
                  id="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                  className="w-full px-3 py-2.5 bg-surface-sunken border border-border/60 rounded-md text-content text-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong transition-colors"
                />
              </div>
              <div>
                <label htmlFor="password" className="block text-xs font-medium text-content-muted uppercase tracking-wider mb-1.5">Password</label>
                <input
                  type="password"
                  id="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  className="w-full px-3 py-2.5 bg-surface-sunken border border-border/60 rounded-md text-content text-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong transition-colors"
                />
              </div>
              <Button
                type="submit"
                variant="primary"
                size="lg"
                className="w-full mt-2"
              >
                Sign In
              </Button>
            </form>
          </div>
        </div>
      </div>
    </>
  );
};

export default LoginPage;
