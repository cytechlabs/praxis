import { useEffect } from 'react';
import type { AppProps } from 'next/app';
import { useRouter } from 'next/router';
import { Inter } from 'next/font/google';
import { Toaster } from 'sonner';
import NProgress from 'nprogress';
import { AuthProvider } from '../context/AuthContext';
import { EntitlementsProvider } from '../context/EntitlementsContext';
import ContentGuard from '../ContentGuard';
import RoleGuard from '../components/RoleGuard';
import EntitlementGuard from '../components/EntitlementGuard';
import ErrorBoundary from '../components/ErrorBoundary';
import ViewportGate from '../components/layout/ViewportGate';
import { TimestampPreferencesProvider } from '../context/TimestampPreferencesContext';
import '../app/globals.css';

NProgress.configure({ showSpinner: false, speed: 300, minimum: 0.2 });

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-inter',
});

export default function App({ Component, pageProps }: AppProps) {
  const router = useRouter();

  useEffect(() => {
    const handleStart = () => NProgress.start();
    const handleDone = () => NProgress.done();

    router.events.on('routeChangeStart', handleStart);
    router.events.on('routeChangeComplete', handleDone);
    router.events.on('routeChangeError', handleDone);

    return () => {
      router.events.off('routeChangeStart', handleStart);
      router.events.off('routeChangeComplete', handleDone);
      router.events.off('routeChangeError', handleDone);
    };
  }, [router]);

  return (
    <div className={`${inter.variable} font-sans`}>
      {/* PRA-272: enforce the desktop support boundary around the entire app. */}
      <ViewportGate>
        <ErrorBoundary>
          <AuthProvider>
            <TimestampPreferencesProvider>
              <EntitlementsProvider>
                <ContentGuard>
                  <RoleGuard pathname={router.pathname}>
                    <EntitlementGuard pathname={router.pathname}>
                      <ErrorBoundary>
                        <Component {...pageProps} />
                      </ErrorBoundary>
                    </EntitlementGuard>
                  </RoleGuard>
                </ContentGuard>
                <Toaster position="bottom-right" theme="dark" richColors />
              </EntitlementsProvider>
            </TimestampPreferencesProvider>
          </AuthProvider>
        </ErrorBoundary>
      </ViewportGate>
    </div>
  );
}
