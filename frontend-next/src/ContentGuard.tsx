import React, { useEffect } from 'react';
import { useRouter } from 'next/router';
import { useAuth } from './context/AuthContext';

interface ContentGuardProps {
  children: React.ReactNode;
}

const publicPaths = ['/login', '/register', '/forgot-password'];

const ContentGuard: React.FC<ContentGuardProps> = ({ children }) => {
  const { user, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (loading) return;

    const isPublicPath = publicPaths.includes(router.pathname);
    const returnUrl = encodeURIComponent(router.asPath);

    if (!user && !isPublicPath) {
      router.push(`/login?returnUrl=${returnUrl}`);
    } else if (user && isPublicPath && router.pathname !== '/login') {
      router.push('/');
    }
  }, [user, loading, router.pathname, router.asPath, router]);

  if (loading || (!user && !publicPaths.includes(router.pathname))) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="h-32 w-32 animate-spin rounded-full border-b-2 border-t-2 border-red-600"></div>
      </div>
    );
  }

  return <>{children}</>;
};

export default ContentGuard;
