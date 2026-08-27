import React from 'react';
import { useAuth } from '@/context/AuthContext';
import { ShieldX } from 'lucide-react';

/**
 * Route-to-role mapping. Routes not listed here are accessible to all authenticated users.
 * Uses prefix matching - "/settings" covers "/settings", "/settings/users", etc.
 */
const ROLE_ROUTES: { prefix: string; roles: string[] }[] = [
  // Admin only
  { prefix: '/settings', roles: ['admin'] },

  // Admin + maintainer (write operations)
  { prefix: '/credentials/add', roles: ['admin', 'maintainer'] },
  { prefix: '/credentials/edit', roles: ['admin', 'maintainer'] },
  { prefix: '/system-management/register', roles: ['admin', 'maintainer'] },
  { prefix: '/system-management/onboard', roles: ['admin', 'maintainer'] },
  { prefix: '/system-management/edit', roles: ['admin', 'maintainer'] },
  { prefix: '/system-management/vault-management', roles: ['admin', 'maintainer'] },
  { prefix: '/ssh/command-execution', roles: ['admin', 'maintainer'] },
];

function getRequiredRoles(pathname: string): string[] | null {
  for (const route of ROLE_ROUTES) {
    if (pathname === route.prefix || pathname.startsWith(route.prefix + '/')) {
      return route.roles;
    }
  }
  return null; // No restriction - any authenticated user
}

interface RoleGuardProps {
  children: React.ReactNode;
  pathname: string;
}

const Forbidden: React.FC = () => (
  <div className="flex flex-col items-center justify-center min-h-[60vh] text-center px-4">
    <ShieldX size={64} className="text-red-500 mb-6" />
    <h1 className="text-2xl font-bold text-content mb-2">Access Denied</h1>
    <p className="text-content-muted max-w-md">
      You do not have permission to access this page. Contact your administrator
      if you believe this is an error.
    </p>
  </div>
);

const RoleGuard: React.FC<RoleGuardProps> = ({ children, pathname }) => {
  const { user } = useAuth();

  if (!user) return <>{children}</>; // ContentGuard handles unauthenticated

  const requiredRoles = getRequiredRoles(pathname);
  if (!requiredRoles) return <>{children}</>; // No restriction

  const userRoles = user.roles ?? [];
  const hasAccess = requiredRoles.some((role) => userRoles.includes(role));

  if (!hasAccess) return <Forbidden />;

  return <>{children}</>;
};

export default RoleGuard;
