import { useEffect } from 'react';
import { useRouter } from 'next/router';

// PRA-273: canonical dashboard is /fleet-dashboard. Redirect straight there
// (previously hopped through '/', which itself redirects to /fleet-dashboard).
const DashboardRedirect = () => {
  const router = useRouter();
  useEffect(() => {
    router.replace('/fleet-dashboard');
  }, [router]);
  return null;
};

export default DashboardRedirect;
