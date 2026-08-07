import { useEffect } from 'react';
import { useRouter } from 'next/router';

const IndexRedirect = () => {
  const router = useRouter();
  useEffect(() => {
    router.replace('/fleet-dashboard');
  }, [router]);
  return null;
};

export default IndexRedirect;
