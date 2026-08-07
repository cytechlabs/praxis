import { useEffect } from 'react';
import { useRouter } from 'next/router';

const SystemManagementRedirect = () => {
  const router = useRouter();
  useEffect(() => { router.replace('/system-management/all-systems'); }, [router]);
  return null;
};

export default SystemManagementRedirect;
