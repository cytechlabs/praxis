import { useEffect } from 'react';
import { useRouter } from 'next/router';

const PackageManagementRedirect = () => {
  const router = useRouter();
  useEffect(() => { router.replace('/package-management/inventory'); }, [router]);
  return null;
};

export default PackageManagementRedirect;
