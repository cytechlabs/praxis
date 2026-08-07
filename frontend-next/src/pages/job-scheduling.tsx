import { useEffect } from 'react';
import { useRouter } from 'next/router';

const JobSchedulingRedirect = () => {
  const router = useRouter();
  useEffect(() => { router.replace('/job-scheduling/scheduled-jobs'); }, [router]);
  return null;
};

export default JobSchedulingRedirect;
