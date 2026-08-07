import { useEffect } from 'react';
import { useRouter } from 'next/router';

const MonitoringReportingRedirect = () => {
  const router = useRouter();
  useEffect(() => { router.replace('/monitoring-reporting/system-status'); }, [router]);
  return null;
};

export default MonitoringReportingRedirect;
