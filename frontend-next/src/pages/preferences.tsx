import { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import MainLayout from '../components/MainLayout';
import { PageHeader, Tabs } from '@/components/ui';
import UserDetailsTab from '../components/profile/UserDetailsTab';
import NotificationPreferencesTab from '../components/profile/NotificationPreferencesTab';
import SecurityTab from '../components/profile/SecurityTab';
import Head from 'next/head';

const PreferencesPage = () => {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState('user-details');

  const tabs = [
    { id: 'user-details', label: 'User Details' },
    { id: 'security', label: 'Security' },
    { id: 'notification-preferences', label: 'Notification Preferences' },
  ];

  if (!user) {
    return null;
  }

  return (
    <MainLayout>
        <Head>
          <title>Preferences | Praxis</title>
        </Head>
        <PageHeader title="Preferences" />

        <div className="mb-6">
          <Tabs tabs={tabs} active={activeTab} onChange={setActiveTab} />
        </div>

        {/* Tab Content */}
        <div>
          {activeTab === 'user-details' && <UserDetailsTab user={user} />}
          {activeTab === 'security' && <SecurityTab />}
          {activeTab === 'notification-preferences' && <NotificationPreferencesTab />}
        </div>
    </MainLayout>
  );
};

export default PreferencesPage;
