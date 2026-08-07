import { useEffect, useState } from 'react';
import { useRouter } from 'next/router';
import { toast } from 'sonner';
import { useAuth } from '../context/AuthContext';
import MainLayout from '../components/MainLayout';
import { PageHeader } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';
import SettingsNav, { buildSettingsGroups } from '../components/settings/SettingsNav';
import UserManagementTab from '../components/settings/UserManagementTab';
import AuthLogsTab from '../components/settings/AuthLogsTab';
import AlertConfigTab from '../components/settings/AlertConfigTab';
import ConnectionSettingsTab from '../components/settings/ConnectionSettingsTab';
import SSHIdentityTab from '../components/settings/SSHIdentityTab';
import IdentityProviderTab from '../components/settings/IdentityProviderTab';
import GeneralSettingsTab from '../components/settings/GeneralSettingsTab';
import FleetAccessTab from '../components/settings/FleetAccessTab';
import AuditExportTab from '../components/settings/AuditExportTab';
import ActivationTokensTab from '../components/settings/ActivationTokensTab';
import LicenseTab from '../components/settings/LicenseTab';
import SupportDiagnosticsTab from '../components/settings/SupportDiagnosticsTab';
import { fetchUsers, changeUserPassword, toggleUserActive, updateUserRoles, createUser, deleteUser } from '../services/userService';
import Head from 'next/head';

interface User {
  id: number;
  username: string;
  email: string;
  is_active: boolean;
  roles: string[];
}

const SettingsPage = () => {
  const router = useRouter();
  const { user, isAdmin, isAuditor } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('general');

  // Grouped, permission-gated section list for the vertical Settings nav.
  // Auth Logs is admin/auditor-gated; Activation Tokens and Support /
  // Diagnostics are admin-only - the same server-side checks as before (PRA-257).
  const groups = buildSettingsGroups(isAdmin, isAuditor);
  const visibleIds = groups.flatMap((g) => g.items.map((i) => i.id));

  // Make the active section bookmarkable via ?tab=<id>. We read once the
  // router is ready (Next.js populates query asynchronously on first
  // render) and accept only ids that exist in the visible section list,
  // so a stale link can't park us on a hidden section.
  useEffect(() => {
    if (!router.isReady) return;
    const q = router.query.tab;
    const requested = Array.isArray(q) ? q[0] : q;
    if (requested && visibleIds.includes(requested) && requested !== activeTab) {
      setActiveTab(requested);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [router.isReady, router.query.tab, isAdmin, isAuditor]);

  const onTabChange = (id: string) => {
    setActiveTab(id);
    // Shallow replace so we don't refetch data or trigger getServerSideProps;
    // pushing 'general' as a bare URL keeps the default tab clean.
    const next = id === 'general' ? { pathname: '/settings' } : {
      pathname: '/settings',
      query: { tab: id },
    };
    void router.replace(next, undefined, { shallow: true });
  };

  useEffect(() => {
    const loadUsers = async () => {
      try {
        if (user) {
          const data = await fetchUsers();
          setUsers(data);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch users');
      } finally {
        setLoading(false);
      }
    };

    loadUsers();
  }, [user]);

  const handlePasswordChange = async (userId: number, username: string, newPassword: string, confirmPassword: string) => {
    if (!user) return;

    try {
      await changeUserPassword(userId, {
        newPassword,
        confirmPassword,
      });


      toast.success('Password changed');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to change password');
      throw err;
    }
  };

  const handleToggleActive = async (targetUser: User) => {
    if (!user) return;

    try {
      const updatedUser = await toggleUserActive(targetUser.id);
      setUsers(users.map(u => u.id === targetUser.id ? updatedUser : u));

      toast.success('User status toggled');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to toggle user status');
      toast.error(err instanceof Error ? err.message : 'Failed to toggle user status');
    }
  };

  const handleRoleUpdate = async (userId: number, username: string, roles: string[]) => {
    if (!user) return;

    try {
      const updatedUser = await updateUserRoles(userId, roles);
      setUsers(users.map(u => u.id === userId ? updatedUser : u));

      toast.success('Roles updated');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to update roles');
      throw err;
    }
  };

  const handleCreateUser = async (userData: { username: string; email: string; password: string }, onSuccess: () => void) => {
    if (!user) return;

    try {
      const newUser = await createUser(userData);
      setUsers([...users, newUser]);

      toast.success('User created');
      onSuccess(); // Call the success callback to close the dialog
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to create user');
      throw err;
    }
  };

  const handleDeleteUser = async (userId: number, _username: string) => {
    if (!user) return;

    try {
      await deleteUser(userId);
      setUsers(users.filter(u => u.id !== userId));

      toast.success('User deleted');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to delete user');
      throw err;
    }
  };

  if (!isAdmin) {
    return (
      <MainLayout>
        <Head>
          <title>Settings | Praxis</title>
        </Head>
        <div className="text-center">
          <h1 className="text-2xl font-semibold text-gray-200">Access Denied</h1>
          <p className="text-gray-400 mt-2">You do not have permission to access this page.</p>
        </div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
        <PageHeader title="Settings" actions={<HelpLink slug="settings" />} />

        <div className="flex flex-col gap-6 lg:flex-row lg:gap-8">
          <SettingsNav groups={groups} active={activeTab} onSelect={onTabChange} />

          {/* Section content */}
          <div className="min-w-0 flex-1">
          {activeTab === 'general' && <GeneralSettingsTab />}
          {activeTab === 'user-management' && (
            <UserManagementTab
              users={users}
              loading={loading}
              error={error}
              onToggleActive={handleToggleActive}
              onPasswordChange={handlePasswordChange}
              onRoleUpdate={handleRoleUpdate}
              onCreateUser={handleCreateUser}
              onDeleteUser={handleDeleteUser}
            />
          )}
          {activeTab === 'auth-logs' && <AuthLogsTab />}
          {activeTab === 'alert-config' && <AlertConfigTab />}
          {activeTab === 'connection-settings' && <ConnectionSettingsTab />}
          {activeTab === 'ssh-identity' && <SSHIdentityTab />}
          {activeTab === 'fleet-access' && <FleetAccessTab />}
          {activeTab === 'activation-tokens' && <ActivationTokensTab />}
          {activeTab === 'audit-export' && <AuditExportTab />}
          {activeTab === 'identity-provider' && <IdentityProviderTab />}
          {activeTab === 'license' && <LicenseTab />}
          {activeTab === 'diagnostics' && <SupportDiagnosticsTab />}
          </div>
        </div>
    </MainLayout>
  );
};

export default SettingsPage;
