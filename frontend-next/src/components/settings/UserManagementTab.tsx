import { useState } from 'react';
import AdminPasswordChangeDialog from '../AdminPasswordChangeDialog';
import RoleSelectionDialog from '../RoleSelectionDialog';
import CreateUserDialog from '../CreateUserDialog';
import DeleteConfirmationDialog from '../DeleteConfirmationDialog';
import Pagination from '../Pagination';

interface User {
  id: number;
  username: string;
  email: string;
  is_active: boolean;
  roles: string[];
}

interface UserManagementTabProps {
  users: User[];
  loading: boolean;
  error: string;
  onToggleActive: (user: User) => Promise<void>;
  onPasswordChange: (userId: number, username: string, newPassword: string, confirmPassword: string) => Promise<void>;
  onRoleUpdate: (userId: number, username: string, roles: string[]) => Promise<void>;
  onCreateUser: (userData: { username: string; email: string; password: string }, onSuccess: () => void) => Promise<void>;
  onDeleteUser: (userId: number, username: string) => Promise<void>;
}

const UserManagementTab = ({
  users,
  loading,
  error,
  onToggleActive,
  onPasswordChange,
  onRoleUpdate,
  onCreateUser,
  onDeleteUser,
}: UserManagementTabProps) => {
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [isPasswordDialogOpen, setIsPasswordDialogOpen] = useState(false);
  const [isRoleDialogOpen, setIsRoleDialogOpen] = useState(false);
  const [isCreateUserDialogOpen, setIsCreateUserDialogOpen] = useState(false);
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false);
  const [pageOffset, setPageOffset] = useState(0);
  const pageLimit = 25;
  const paginatedUsers = users.slice(pageOffset, pageOffset + pageLimit);

  const handlePasswordChange = async (newPassword: string, confirmPassword: string) => {
    if (selectedUser) {
      await onPasswordChange(selectedUser.id, selectedUser.username, newPassword, confirmPassword);
      setIsPasswordDialogOpen(false);
      setSelectedUser(null);
    }
  };

  const handleRoleUpdate = async (roles: string[]) => {
    if (selectedUser) {
      await onRoleUpdate(selectedUser.id, selectedUser.username, roles);
      setIsRoleDialogOpen(false);
      setSelectedUser(null);
    }
  };

  const handleDeleteUser = async () => {
    if (selectedUser) {
      await onDeleteUser(selectedUser.id, selectedUser.username);
      setIsDeleteDialogOpen(false);
      setSelectedUser(null);
    }
  };

  const handleCreateUser = async (userData: { username: string; email: string; password: string }) => {
    await onCreateUser(userData, () => setIsCreateUserDialogOpen(false));
  };

  return (
    <div className="mb-8">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl">User Management</h2>
        <button
          onClick={() => setIsCreateUserDialogOpen(true)}
          className="px-4 py-2 bg-red-600 text-white text-sm font-medium rounded hover:bg-red-700"
        >
          Create User
        </button>
      </div>

      {loading && <div>Loading users...</div>}

      {error && (
        <div className="text-red-500 mb-4">{error}</div>
      )}

      {!loading && !error && (
        <div className="overflow-x-auto">
          <table className="min-w-full bg-[#0c0c0f] border border-gray-800/60 rounded">
            <thead>
              <tr className="border-b border-gray-800/60">
                <th scope="col" className="px-6 py-3 text-left text-sm font-medium text-gray-400">ID</th>
                <th scope="col" className="px-6 py-3 text-left text-sm font-medium text-gray-400">Username</th>
                <th scope="col" className="px-6 py-3 text-left text-sm font-medium text-gray-400">Email</th>
                <th scope="col" className="px-6 py-3 text-left text-sm font-medium text-gray-400">Status</th>
                <th scope="col" className="px-6 py-3 text-left text-sm font-medium text-gray-400">Roles</th>
                <th scope="col" className="px-6 py-3 text-left text-sm font-medium text-gray-400">Actions</th>
              </tr>
            </thead>
            <tbody>
              {paginatedUsers.map((user) => (
                <tr key={user.id} className="border-b border-gray-800/60">
                  <td className="px-6 py-4 text-sm text-gray-300">{user.id}</td>
                  <td className="px-6 py-4 text-sm text-gray-300">{user.username}</td>
                  <td className="px-6 py-4 text-sm text-gray-300">{user.email}</td>
                  <td className="px-6 py-4 text-sm">
                    <button
                      onClick={() => onToggleActive(user)}
                      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium cursor-pointer transition-colors ${
                        user.is_active
                          ? 'bg-emerald-500/15 text-emerald-400 hover:bg-emerald-500/25'
                          : 'bg-red-500/15 text-red-400 hover:bg-red-500/25'
                      }`}
                    >
                      {user.is_active ? 'Active' : 'Inactive'}
                    </button>
                  </td>
                  <td className="px-6 py-4 text-sm">
                    <button
                      onClick={() => {
                        setSelectedUser(user);
                        setIsRoleDialogOpen(true);
                      }}
                      className="text-gray-300 hover:text-white cursor-pointer"
                    >
                      {user.roles.length > 0 ? user.roles.join(', ') : 'Set Role'}
                    </button>
                  </td>
                  <td className="px-6 py-4 text-sm space-x-4">
                    <button
                      onClick={() => {
                        setSelectedUser(user);
                        setIsPasswordDialogOpen(true);
                      }}
                      className="text-red-500 hover:text-red-400"
                    >
                      Change Password
                    </button>
                    <button
                      onClick={() => {
                        setSelectedUser(user);
                        setIsDeleteDialogOpen(true);
                      }}
                      className="text-red-500 hover:text-red-400"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {users.length > pageLimit && (
            <Pagination
              offset={pageOffset}
              limit={pageLimit}
              total={users.length}
              onPageChange={setPageOffset}
            />
          )}
        </div>
      )}

      {selectedUser && (
        <>
          <AdminPasswordChangeDialog
            isOpen={isPasswordDialogOpen}
            onClose={() => {
              setIsPasswordDialogOpen(false);
              setSelectedUser(null);
            }}
            onSubmit={handlePasswordChange}
            username={selectedUser.username}
          />
          <RoleSelectionDialog
            isOpen={isRoleDialogOpen}
            onClose={() => {
              setIsRoleDialogOpen(false);
              setSelectedUser(null);
            }}
            onSubmit={handleRoleUpdate}
            username={selectedUser.username}
            currentRoles={selectedUser.roles}
          />
          <DeleteConfirmationDialog
            isOpen={isDeleteDialogOpen}
            onClose={() => {
              setIsDeleteDialogOpen(false);
              setSelectedUser(null);
            }}
            onConfirm={handleDeleteUser}
            username={selectedUser.username}
          />
        </>
      )}

      <CreateUserDialog
        isOpen={isCreateUserDialogOpen}
        onClose={() => setIsCreateUserDialogOpen(false)}
        onSubmit={handleCreateUser}
      />
    </div>
  );
};

export default UserManagementTab;
