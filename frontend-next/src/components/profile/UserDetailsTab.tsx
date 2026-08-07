import React, { useState } from 'react';
import { toast } from 'sonner';
import { PasswordChangeDialog } from '../PasswordChangeDialog';
import { changePassword } from '../../services/authService';

interface UserDetailsTabProps {
  user: {
    id: number;
    username: string;
    email: string;
    roles: string[];
  };
}

const UserDetailsTab: React.FC<UserDetailsTabProps> = ({ user }) => {
  const [isPasswordDialogOpen, setIsPasswordDialogOpen] = useState(false);

  const handlePasswordChange = async (currentPassword: string, newPassword: string) => {
    await changePassword(currentPassword, newPassword);
    toast.success('Password changed');
  };

  return (
    <div>
      <div className="mb-4">
        <div className="text-sm text-gray-600">User ID</div>
        <div>{user.id}</div>
      </div>

      <div className="mb-4">
        <div className="text-sm text-gray-600">Name</div>
        <div>{user.username}</div>
      </div>

      <div className="mb-4">
        <div className="text-sm text-gray-600">Email</div>
        <div>{user.email}</div>
      </div>

      <div className="mb-4">
        <div className="text-sm text-gray-600">Group Membership</div>
        <div>
          {user.roles?.length > 0 ? (
            user.roles.join(', ')
          ) : (
            'No group memberships assigned'
          )}
        </div>
      </div>

      <div className="mt-8">
        <button
          onClick={() => setIsPasswordDialogOpen(true)}
          className="px-4 py-2 text-sm font-medium text-gray-400 bg-[#0c0c0f] border border-gray-800/60 rounded hover:text-white hover:border-red-500 transition-colors"
        >
          Change Password
        </button>
      </div>

      <PasswordChangeDialog
        isOpen={isPasswordDialogOpen}
        onClose={() => setIsPasswordDialogOpen(false)}
        onSubmit={handlePasswordChange}
      />
    </div>
  );
};

export default UserDetailsTab;
