import { apiFetch, formatApiError } from '../utils/api';

export const fetchUsers = async () => {
  const response = await apiFetch('/api/backend/users');
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch users'));
  }
  return response.json();
};

interface PasswordChangeData {
  newPassword: string;
  confirmPassword: string;
}

export const changeUserPassword = async (userId: number, passwordData: PasswordChangeData) => {
  const response = await apiFetch(`/api/backend/users/${userId}/password`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      new_password: passwordData.newPassword,
      confirm_password: passwordData.confirmPassword,
    }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to change password'));
  }
  return response.json();
};

export const toggleUserActive = async (userId: number) => {
  const response = await apiFetch(`/api/backend/users/${userId}/toggle-active`, {
    method: 'PATCH',
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to toggle user status'));
  }
  return response.json();
};

export const updateUserRoles = async (userId: number, roles: string[]) => {
  const response = await apiFetch(`/api/backend/users/${userId}/roles`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ roles }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to update user roles'));
  }
  return response.json();
};

export const fetchAvailableRoles = async () => {
  const response = await apiFetch('/api/backend/users/roles');
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch roles'));
  }
  return response.json();
};

interface CreateUserData {
  username: string;
  email: string;
  password: string;
}

export const createUser = async (userData: CreateUserData) => {
  const response = await apiFetch('/api/backend/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(userData),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to create user'));
  }
  return response.json();
};

export const deleteUser = async (userId: number) => {
  const response = await apiFetch(`/api/backend/users/${userId}`, {
    method: 'DELETE',
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to delete user'));
  }
  return response.json();
};
