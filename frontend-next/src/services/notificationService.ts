import { apiFetch, formatApiError } from '../utils/api';

// Types

export interface Notification {
  id: number;
  type: string; // job_completed, job_failed, job_cancelled
  title: string;
  message: string | null;
  severity: string; // info, warning, error
  is_read: boolean;
  user_id: number | null;
  related_job_id: number | null;
  created_at: string;
}

export interface NotificationListResponse {
  status: string;
  total: number;
  limit: number;
  offset: number;
  notifications: Notification[];
}

export interface UnreadCountResponse {
  status: string;
  unread_count: number;
}

export interface MarkReadResponse {
  status: string;
  notification: Notification;
}

export interface MarkAllReadResponse {
  status: string;
  message: string;
  updated_count: number;
}

// API functions

export const fetchNotifications = async (
  isRead?: boolean,
  limit = 50,
  offset = 0
): Promise<NotificationListResponse> => {
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
  });
  if (isRead !== undefined) params.set('is_read', String(isRead));

  const response = await apiFetch(`/api/backend/notifications?${params}`);
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch notifications'));
  }
  return response.json();
};

export const fetchUnreadCount = async (): Promise<UnreadCountResponse> => {
  const response = await apiFetch('/api/backend/notifications/unread-count');
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch unread count'));
  }
  return response.json();
};

export const markNotificationRead = async (
  notificationId: number
): Promise<MarkReadResponse> => {
  const response = await apiFetch(
    `/api/backend/notifications/${notificationId}/read`,
    { method: 'PUT' }
  );
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to mark notification as read'));
  }
  return response.json();
};

export const markAllNotificationsRead =
  async (): Promise<MarkAllReadResponse> => {
    const response = await apiFetch('/api/backend/notifications/read-all', {
      method: 'PUT',
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(formatApiError(error, 'Failed to mark all as read'));
    }
    return response.json();
  };
