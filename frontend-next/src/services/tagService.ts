import { apiFetch, formatApiError } from '../utils/api';

export interface Tag {
  id: number;
  name: string;
  color: string;
  created_by: number;
  system_count: number;
  created_at: string;
  updated_at: string;
}

export interface TagCreate {
  name: string;
  color?: string;
}

export interface TagUpdate {
  name?: string;
  color?: string;
}

export const fetchTags = async (): Promise<Tag[]> => {
  const response = await apiFetch('/api/backend/tags');
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch tags'));
  }
  return response.json();
};

export const createTag = async (data: TagCreate): Promise<Tag> => {
  const response = await apiFetch('/api/backend/tags', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to create tag'));
  }
  return response.json();
};

export const updateTag = async (tagId: number, data: TagUpdate): Promise<Tag> => {
  const response = await apiFetch(`/api/backend/tags/${tagId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to update tag'));
  }
  return response.json();
};

export const deleteTag = async (tagId: number): Promise<void> => {
  const response = await apiFetch(`/api/backend/tags/${tagId}`, { method: 'DELETE' });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to delete tag'));
  }
};

export const assignTagToSystems = async (tagId: number, systemIds: number[]): Promise<void> => {
  const response = await apiFetch(`/api/backend/tags/${tagId}/systems`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ system_ids: systemIds }),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to assign tag to systems'));
  }
};

export const removeTagFromSystems = async (tagId: number, systemIds: number[]): Promise<void> => {
  const response = await apiFetch(`/api/backend/tags/${tagId}/systems`, {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ system_ids: systemIds }),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to remove tag from systems'));
  }
};

export const bulkAssignTags = async (tagIds: number[], systemIds: number[]): Promise<void> => {
  const response = await apiFetch('/api/backend/tags/bulk-assign', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tag_ids: tagIds, system_ids: systemIds }),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to bulk assign tags'));
  }
};
