import React, { useState, useEffect } from 'react';
import { toast } from 'sonner';
import { useRouter } from 'next/router';
import MainLayout from '@/components/MainLayout';
import { fetchGroups, createGroup, updateGroup, deleteGroup, fetchGroupSystems, assignSystemsToGroup, fetchAllSystems } from '@/services/systemService';
import { useAuth } from '@/context/AuthContext';
import Head from 'next/head';
import { PageHeader, Button, Card, CardBody, StatusBadge, EmptyState, SkeletonCards, ActionMenu } from '@/components/ui';
import type { ActionMenuItem } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';

interface Group {
  id: number;
  name: string;
  description?: string;
  parent_id?: number;
  systemCount?: number;
  childCount?: number;
}

interface System {
  id: number;
  hostname: string;
  ip_address: string;
  status: string;
  os_version: string;
  registered_at: string;
  environment_type?: string;
  group_name: string;
  distro_name: string;
}

const SystemGroups = () => {
  const { user, canWrite } = useAuth();
  const router = useRouter();
  const [groups, setGroups] = useState<Group[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [showAssignModal, setShowAssignModal] = useState(false);
  const [showViewSystemsModal, setShowViewSystemsModal] = useState(false);
  const [currentGroup, setCurrentGroup] = useState<Group | null>(null);
  const [groupSystems, setGroupSystems] = useState<System[]>([]);
  const [allSystems, setAllSystems] = useState<System[]>([]);
  const [selectedSystems, setSelectedSystems] = useState<number[]>([]);
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    parent_id: undefined as number | undefined,
  });
  const [formErrors, setFormErrors] = useState({
    name: '',
  });

  // Fetch groups on component mount
  useEffect(() => {
    const loadGroups = async () => {
      if (user) {
        try {
          setLoading(true);
          const groupsData = await fetchGroups();

          // Count systems and child groups for each group
          const groupsWithCounts = await Promise.all(
            groupsData.map(async (group: Group) => {
              try {
                const systems = await fetchGroupSystems(group.id);
                // Count child groups
                const childCount = groupsData.filter(g => g.parent_id === group.id).length;
                return { ...group, systemCount: systems.length, childCount };
              } catch (error) {
                console.error(`Error fetching systems for group ${group.id}:`, error);
                return { ...group, systemCount: 0, childCount: 0 };
              }
            })
          );

          setGroups(groupsWithCounts);
          setError(null);
        } catch (err) {
          console.error('Error fetching groups:', err);
          setError('Failed to load groups. Please try again later.');
        } finally {
          setLoading(false);
        }
      }
    };

    loadGroups();
  }, [user]);

  // Load all systems for assignment
  const loadAllSystems = async () => {
    if (user) {
      try {
        const systems = await fetchAllSystems();
        setAllSystems(systems);
      } catch (err) {
        console.error('Error fetching all systems:', err);
        setError('Failed to load systems. Please try again later.');
      }
    }
  };

  // Load systems for a specific group
  const loadGroupSystems = async (groupId: number) => {
    if (user) {
      try {
        const systems = await fetchGroupSystems(groupId);
        setGroupSystems(systems);
      } catch (err) {
        console.error(`Error fetching systems for group ${groupId}:`, err);
        setError('Failed to load systems for this group. Please try again later.');
      }
    }
  };

  // Handle form input changes
  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: name === 'parent_id' ? (value ? parseInt(value) : undefined) : value,
    });

    // Clear validation errors when user types
    if (formErrors[name as keyof typeof formErrors]) {
      setFormErrors({
        ...formErrors,
        [name]: '',
      });
    }
  };

  // Validate form data
  const validateForm = () => {
    const errors = {
      name: '',
    };
    let isValid = true;

    if (!formData.name.trim()) {
      errors.name = 'Group name is required';
      isValid = false;
    }

    setFormErrors(errors);
    return isValid;
  };

  // Handle create group
  const handleCreateGroup = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateForm()) return;

    if (user) {
      try {
        await createGroup(formData);

        // Refresh groups list
        const groupsData = await fetchGroups();
        const groupsWithCounts = await Promise.all(
          groupsData.map(async (group: Group) => {
            try {
              const systems = await fetchGroupSystems(group.id);
              // Count child groups
              const childCount = groupsData.filter(g => g.parent_id === group.id).length;
              return { ...group, systemCount: systems.length, childCount };
            } catch (error) {
              console.error(`Error fetching systems for group ${group.id}:`, error);
              return { ...group, systemCount: 0, childCount: 0 };
            }
          })
        );

        setGroups(groupsWithCounts);
        setShowCreateModal(false);
        setFormData({ name: '', description: '', parent_id: undefined });
        toast.success('Group created');
      } catch (err) {
        console.error('Error creating group:', err);
        setError('Failed to create group. Please try again later.');
        toast.error('Failed to create group');
      }
    }
  };

  // Handle edit group
  const handleEditGroup = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateForm() || !currentGroup) return;

    if (user) {
      try {
        await updateGroup(currentGroup.id, formData);

        // Refresh groups list
        const groupsData = await fetchGroups();
        const groupsWithCounts = await Promise.all(
          groupsData.map(async (group: Group) => {
            try {
              const systems = await fetchGroupSystems(group.id);
              // Count child groups
              const childCount = groupsData.filter(g => g.parent_id === group.id).length;
              return { ...group, systemCount: systems.length, childCount };
            } catch (error) {
              console.error(`Error fetching systems for group ${group.id}:`, error);
              return { ...group, systemCount: 0, childCount: 0 };
            }
          })
        );

        setGroups(groupsWithCounts);
        setShowEditModal(false);
        setCurrentGroup(null);
        setFormData({ name: '', description: '', parent_id: undefined });
        toast.success('Group updated');
      } catch (err) {
        console.error('Error updating group:', err);
        setError('Failed to update group. Please try again later.');
        toast.error('Failed to update group');
      }
    }
  };

  // Handle delete group
  const handleDeleteGroup = async () => {
    if (!currentGroup) return;

    if (user) {
      try {
        await deleteGroup(currentGroup.id);

        // Refresh groups list
        const groupsData = await fetchGroups();
        const groupsWithCounts = await Promise.all(
          groupsData.map(async (group: Group) => {
            try {
              const systems = await fetchGroupSystems(group.id);
              // Count child groups
              const childCount = groupsData.filter(g => g.parent_id === group.id).length;
              return { ...group, systemCount: systems.length, childCount };
            } catch (error) {
              console.error(`Error fetching systems for group ${group.id}:`, error);
              return { ...group, systemCount: 0, childCount: 0 };
            }
          })
        );

        setGroups(groupsWithCounts);
        setShowDeleteModal(false);
        setCurrentGroup(null);
        toast.success('Group deleted');
      } catch (err) {
        console.error('Error deleting group:', err);
        setError('Failed to delete group. Please try again later.');
        toast.error('Failed to delete group');
      }
    }
  };

  // Handle assign systems to group
  const handleAssignSystems = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!currentGroup || selectedSystems.length === 0) return;

    if (user) {
      try {
        await assignSystemsToGroup(currentGroup.id, selectedSystems);

        // Refresh groups list
        const groupsData = await fetchGroups();
        const groupsWithCounts = await Promise.all(
          groupsData.map(async (group: Group) => {
            try {
              const systems = await fetchGroupSystems(group.id);
              // Count child groups
              const childCount = groupsData.filter(g => g.parent_id === group.id).length;
              return { ...group, systemCount: systems.length, childCount };
            } catch (error) {
              console.error(`Error fetching systems for group ${group.id}:`, error);
              return { ...group, systemCount: 0, childCount: 0 };
            }
          })
        );

        setGroups(groupsWithCounts);
        setShowAssignModal(false);
        setSelectedSystems([]);
        toast.success('Systems assigned to group');
      } catch (err) {
        console.error('Error assigning systems to group:', err);
        setError('Failed to assign systems to group. Please try again later.');
        toast.error('Failed to assign systems to group');
      }
    }
  };

  // Open edit modal with group data
  const openEditModal = (group: Group) => {
    setCurrentGroup(group);
    setFormData({
      name: group.name,
      description: group.description || '',
      parent_id: group.parent_id,
    });
    setShowEditModal(true);
  };

  // Open delete modal with group data
  const openDeleteModal = (group: Group) => {
    setCurrentGroup(group);
    setShowDeleteModal(true);
  };

  // Open view systems modal with group data
  const openViewSystemsModal = async (group: Group) => {
    setCurrentGroup(group);
    await loadGroupSystems(group.id);
    setShowViewSystemsModal(true);
  };

  // Open assign systems modal with group data
  const openAssignModal = async (group: Group) => {
    setCurrentGroup(group);
    await loadAllSystems();
    await loadGroupSystems(group.id);
    setShowAssignModal(true);
  };

  // Handle system selection for assignment
  const handleSystemSelection = (systemId: number) => {
    if (selectedSystems.includes(systemId)) {
      setSelectedSystems(selectedSystems.filter(id => id !== systemId));
    } else {
      setSelectedSystems([...selectedSystems, systemId]);
    }
  };

  // Group menu options. PRA-349: rendered through a portal-based ActionMenu so it
  // escapes card clipping and flips/clamps to stay fully visible near the viewport
  // edges. Actions and canWrite gating are preserved exactly.
  const renderGroupMenu = (group: Group) => {
    const items: ActionMenuItem[] = [
      { label: 'View Systems', onSelect: () => openViewSystemsModal(group) },
    ];
    if (canWrite) {
      items.push(
        { label: 'Assign Systems', onSelect: () => openAssignModal(group) },
        { label: 'Edit Group', onSelect: () => openEditModal(group) },
        { label: 'Delete Group', onSelect: () => openDeleteModal(group), danger: true },
      );
    }
    return <ActionMenu items={items} triggerLabel={`Actions for ${group.name}`} />;
  };

  return (
    <MainLayout>
        <Head>
          <title>System Groups | Praxis</title>
        </Head>
        <PageHeader
          title="System Groups"
          subtitle="Manage system groups and classifications"
          actions={
            <div className="flex items-center gap-2">
              {canWrite && (
                <Button
                  variant="primary"
                  onClick={() => {
                    setFormData({ name: '', description: '', parent_id: undefined });
                    setShowCreateModal(true);
                  }}
                >
                  Create Group
                </Button>
              )}
              <HelpLink slug="fleet-and-hosts" />
            </div>
          }
        />

        {error && (
          <div className="mb-4 p-4 bg-red-500/10 border border-red-500/30 text-red-400 rounded-lg text-sm">
            {error}
          </div>
        )}

        <Card>
          <CardBody>
          {loading ? (
            <SkeletonCards count={6} />
          ) : groups.length === 0 ? (
            <EmptyState
              title="No groups found"
              description="Create your first group to get started."
              action={
                canWrite ? (
                  <Button variant="primary" onClick={() => { setFormData({ name: '', description: '', parent_id: undefined }); setShowCreateModal(true); }}>
                    Create Group
                  </Button>
                ) : undefined
              }
            />
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {groups.map(group => (
                <div key={group.id} className="border border-border bg-surface-raised rounded-lg p-4 hover:shadow-md transition-shadow">
                  <div className="flex justify-between items-start mb-3">
                    <div>
                      <h3 className="text-lg font-medium text-content">{group.name}</h3>
                      <p className="text-sm text-content-muted">{group.systemCount || 0} systems</p>
                    </div>
                    {renderGroupMenu(group)}
                  </div>
                  <p className="text-content-muted text-sm">{group.description || 'No description'}</p>
                  {group.parent_id && (
                    <p className="text-xs text-content-subtle mt-2">
                      Parent: {groups.find(g => g.id === group.parent_id)?.name || 'Unknown'}
                    </p>
                  )}
                </div>
              ))}
            </div>
          )}
          </CardBody>
        </Card>

      {/* Create Group Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-surface/50 flex items-center justify-center z-50">
          <div className="bg-surface-overlay border border-border rounded-lg p-6 w-full max-w-md">
            <h2 className="text-xl font-semibold mb-4 text-content">Create New Group</h2>
            <form onSubmit={handleCreateGroup}>
              <div className="mb-4">
                <label className="block text-content text-sm font-medium mb-2" htmlFor="name">
                  Group Name*
                </label>
                <input
                  type="text"
                  id="name"
                  name="name"
                  value={formData.name}
                  onChange={handleInputChange}
                  className={`w-full px-3 py-2 bg-surface-sunken border border-border/60 rounded-md text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring ${
                    formErrors.name ? 'border-red-500' : ''
                  }`}
                />
                {formErrors.name && <p className="text-red-500 text-xs italic">{formErrors.name}</p>}
              </div>
              <div className="mb-4">
                <label className="block text-content text-sm font-medium mb-2" htmlFor="description">
                  Description
                </label>
                <textarea
                  id="description"
                  name="description"
                  value={formData.description}
                  onChange={handleInputChange}
                  className="w-full px-3 py-2 bg-surface-sunken border border-border/60 rounded-md text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
                  rows={3}
                />
              </div>
              <div className="mb-6">
                <label className="block text-content text-sm font-medium mb-2" htmlFor="parent_id">
                  Parent Group
                </label>
                <select
                  id="parent_id"
                  name="parent_id"
                  value={formData.parent_id || ''}
                  onChange={handleInputChange}
                  className="w-full px-3 py-2 bg-surface-sunken border border-border/60 rounded-md text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
                >
                  <option value="">None</option>
                  {groups.map(group => (
                    <option key={group.id} value={group.id}>
                      {group.name}
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex items-center justify-between">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="bg-border hover:bg-border-strong text-content font-medium py-2 px-4 rounded focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline"
                >
                  Create Group
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit Group Modal */}
      {showEditModal && currentGroup && (
        <div className="fixed inset-0 bg-surface/50 flex items-center justify-center z-50">
          <div className="bg-surface-overlay border border-border rounded-lg p-6 w-full max-w-md">
            <h2 className="text-xl font-semibold mb-4 text-content">Edit Group: {currentGroup.name}</h2>
            <form onSubmit={handleEditGroup}>
              <div className="mb-4">
                <label className="block text-content text-sm font-medium mb-2" htmlFor="name">
                  Group Name*
                </label>
                <input
                  type="text"
                  id="name"
                  name="name"
                  value={formData.name}
                  onChange={handleInputChange}
                  className={`w-full px-3 py-2 bg-surface-sunken border border-border/60 rounded-md text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring ${
                    formErrors.name ? 'border-red-500' : ''
                  }`}
                />
                {formErrors.name && <p className="text-red-500 text-xs italic">{formErrors.name}</p>}
              </div>
              <div className="mb-4">
                <label className="block text-content text-sm font-medium mb-2" htmlFor="description">
                  Description
                </label>
                <textarea
                  id="description"
                  name="description"
                  value={formData.description}
                  onChange={handleInputChange}
                  className="w-full px-3 py-2 bg-surface-sunken border border-border/60 rounded-md text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
                  rows={3}
                />
              </div>
              <div className="mb-6">
                <label className="block text-content text-sm font-medium mb-2" htmlFor="parent_id">
                  Parent Group
                </label>
                <select
                  id="parent_id"
                  name="parent_id"
                  value={formData.parent_id || ''}
                  onChange={handleInputChange}
                  className="w-full px-3 py-2 bg-surface-sunken border border-border/60 rounded-md text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
                >
                  <option value="">None</option>
                  {groups
                    .filter(group => group.id !== currentGroup.id) // Prevent circular references
                    .map(group => (
                      <option key={group.id} value={group.id}>
                        {group.name}
                      </option>
                    ))}
                </select>
              </div>
              <div className="flex items-center justify-between">
                <button
                  type="button"
                  onClick={() => setShowEditModal(false)}
                  className="bg-border hover:bg-border-strong text-content font-medium py-2 px-4 rounded focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline"
                >
                  Update Group
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Group Modal */}
      {showDeleteModal && currentGroup && (
        <div className="fixed inset-0 bg-surface/50 flex items-center justify-center z-50">
          <div className="bg-surface-overlay border border-border rounded-lg p-6 w-full max-w-md">
            <h2 className="text-xl font-semibold mb-4 text-content">Delete Group</h2>
            <p className="mb-6 text-content">
              Are you sure you want to delete the group &quot;{currentGroup.name}&quot;? This action cannot be undone.
              {currentGroup.systemCount && currentGroup.systemCount > 0 ? (
                <span className="block text-red-600 mt-2">
                  This group contains {currentGroup.systemCount} systems. You must reassign these systems before deleting the group.
                </span>
              ) : null}
              {currentGroup.childCount && currentGroup.childCount > 0 ? (
                <span className="block text-red-600 mt-2">
                  This group has {currentGroup.childCount} child groups. You must delete or reassign these child groups first.
                </span>
              ) : null}
            </p>
            <div className="flex items-center justify-between">
              <button
                type="button"
                onClick={() => setShowDeleteModal(false)}
                className="bg-border hover:bg-border-strong text-content font-medium py-2 px-4 rounded focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleDeleteGroup}
                className="bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline"
                disabled={(currentGroup.systemCount ?? 0) > 0 || (currentGroup.childCount ?? 0) > 0}
              >
                Delete Group
              </button>
            </div>
          </div>
        </div>
      )}

      {/* View Systems Modal */}
      {showViewSystemsModal && currentGroup && (
        <div className="fixed inset-0 bg-surface/50 flex items-center justify-center z-50">
          <div className="bg-surface-overlay border border-border rounded-lg p-6 w-full max-w-4xl max-h-[80vh] overflow-auto">
            <h2 className="text-xl font-semibold mb-4 text-content">Systems in Group: {currentGroup.name}</h2>

            {groupSystems.length === 0 ? (
              <p className="text-content text-center py-8">No systems in this group.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-border">
                  <thead className="bg-surface-raised">
                    <tr>
                      <th scope="col" className="py-2 px-4 border-b border-border text-left text-xs font-medium text-content uppercase tracking-wider">
                        Hostname
                      </th>
                      <th scope="col" className="py-2 px-4 border-b border-border text-left text-xs font-medium text-content uppercase tracking-wider">
                        IP Address
                      </th>
                      <th scope="col" className="py-2 px-4 border-b border-border text-left text-xs font-medium text-content uppercase tracking-wider">
                        Status
                      </th>
                      <th scope="col" className="py-2 px-4 border-b border-border text-left text-xs font-medium text-content uppercase tracking-wider">
                        OS
                      </th>
                      <th scope="col" className="py-2 px-4 border-b border-border text-left text-xs font-medium text-content uppercase tracking-wider">
                        Environment
                      </th>
                      <th scope="col" className="py-2 px-4 border-b border-border text-left text-xs font-medium text-content uppercase tracking-wider">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-surface-sunken divide-y divide-border">
                    {groupSystems.map(system => (
                      <tr key={system.id} className="hover:bg-white/[0.03]">
                        <td className="py-2 px-4 whitespace-nowrap text-sm font-medium text-content">{system.hostname}</td>
                        <td className="py-2 px-4 whitespace-nowrap text-sm text-content">{system.ip_address}</td>
                        <td className="py-2 px-4 whitespace-nowrap">
                          <StatusBadge status={system.status} />
                        </td>
                        <td className="py-2 px-4 whitespace-nowrap text-sm text-content">{system.distro_name} {system.os_version}</td>
                        <td className="py-2 px-4 whitespace-nowrap text-sm text-content">{system.environment_type || 'N/A'}</td>
                        <td className="py-2 px-4 whitespace-nowrap text-sm font-medium">
                          <button
                            onClick={() => router.push(`/system-management/system/${system.id}`)}
                            className="text-red-500 hover:text-red-400"
                          >
                            View
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            <div className="mt-6 flex justify-end">
              <button
                type="button"
                onClick={() => setShowViewSystemsModal(false)}
                className="bg-border hover:bg-border-strong text-content font-medium py-2 px-4 rounded focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Assign Systems Modal */}
      {showAssignModal && currentGroup && (
        <div className="fixed inset-0 bg-surface/50 flex items-center justify-center z-50">
          <div className="bg-surface-overlay border border-border rounded-lg p-6 w-full max-w-4xl max-h-[80vh] overflow-auto">
            <h2 className="text-xl font-semibold mb-4 text-content">Assign Systems to Group: {currentGroup.name}</h2>

            {allSystems.length === 0 ? (
              <p className="text-content text-center py-8">No systems available to assign.</p>
            ) : (
              <form onSubmit={handleAssignSystems}>
                <div className="mb-4">
                  <p className="text-sm text-content mb-2">
                    Select systems to assign to this group. Systems already in this group are marked.
                  </p>
                  <div className="border border-border rounded-lg overflow-hidden">
                    <table className="min-w-full divide-y divide-border">
                      <thead className="bg-surface-raised">
                        <tr>
                          <th scope="col" className="py-2 px-4 border-b border-border text-left text-xs font-medium text-content uppercase tracking-wider">
                            Select
                          </th>
                          <th scope="col" className="py-2 px-4 border-b border-border text-left text-xs font-medium text-content uppercase tracking-wider">
                            Hostname
                          </th>
                          <th scope="col" className="py-2 px-4 border-b border-border text-left text-xs font-medium text-content uppercase tracking-wider">
                            IP Address
                          </th>
                          <th scope="col" className="py-2 px-4 border-b border-border text-left text-xs font-medium text-content uppercase tracking-wider">
                            Status
                          </th>
                          <th scope="col" className="py-2 px-4 border-b border-border text-left text-xs font-medium text-content uppercase tracking-wider">
                            OS Version
                          </th>
                          <th scope="col" className="py-2 px-4 border-b border-border text-left text-xs font-medium text-content uppercase tracking-wider">
                            Current Group
                          </th>
                        </tr>
                      </thead>
                      <tbody className="bg-surface-sunken divide-y divide-border">
                        {allSystems.map(system => {
                          const isInCurrentGroup = groupSystems.some(gs => gs.id === system.id);
                          return (
                            <tr key={system.id} className={`hover:bg-white/[0.03] ${isInCurrentGroup ? 'bg-surface-raised' : ''}`}>
                              <td className="py-2 px-4 whitespace-nowrap text-sm">
                                <input
                                  type="checkbox"
                                  checked={selectedSystems.includes(system.id) || isInCurrentGroup}
                                  onChange={() => handleSystemSelection(system.id)}
                                  disabled={isInCurrentGroup}
                                  className="form-checkbox h-5 w-5 text-red-600"
                                />
                              </td>
                              <td className="py-2 px-4 whitespace-nowrap text-sm font-medium text-content">{system.hostname}</td>
                              <td className="py-2 px-4 whitespace-nowrap text-sm text-content">{system.ip_address}</td>
                              <td className="py-2 px-4 whitespace-nowrap">
                                <StatusBadge status={system.status} />
                              </td>
                              <td className="py-2 px-4 whitespace-nowrap text-sm text-content">{system.distro_name} {system.os_version}</td>
                              <td className="py-2 px-4 whitespace-nowrap text-sm text-content">{system.group_name}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
                <div className="mt-6 flex justify-end space-x-4">
                  <button
                    type="button"
                    onClick={() => setShowAssignModal(false)}
                    className="bg-border hover:bg-border-strong text-content font-medium py-2 px-4 rounded focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline"
                    disabled={selectedSystems.length === 0}
                  >
                    Assign Systems
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </MainLayout>
  );
};

export default SystemGroups;
