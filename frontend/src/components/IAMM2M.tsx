import React, { useState, useMemo, useCallback } from 'react';
import {
  PlusIcon,
  MagnifyingGlassIcon,
  TrashIcon,
  ArrowLeftIcon,
  ArrowPathIcon,
  ClipboardDocumentIcon,
  EyeIcon,
  EyeSlashIcon,
  PencilIcon,
} from '@heroicons/react/24/outline';
import { useIAMUsers, useIAMGroups, createM2MAccount, deleteUser, updateUserGroups, CreateM2MPayload, M2MCredentials, IAMUser } from '../hooks/useIAM';
import DeleteConfirmation from './DeleteConfirmation';

interface IAMM2MProps {
  onShowToast: (message: string, type: 'success' | 'error' | 'info') => void;
}

type View = 'list' | 'create' | 'credentials' | 'edit';

interface FormErrors {
  name?: string;
  groups?: string;
}

const IAMM2M: React.FC<IAMM2MProps> = ({ onShowToast }) => {
  // Filter to only M2M accounts
  const { users, isLoading, error, refetch } = useIAMUsers();
  const { groups } = useIAMGroups();
  const [searchQuery, setSearchQuery] = useState('');
  const [view, setView] = useState<View>('list');

  // Create form state
  const [formName, setFormName] = useState('');
  const [formDescription, setFormDescription] = useState('');
  const [formGroups, setFormGroups] = useState<Set<string>>(new Set());
  const [isCreating, setIsCreating] = useState(false);
  const [errors, setErrors] = useState<FormErrors>({});

  // Credentials display
  const [credentials, setCredentials] = useState<M2MCredentials | null>(null);
  const [showSecret, setShowSecret] = useState(false);

  // Delete state
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);

  // Edit state
  const [editTarget, setEditTarget] = useState<IAMUser | null>(null);
  const [isUpdating, setIsUpdating] = useState(false);

  const m2mAccounts = useMemo(() => {
    // M2M service accounts are identified by their email domain.
    // The backend sets email to "{clientId}@service-account.local" for all M2M accounts.
    return users.filter(
      (u) => (u.email || '').endsWith('@service-account.local')
    );
  }, [users]);

  const filteredAccounts = useMemo(() => {
    if (!searchQuery) return m2mAccounts;
    const q = searchQuery.toLowerCase();
    return m2mAccounts.filter(
      (u) =>
        u.username.toLowerCase().includes(q) ||
        (u.email || '').toLowerCase().includes(q)
    );
  }, [m2mAccounts, searchQuery]);

  const resetForm = useCallback(() => {
    setFormName('');
    setFormDescription('');
    setFormGroups(new Set());
    setErrors({});
  }, []);

  const toggleGroup = (groupName: string) => {
    setFormGroups((prev) => {
      const next = new Set(prev);
      if (next.has(groupName)) next.delete(groupName);
      else next.add(groupName);
      return next;
    });
  };

  const copyToClipboard = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      onShowToast(`${label} copied to clipboard`, 'info');
    } catch {
      onShowToast('Failed to copy to clipboard', 'error');
    }
  };

  const handleCreate = async () => {
    // Validate
    const newErrors: FormErrors = {};
    if (!formName.trim()) newErrors.name = 'Name is required';
    if (formGroups.size === 0) newErrors.groups = 'At least one group is required';
    setErrors(newErrors);
    if (Object.keys(newErrors).length > 0) return;

    setIsCreating(true);
    try {
      const payload: CreateM2MPayload = {
        name: formName.trim(),
        description: formDescription.trim() || undefined,
        groups: Array.from(formGroups),
      };
      const creds = await createM2MAccount(payload);
      setCredentials(creds);
      setView('credentials');
      onShowToast(`M2M account "${formName}" created`, 'success');
      resetForm();
    } catch (err: any) {
      const detail = err.response?.data?.detail;
      const message = Array.isArray(detail)
        ? detail.map((d: any) => d.msg).join(', ')
        : detail || 'Failed to create M2M account';
      onShowToast(message, 'error');
    } finally {
      setIsCreating(false);
    }
  };

  const handleDelete = async (username: string) => {
    await deleteUser(username);
    onShowToast(`Account "${username}" deleted`, 'success');
    setDeleteTarget(null);
    await refetch();
  };

  const handleEdit = (user: IAMUser) => {
    setEditTarget(user);
    setFormGroups(new Set(user.groups || []));
    setView('edit');
  };

  const handleUpdate = async () => {
    if (!editTarget) return;

    // Validate
    const newErrors: FormErrors = {};
    if (formGroups.size === 0) newErrors.groups = 'At least one group is required';
    setErrors(newErrors);
    if (Object.keys(newErrors).length > 0) return;

    setIsUpdating(true);
    try {
      await updateUserGroups(editTarget.username, Array.from(formGroups));
      onShowToast(`Groups updated for "${editTarget.username}"`, 'success');
      setEditTarget(null);
      setFormGroups(new Set());
      setView('list');
      await refetch();
    } catch (err: any) {
      const detail = err.response?.data?.detail;
      const message = Array.isArray(detail)
        ? detail.map((d: any) => d.msg).join(', ')
        : detail || 'Failed to update groups';
      onShowToast(message, 'error');
    } finally {
      setIsUpdating(false);
    }
  };

  // ─── Credentials View (after creation) ────────────────────────
  if (view === 'credentials' && credentials) {
    return (
      <div className="space-y-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
          IAM &gt; M2M Accounts &gt; Credentials
        </h2>

        <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-6 space-y-4">
          <p className="text-sm font-medium text-green-800 dark:text-green-200">
            M2M Account Created Successfully
          </p>

          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <span className="text-xs text-gray-500 dark:text-gray-400">Client ID</span>
                <p className="text-sm font-mono text-gray-900 dark:text-white">{credentials.client_id}</p>
              </div>
              <button onClick={() => copyToClipboard(credentials.client_id, 'Client ID')}
                className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200" title="Copy">
                <ClipboardDocumentIcon className="h-4 w-4" />
              </button>
            </div>

            <div className="flex items-center justify-between">
              <div>
                <span className="text-xs text-gray-500 dark:text-gray-400">Client Secret</span>
                <p className="text-sm font-mono text-gray-900 dark:text-white">
                  {showSecret ? credentials.client_secret : '••••••••••••••••'}
                </p>
              </div>
              <div className="flex items-center space-x-1">
                <button onClick={() => setShowSecret(!showSecret)}
                  className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200" title={showSecret ? 'Hide' : 'Show'}>
                  {showSecret ? <EyeSlashIcon className="h-4 w-4" /> : <EyeIcon className="h-4 w-4" />}
                </button>
                <button onClick={() => copyToClipboard(credentials.client_secret, 'Client Secret')}
                  className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200" title="Copy">
                  <ClipboardDocumentIcon className="h-4 w-4" />
                </button>
              </div>
            </div>
          </div>

          <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded p-3">
            <p className="text-xs text-yellow-800 dark:text-yellow-200">
              Save these credentials now. The client secret cannot be retrieved later.
            </p>
          </div>
        </div>

        <button
          onClick={() => { setCredentials(null); setShowSecret(false); setView('list'); refetch(); }}
          className="flex items-center text-sm text-purple-600 dark:text-purple-400 hover:underline"
        >
          <ArrowLeftIcon className="h-4 w-4 mr-1" />
          Back to M2M Accounts List
        </button>
      </div>
    );
  }

  // ─── Edit View ────────────────────────────────────────────────
  if (view === 'edit' && editTarget) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            IAM &gt; M2M Accounts &gt; Edit "{editTarget.username}"
          </h2>
          <button onClick={() => { setFormGroups(new Set()); setEditTarget(null); setErrors({}); setView('list'); }}
            className="flex items-center text-sm text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200">
            <ArrowLeftIcon className="h-4 w-4 mr-1" /> Back to List
          </button>
        </div>

        <div className="space-y-4 max-w-lg">
          <div>
            <label className="block text-sm text-gray-600 dark:text-gray-400 mb-2">Groups *</label>
            <div className={`space-y-2 max-h-48 overflow-y-auto rounded-lg p-3 ${
              errors.groups ? 'border-2 border-red-500' : 'border border-gray-200 dark:border-gray-700'
            }`}>
              {groups.length === 0 ? (
                <p className="text-xs text-gray-400">No groups available</p>
              ) : (
                groups.map((g) => (
                  <label key={g.name} className="flex items-center space-x-2 cursor-pointer">
                    <input type="checkbox" checked={formGroups.has(g.name)}
                      onChange={() => { toggleGroup(g.name); if (errors.groups) setErrors((p) => ({ ...p, groups: undefined })); }}
                      className="rounded border-gray-300 dark:border-gray-600 text-purple-600 focus:ring-purple-500" />
                    <span className="text-sm text-gray-700 dark:text-gray-300">{g.name}</span>
                  </label>
                ))
              )}
            </div>
            {errors.groups && <p className="mt-1 text-sm text-red-500">{errors.groups}</p>}
          </div>
        </div>

        <div className="flex justify-end space-x-3 pt-4 border-t border-gray-200 dark:border-gray-700">
          <button onClick={() => { setFormGroups(new Set()); setEditTarget(null); setErrors({}); setView('list'); }}
            className="px-4 py-2 text-sm text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-700 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600">
            Cancel
          </button>
          <button onClick={handleUpdate} disabled={isUpdating}
            className="px-4 py-2 text-sm text-white bg-purple-600 rounded-lg hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed">
            {isUpdating ? 'Updating...' : 'Update Groups'}
          </button>
        </div>
      </div>
    );
  }

  // ─── Create View ──────────────────────────────────────────────
  if (view === 'create') {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            IAM &gt; M2M Accounts &gt; Create
          </h2>
          <button onClick={() => { resetForm(); setView('list'); }}
            className="flex items-center text-sm text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200">
            <ArrowLeftIcon className="h-4 w-4 mr-1" /> Back to List
          </button>
        </div>

        <div className="space-y-4 max-w-lg">
          <div>
            <label className="block text-sm text-gray-600 dark:text-gray-400 mb-1">Name *</label>
            <input type="text" value={formName}
              onChange={(e) => { setFormName(e.target.value); if (errors.name) setErrors((p) => ({ ...p, name: undefined })); }}
              placeholder="e.g. ci-pipeline"
              className={`w-full px-3 py-2 border rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white focus:ring-2 focus:ring-purple-500 focus:border-transparent ${
                errors.name ? 'border-red-500' : 'border-gray-300 dark:border-gray-600'
              }`} />
            {errors.name && <p className="mt-1 text-sm text-red-500">{errors.name}</p>}
          </div>
          <div>
            <label className="block text-sm text-gray-600 dark:text-gray-400 mb-1">Description (optional)</label>
            <input type="text" value={formDescription} onChange={(e) => setFormDescription(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white focus:ring-2 focus:ring-purple-500 focus:border-transparent" />
          </div>

          <div>
            <label className="block text-sm text-gray-600 dark:text-gray-400 mb-2">Groups *</label>
            <div className={`space-y-2 max-h-48 overflow-y-auto rounded-lg p-3 ${
              errors.groups ? 'border-2 border-red-500' : 'border border-gray-200 dark:border-gray-700'
            }`}>
              {groups.length === 0 ? (
                <p className="text-xs text-gray-400">No groups available</p>
              ) : (
                groups.map((g) => (
                  <label key={g.name} className="flex items-center space-x-2 cursor-pointer">
                    <input type="checkbox" checked={formGroups.has(g.name)}
                      onChange={() => { toggleGroup(g.name); if (errors.groups) setErrors((p) => ({ ...p, groups: undefined })); }}
                      className="rounded border-gray-300 dark:border-gray-600 text-purple-600 focus:ring-purple-500" />
                    <span className="text-sm text-gray-700 dark:text-gray-300">{g.name}</span>
                  </label>
                ))
              )}
            </div>
            {errors.groups && <p className="mt-1 text-sm text-red-500">{errors.groups}</p>}
          </div>
        </div>

        <div className="flex justify-end space-x-3 pt-4 border-t border-gray-200 dark:border-gray-700">
          <button onClick={() => { resetForm(); setView('list'); }}
            className="px-4 py-2 text-sm text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-700 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600">
            Cancel
          </button>
          <button onClick={handleCreate} disabled={isCreating}
            className="px-4 py-2 text-sm text-white bg-purple-600 rounded-lg hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed">
            {isCreating ? 'Creating...' : 'Create Account'}
          </button>
        </div>
      </div>
    );
  }

  // ─── List View ────────────────────────────────────────────────
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white">IAM &gt; M2M Accounts</h2>
        <div className="flex items-center space-x-2">
          <button onClick={refetch} className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200" title="Refresh">
            <ArrowPathIcon className="h-5 w-5" />
          </button>
          <button onClick={() => setView('create')}
            className="flex items-center px-3 py-2 text-sm text-white bg-purple-600 rounded-lg hover:bg-purple-700">
            <PlusIcon className="h-4 w-4 mr-1" /> Create M2M Account
          </button>
        </div>
      </div>

      <div className="relative">
        <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
        <input type="text" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Search M2M accounts..."
          className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-purple-500 focus:border-transparent" />
      </div>

      {isLoading && (
        <div className="flex justify-center py-12"><ArrowPathIcon className="h-6 w-6 text-gray-400 animate-spin" /></div>
      )}
      {error && !isLoading && (
        <div className="text-center py-8 text-red-500 dark:text-red-400 text-sm">{error}</div>
      )}
      {!isLoading && !error && filteredAccounts.length === 0 && (
        <div className="text-center py-12 text-gray-500 dark:text-gray-400">
          {searchQuery ? 'No accounts match your search.' : 'No M2M accounts yet. Create your first service account.'}
        </div>
      )}

      {!isLoading && !error && filteredAccounts.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 dark:border-gray-700">
                <th className="text-left py-3 px-4 font-medium text-gray-500 dark:text-gray-400">Name</th>
                <th className="text-left py-3 px-4 font-medium text-gray-500 dark:text-gray-400">Groups</th>
                <th className="text-right py-3 px-4 font-medium text-gray-500 dark:text-gray-400">Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredAccounts.map((u) => (
                <React.Fragment key={u.username}>
                  <tr className="border-b border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800/50">
                    <td className="py-3 px-4 text-gray-900 dark:text-white font-medium">{u.username}</td>
                    <td className="py-3 px-4">
                      <div className="flex flex-wrap gap-1">
                        {(u.groups || []).map((g) => (
                          <span key={g} className="inline-block px-2 py-0.5 text-xs rounded-full bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300">
                            {g}
                          </span>
                        ))}
                        {(!u.groups || u.groups.length === 0) && <span className="text-gray-400 text-xs">{'\u2014'}</span>}
                      </div>
                    </td>
                    <td className="py-3 px-4 text-right">
                      <div className="flex items-center justify-end space-x-2">
                        <button onClick={() => handleEdit(u)} className="p-1 text-gray-400 hover:text-purple-500 dark:hover:text-purple-400" title="Edit groups">
                          <PencilIcon className="h-4 w-4" />
                        </button>
                        <button onClick={() => setDeleteTarget(u.username)} className="p-1 text-gray-400 hover:text-red-500 dark:hover:text-red-400" title="Delete account">
                          <TrashIcon className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                  {deleteTarget === u.username && (
                    <tr>
                      <td colSpan={3} className="p-2">
                        <DeleteConfirmation
                          entityType="m2m"
                          entityName={u.username}
                          entityPath={u.username}
                          onConfirm={handleDelete}
                          onCancel={() => setDeleteTarget(null)}
                        />
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default IAMM2M;
