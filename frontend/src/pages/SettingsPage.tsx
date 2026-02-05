import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  ChevronDownIcon,
  ChevronRightIcon,
  UsersIcon,
  GlobeAltIcon,
  ArrowLeftIcon,
  ClipboardDocumentListIcon,
} from '@heroicons/react/24/outline';
import FederationPeers from '../components/FederationPeers';
import FederationPeerForm from '../components/FederationPeerForm';
import AuditLogsPage from './AuditLogsPage';
import { useAuth } from '../contexts/AuthContext';


/**
 * Toast notification state interface.
 */
interface ToastState {
  show: boolean;
  message: string;
  type: 'success' | 'error' | 'info';
}


/**
 * Settings category item interface.
 */
interface SettingsItem {
  id: string;
  label: string;
  path: string;
}


/**
 * Settings category interface.
 */
interface SettingsCategory {
  id: string;
  label: string;
  icon: React.ReactNode;
  items: SettingsItem[];
  disabled?: boolean;
  adminOnly?: boolean;
}


/**
 * Settings categories configuration.
 * Following VS Code-style layout from issue #416.
 */
const SETTINGS_CATEGORIES: SettingsCategory[] = [
  {
    id: 'iam',
    label: 'IAM',
    icon: <UsersIcon className="h-5 w-5" />,
    items: [
      { id: 'groups', label: 'Groups', path: '/settings/iam/groups' },
      { id: 'users', label: 'Users', path: '/settings/iam/users' },
      { id: 'm2m', label: 'M2M Accounts', path: '/settings/iam/m2m' },
    ],
    disabled: true, // IAM not implemented yet
  },
  {
    id: 'federation',
    label: 'Federation',
    icon: <GlobeAltIcon className="h-5 w-5" />,
    items: [
      { id: 'peers', label: 'Peers', path: '/settings/federation/peers' },
    ],
  },
  {
    id: 'audit',
    label: 'Audit',
    icon: <ClipboardDocumentListIcon className="h-5 w-5" />,
    items: [
      { id: 'logs', label: 'Audit Logs', path: '/settings/audit/logs' },
    ],
    adminOnly: true, // Only visible to admins
  },
];


/**
 * SettingsPage component provides a VS Code-style settings interface.
 *
 * Features a collapsible sidebar with categories and a main content area
 * that renders the appropriate component based on the current route.
 */
const SettingsPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { user } = useAuth();

  // Filter categories based on user permissions
  const visibleCategories = SETTINGS_CATEGORIES.filter(
    (category) => !category.adminOnly || user?.is_admin
  );

  // Track which categories are expanded
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(
    new Set(['federation']) // Federation expanded by default
  );

  // Toast notification state
  const [toast, setToast] = useState<ToastState>({
    show: false,
    message: '',
    type: 'success',
  });

  // Auto-dismiss toast after 4 seconds
  useEffect(() => {
    if (toast.show) {
      const timer = setTimeout(() => {
        setToast((prev) => ({ ...prev, show: false }));
      }, 4000);
      return () => clearTimeout(timer);
    }
  }, [toast.show]);

  /**
   * Show a toast notification.
   */
  const showToast = (message: string, type: 'success' | 'error' | 'info' = 'success') => {
    setToast({ show: true, message, type });
  };

  /**
   * Toggle category expansion.
   */
  const toggleCategory = (categoryId: string) => {
    setExpandedCategories((prev) => {
      const next = new Set(prev);
      if (next.has(categoryId)) {
        next.delete(categoryId);
      } else {
        next.add(categoryId);
      }
      return next;
    });
  };

  /**
   * Check if a path is currently active.
   */
  const isActivePath = (path: string): boolean => {
    return location.pathname.startsWith(path);
  };

  /**
   * Get the current active item ID.
   */
  const getActiveItemId = (): string | null => {
    for (const category of SETTINGS_CATEGORIES) {
      for (const item of category.items) {
        if (isActivePath(item.path)) {
          return item.id;
        }
      }
    }
    return null;
  };

  /**
   * Render the content area based on current route.
   */
  const renderContent = () => {
    const path = location.pathname;

    // Audit > Logs
    if (path === '/settings/audit/logs' || path === '/settings/audit') {
      return <AuditLogsPage embedded />;
    }

    // Federation > Peers list
    if (path === '/settings/federation/peers' || path === '/settings/federation') {
      return <FederationPeers onShowToast={showToast} />;
    }

    // Federation > Add peer
    if (path === '/settings/federation/peers/add') {
      return <FederationPeerForm onShowToast={showToast} />;
    }

    // Federation > Edit peer
    const editMatch = path.match(/^\/settings\/federation\/peers\/([^/]+)\/edit$/);
    if (editMatch) {
      return <FederationPeerForm peerId={editMatch[1]} onShowToast={showToast} />;
    }

    // IAM placeholders (not implemented yet)
    if (path.startsWith('/settings/iam')) {
      return (
        <div className="flex items-center justify-center h-64">
          <div className="text-center">
            <UsersIcon className="h-12 w-12 mx-auto text-gray-400 dark:text-gray-600 mb-4" />
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
              IAM Settings
            </h3>
            <p className="text-gray-500 dark:text-gray-400">
              Identity and Access Management settings are coming soon.
            </p>
          </div>
        </div>
      );
    }

    // Default to Federation Peers
    return <FederationPeers onShowToast={showToast} />;
  };

  const activeItemId = getActiveItemId();

  return (
    <div className="flex flex-col h-full">
      {/* Header with back button */}
      <div className="flex items-center space-x-4 mb-6">
        <button
          onClick={() => navigate('/')}
          className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800
                     text-gray-500 dark:text-gray-400 transition-colors"
          title="Back to Dashboard"
        >
          <ArrowLeftIcon className="h-5 w-5" />
        </button>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
          Settings
        </h1>
      </div>

      {/* Main content area with sidebar */}
      <div className="flex flex-1 gap-6 min-h-0">
        {/* Sidebar */}
        <div className="w-64 flex-shrink-0">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-4">
            <nav className="space-y-1">
              {visibleCategories.map((category) => (
                <div key={category.id}>
                  {/* Category header */}
                  <button
                    onClick={() => !category.disabled && toggleCategory(category.id)}
                    disabled={category.disabled}
                    className={`w-full flex items-center justify-between px-3 py-2 text-sm font-medium rounded-lg transition-colors ${
                      category.disabled
                        ? 'text-gray-400 dark:text-gray-600 cursor-not-allowed'
                        : 'text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700'
                    }`}
                  >
                    <div className="flex items-center space-x-3">
                      <span className={category.disabled ? 'opacity-50' : ''}>
                        {category.icon}
                      </span>
                      <span>{category.label}</span>
                      {category.disabled && (
                        <span className="text-xs text-gray-400 dark:text-gray-500">
                          (Soon)
                        </span>
                      )}
                    </div>
                    {!category.disabled && (
                      expandedCategories.has(category.id) ? (
                        <ChevronDownIcon className="h-4 w-4" />
                      ) : (
                        <ChevronRightIcon className="h-4 w-4" />
                      )
                    )}
                  </button>

                  {/* Category items */}
                  {!category.disabled && expandedCategories.has(category.id) && (
                    <div className="ml-8 mt-1 space-y-1">
                      {category.items.map((item) => (
                        <button
                          key={item.id}
                          onClick={() => navigate(item.path)}
                          className={`w-full text-left px-3 py-2 text-sm rounded-lg transition-colors ${
                            activeItemId === item.id
                              ? 'bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300 font-medium'
                              : 'text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700'
                          }`}
                        >
                          {item.label}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </nav>
          </div>
        </div>

        {/* Content area */}
        <div className="flex-1 min-w-0">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6 h-full overflow-y-auto">
            {renderContent()}
          </div>
        </div>
      </div>

      {/* Toast notification */}
      {toast.show && (
        <div
          className={`fixed bottom-4 right-4 px-4 py-3 rounded-lg shadow-lg transform transition-all duration-300 animate-slide-in-top ${
            toast.type === 'success'
              ? 'bg-green-500 text-white'
              : toast.type === 'error'
              ? 'bg-red-500 text-white'
              : 'bg-blue-500 text-white'
          }`}
        >
          {toast.message}
        </div>
      )}
    </div>
  );
};

export default SettingsPage;
