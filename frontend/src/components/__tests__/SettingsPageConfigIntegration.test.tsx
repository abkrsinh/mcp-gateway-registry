import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import SettingsPage from '../../pages/SettingsPage';

// Mock auth context
jest.mock('../../contexts/AuthContext', () => ({
  useAuth: jest.fn(),
}));
import { useAuth } from '../../contexts/AuthContext';

// Mock child components to avoid deep rendering
jest.mock('../../pages/AuditLogsPage', () => () => <div>AuditLogsPage</div>);
jest.mock('../FederationPeers', () => () => <div>FederationPeers</div>);
jest.mock('../FederationPeerForm', () => () => <div>FederationPeerForm</div>);
jest.mock('../ConfigPanel', () => () => <div data-testid="config-panel-mock">ConfigPanel</div>);

describe('SettingsPage - System Config category', () => {
  test('shows System Config category for admin users', () => {
    (useAuth as jest.Mock).mockReturnValue({
      user: { username: 'admin', is_admin: true },
      loading: false,
    });

    render(
      <MemoryRouter initialEntries={['/settings']}>
        <SettingsPage />
      </MemoryRouter>
    );

    expect(screen.getByText('System Config')).toBeInTheDocument();
  });

  test('hides System Config category for non-admin users', () => {
    (useAuth as jest.Mock).mockReturnValue({
      user: { username: 'viewer', is_admin: false },
      loading: false,
    });

    render(
      <MemoryRouter initialEntries={['/settings']}>
        <SettingsPage />
      </MemoryRouter>
    );

    expect(screen.queryByText('System Config')).not.toBeInTheDocument();
  });
});
