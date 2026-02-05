import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { AuthProvider } from './contexts/AuthContext';
import { ThemeProvider } from './contexts/ThemeContext';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import TokenGeneration from './pages/TokenGeneration';
import RegisterPage from './pages/RegisterPage';
import Login from './pages/Login';
import OAuthCallback from './pages/OAuthCallback';
import ProtectedRoute from './components/ProtectedRoute';
import SettingsPage from './pages/SettingsPage';

// Get basename from <base> tag for path-based routing (e.g., /registry)
const getBasename = () => {
  const baseTag = document.querySelector('base');
  if (baseTag && baseTag.href) {
    const url = new URL(baseTag.href);
    return url.pathname.replace(/\/$/, '') || '/';
  }
  return '/';
};

function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <Router basename={getBasename()}>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/auth/callback" element={<OAuthCallback />} />
            <Route path="/" element={
              <ProtectedRoute>
                <Layout>
                  <Dashboard />
                </Layout>
              </ProtectedRoute>
            } />
            <Route path="/generate-token" element={
              <ProtectedRoute>
                <Layout>
                  <TokenGeneration />
                </Layout>
              </ProtectedRoute>
            } />
            <Route path="/servers/register" element={
              <ProtectedRoute>
                <Layout>
                  <RegisterPage />
                </Layout>
              </ProtectedRoute>
            } />
            <Route path="/settings/*" element={
              <ProtectedRoute>
                <Layout>
                  <SettingsPage />
                </Layout>
              </ProtectedRoute>
            } />
          </Routes>
        </Router>
      </AuthProvider>
    </ThemeProvider>
  );
}

export default App; 