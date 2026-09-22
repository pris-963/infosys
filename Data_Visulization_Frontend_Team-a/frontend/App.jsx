import React, { useState, useEffect } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import LandingPage from './pages/LandingPage';
import LoginPage from './pages/LoginPage';
import SignupPage from './pages/SignupPage';
import DashboardPage from './pages/DashboardPage';
import 'bootstrap/dist/css/bootstrap.min.css';

function AppContent() {
  const [currentRoute, setCurrentRoute] = useState('landing');
  const [theme, setTheme] = useState(() => localStorage.getItem('appTheme') || 'dark');
  const { user } = useAuth();

  useEffect(() => {
    if (currentRoute === 'dashboard' && theme === 'light') {
      document.documentElement.classList.add('light-theme');
    } else {
      document.documentElement.classList.remove('light-theme');
    }
    localStorage.setItem('appTheme', theme);
  }, [theme, currentRoute]);

  const toggleTheme = () => {
    setTheme(prev => (prev === 'dark' ? 'light' : 'dark'));
  };

  // Route Guard verification helper
  const handleNavigation = (route) => {
    if (route === 'dashboard') {
      const sessionUser = localStorage.getItem('currentUser');
      if (!sessionUser && !user) {
        setCurrentRoute('login');
        return;
      }
    }
    setCurrentRoute(route);
  };

  return (
    <>
      {currentRoute === 'landing' && (
        <LandingPage 
          onNavigate={handleNavigation} 
        />
      )}
      {currentRoute === 'login' && (
        <LoginPage 
          onNavigate={handleNavigation} 
          theme={theme}
        />
      )}
      {currentRoute === 'signup' && (
        <SignupPage 
          onNavigate={handleNavigation} 
          theme={theme}
        />
      )}
      {currentRoute === 'dashboard' && (
        <DashboardPage 
          onNavigate={handleNavigation} 
          theme={theme}
          toggleTheme={toggleTheme}
        />
      )}
    </>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}
