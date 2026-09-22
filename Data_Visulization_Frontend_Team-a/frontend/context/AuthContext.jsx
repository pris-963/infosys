import React, { createContext, useContext, useState, useEffect } from 'react';
import { loginUser as apiLogin, signupUser as apiSignup, logoutUser as apiLogout } from '../services/api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try {
      const saved = localStorage.getItem('currentUser');
      return saved ? JSON.parse(saved) : null;
    } catch (e) {
      return null;
    }
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (user) {
      localStorage.setItem('currentUser', JSON.stringify(user));
    } else {
      localStorage.removeItem('currentUser');
    }
  }, [user]);

  const login = async (identity, password) => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiLogin(identity, password);
      const userData = {
        username: data.username || identity,
        email: data.email || (identity.includes('@') ? identity : `${identity}@infosys.com`),
        role: data.role || (identity.toLowerCase() === 'admin' ? 'Administrator' : 'SOC Analyst'),
        loginTime: new Date().toISOString()
      };
      setUser(userData);
      setLoading(false);
      return { success: true, user: userData };
    } catch (err) {
      setLoading(false);
      setError(err.message || 'Login failed.');
      throw err;
    }
  };

  const signup = async (username, email, password) => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiSignup(username, email, password);
      setLoading(false);
      return res;
    } catch (err) {
      setLoading(false);
      setError(err.message || 'Signup failed.');
      throw err;
    }
  };

  const logout = async () => {
    try {
      await apiLogout();
    } catch (e) {
      console.warn('Logout API error:', e);
    }
    setUser(null);
    localStorage.removeItem('currentUser');
  };

  return (
    <AuthContext.Provider value={{ user, loading, error, login, signup, logout, isAuthenticated: !!user }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

export default AuthContext;
