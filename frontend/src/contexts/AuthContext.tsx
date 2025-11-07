/**
 * Authentication Context for RBAC (Week 4)
 *
 * Manages JWT tokens, user sessions, and organization context.
 */

import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import { useToast } from '@/hooks/use-toast';

interface User {
  user_id: string;
  username: string;
  email: string;
  organization_id: string;
  organization_name: string;
  organization_slug: string;
  role: 'admin' | 'analyst' | 'viewer';
  is_superuser: boolean;
}

interface Organization {
  organization_id: string;
  name: string;
  slug: string;
  tier: string;
  role: string;
  joined_at: string;
}

interface AuthContextType {
  user: User | null;
  organizations: Organization[];
  token: string | null;
  isLoading: boolean;
  login: (email: string, password: string, organizationId?: string) => Promise<void>;
  register: (email: string, password: string, username: string, organizationName: string) => Promise<void>;
  logout: () => void;
  switchOrganization: (organizationId: string) => Promise<void>;
  refreshUserData: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [user, setUser] = useState<User | null>(null);
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const { toast } = useToast();
  const navigate = useNavigate();

  const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

  // Load token from localStorage on mount
  useEffect(() => {
    const storedToken = localStorage.getItem('venti_auth_token');
    const storedUser = localStorage.getItem('venti_user');

    if (storedToken && storedUser) {
      setToken(storedToken);
      setUser(JSON.parse(storedUser));
      refreshUserData();
    } else {
      setIsLoading(false);
    }
  }, []);

  const refreshUserData = async () => {
    const storedToken = localStorage.getItem('venti_auth_token');
    if (!storedToken) {
      setIsLoading(false);
      return;
    }

    try {
      // Fetch user's organizations
      const response = await fetch(`${API_BASE}/api/user/organizations`, {
        headers: {
          'Authorization': `Bearer ${storedToken}`,
        },
      });

      if (response.ok) {
        const orgs = await response.json();
        setOrganizations(orgs);
      }
    } catch (error) {
      console.error('Failed to refresh user data:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const login = async (email: string, password: string, organizationId?: string) => {
    setIsLoading(true);
    try {
      const response = await fetch(`${API_BASE}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email,
          password,
          organization_id: organizationId,
        }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Login failed');
      }

      const data = await response.json();

      // Store token and user data
      localStorage.setItem('venti_auth_token', data.access_token);
      localStorage.setItem('venti_user', JSON.stringify(data.user));

      setToken(data.access_token);
      setUser(data.user);
      setOrganizations(data.user.organizations || []);

      toast({
        title: 'Login successful',
        description: `Welcome back, ${data.user.username}!`,
      });

      navigate('/dashboard');
    } catch (error: any) {
      toast({
        title: 'Login failed',
        description: error.message,
        variant: 'destructive',
      });
      throw error;
    } finally {
      setIsLoading(false);
    }
  };

  const register = async (
    email: string,
    password: string,
    username: string,
    organizationName: string
  ) => {
    setIsLoading(true);
    try {
      const response = await fetch(`${API_BASE}/api/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email,
          password,
          username,
          full_name: username,
          organization_name: organizationName,
        }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Registration failed');
      }

      const data = await response.json();

      // Auto-login after registration
      localStorage.setItem('venti_auth_token', data.access_token);
      localStorage.setItem('venti_user', JSON.stringify(data.user));

      setToken(data.access_token);
      setUser(data.user);
      setOrganizations([data.organization]);

      toast({
        title: 'Account created successfully',
        description: `Welcome to VentiAPI, ${username}!`,
      });

      navigate('/scanner');
    } catch (error: any) {
      toast({
        title: 'Registration failed',
        description: error.message,
        variant: 'destructive',
      });
      throw error;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = () => {
    localStorage.removeItem('venti_auth_token');
    localStorage.removeItem('venti_user');
    setToken(null);
    setUser(null);
    setOrganizations([]);

    toast({
      title: 'Logged out',
      description: 'You have been logged out successfully',
    });

    navigate('/auth');
  };

  const switchOrganization = async (organizationId: string) => {
    if (!token) return;

    setIsLoading(true);
    try {
      const response = await fetch(`${API_BASE}/api/user/switch-organization`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          organization_id: organizationId,
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to switch organization');
      }

      const data = await response.json();

      // Update token and user data
      localStorage.setItem('venti_auth_token', data.access_token);
      localStorage.setItem('venti_user', JSON.stringify(data.user));

      setToken(data.access_token);
      setUser(data.user);

      toast({
        title: 'Organization switched',
        description: `Now viewing ${data.user.organization_name}`,
      });

      // Reload current page to refresh data
      window.location.reload();
    } catch (error: any) {
      toast({
        title: 'Failed to switch organization',
        description: error.message,
        variant: 'destructive',
      });
    } finally {
      setIsLoading(false);
    }
  };

  const value = {
    user,
    organizations,
    token,
    isLoading,
    login,
    register,
    logout,
    switchOrganization,
    refreshUserData,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
