/**
 * Protected Route Component for RBAC
 *
 * Wraps routes to enforce authentication and role-based access control.
 */

import React, { useEffect } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '@/contexts/AuthContext';
import { Loader2 } from 'lucide-react';

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredRole?: 'admin' | 'analyst' | 'viewer';
  requireAuth?: boolean;
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({
  children,
  requiredRole,
  requireAuth = true,
}) => {
  const { user, isLoading } = useAuth();
  const location = useLocation();

  // Show loading spinner while checking auth status
  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  // Redirect to login if authentication required but user not logged in
  if (requireAuth && !user) {
    return <Navigate to="/auth" state={{ from: location }} replace />;
  }

  // Check role-based access
  if (requiredRole && user) {
    const roleHierarchy: Record<string, number> = {
      viewer: 1,
      analyst: 2,
      admin: 3,
    };

    const userRoleLevel = roleHierarchy[user.role] || 0;
    const requiredRoleLevel = roleHierarchy[requiredRole] || 0;

    // Deny access if user role is below required role
    if (userRoleLevel < requiredRoleLevel) {
      return (
        <div className="flex flex-col items-center justify-center min-h-screen p-8">
          <div className="max-w-md text-center">
            <h1 className="text-4xl font-bold mb-4">Access Denied</h1>
            <p className="text-muted-foreground mb-6">
              You don't have permission to access this page. Required role: {requiredRole}
            </p>
            <p className="text-sm text-muted-foreground">
              Your current role: <strong>{user.role}</strong>
            </p>
            <a href="/dashboard" className="text-primary hover:underline mt-4 inline-block">
              Return to Dashboard
            </a>
          </div>
        </div>
      );
    }
  }

  // Render children if all checks pass
  return <>{children}</>;
};

/**
 * Hook to check if user has required role
 */
export const useRequiredRole = (requiredRole: 'admin' | 'analyst' | 'viewer'): boolean => {
  const { user } = useAuth();

  if (!user) return false;

  const roleHierarchy: Record<string, number> = {
    viewer: 1,
    analyst: 2,
    admin: 3,
  };

  const userRoleLevel = roleHierarchy[user.role] || 0;
  const requiredRoleLevel = roleHierarchy[requiredRole] || 0;

  return userRoleLevel >= requiredRoleLevel;
};

/**
 * Hook to check if user is authenticated
 */
export const useIsAuthenticated = (): boolean => {
  const { user } = useAuth();
  return !!user;
};
