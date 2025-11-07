/**
 * Dashboard Page with RBAC Integration (Week 4)
 *
 * Features:
 * - Role-based UI controls
 * - Organization switcher in header
 * - Persona-based content (mapped from RBAC roles)
 */

import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Shield, ScanLine, FileSearch, Settings, Users } from "lucide-react";
import cyberBearLogo from "@/assets/cyber-bear-logo.png";
import { ScanConfigDialog } from "@/components/ScanConfigDialog";
import { OrganizationSwitcher } from "@/components/OrganizationSwitcher";
import { useAuth } from "@/contexts/AuthContext";
import { useRequiredRole } from "@/components/ProtectedRoute";
import { useState } from "react";

const Dashboard = () => {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [showScanDialog, setShowScanDialog] = useState(false);

  // Role-based permissions
  const canStartScans = useRequiredRole('analyst');
  const canManageSettings = useRequiredRole('admin');

  if (!user) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin w-12 h-12 border-4 border-primary border-t-transparent rounded-full mx-auto mb-4" />
          <p className="text-muted-foreground">Loading...</p>
        </div>
      </div>
    );
  }

  const getRoleTitle = () => {
    const titles = {
      admin: "Admin Dashboard",
      analyst: "Security Analyst Dashboard",
      viewer: "Viewer Dashboard",
    };
    return titles[user.role];
  };

  const getRoleContent = () => {
    const content = {
      admin: {
        title: "Organization Management",
        description: "Full control over organization settings, users, and security scans",
        features: [
          "Manage team members and permissions",
          "Configure organization settings",
          "Run security scans (including dangerous mode)",
          "View all scan results and analytics",
        ],
      },
      analyst: {
        title: "Security Analysis",
        description: "Comprehensive security analysis and vulnerability management",
        features: [
          "Run API security scans",
          "Triage and manage findings",
          "Generate security reports",
          "Track vulnerability remediation",
        ],
      },
      viewer: {
        title: "Security Overview",
        description: "Read-only access to security scan results and reports",
        features: [
          "View scan results",
          "Access security reports",
          "Monitor vulnerability trends",
          "Export compliance data",
        ],
      },
    };

    return content[user.role];
  };

  const roleContent = getRoleContent();

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b">
        <div className="container mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <img src={cyberBearLogo} alt="VentiAPI" className="w-10 h-10" />
            <h1 className="text-xl font-bold">VentiAPI</h1>
          </div>
          <div className="flex items-center gap-4">
            <OrganizationSwitcher />
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-6 py-8">
        <div className="mb-8">
          <h2 className="text-3xl font-bold mb-2">{getRoleTitle()}</h2>
          <p className="text-muted-foreground">
            Welcome back, {user.username} ({user.email})
          </p>
          <div className="mt-2 flex items-center gap-2">
            <span className="text-sm text-muted-foreground">Organization:</span>
            <span className="text-sm font-medium">{user.organization_name}</span>
            <span className="text-xs px-2 py-1 rounded bg-primary/10 text-primary font-medium">
              {user.role.toUpperCase()}
            </span>
          </div>
        </div>

        <div className="grid gap-6 md:grid-cols-2">
          {/* Welcome Card */}
          <Card className="md:col-span-2">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-primary" />
                {roleContent.title}
              </CardTitle>
              <CardDescription>{roleContent.description}</CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2">
                {roleContent.features.map((feature, index) => (
                  <li key={index} className="flex items-center gap-2">
                    <div className="w-1.5 h-1.5 rounded-full bg-primary" />
                    {feature}
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>

          {/* Start Scan Card - Only for Analyst and Admin */}
          {canStartScans && (
            <Card className="hover:shadow-lg transition-shadow cursor-pointer">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <ScanLine className="w-5 h-5 text-primary" />
                  Start Scan
                </CardTitle>
                <CardDescription>
                  Begin a new API security scan
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Button className="w-full" onClick={() => setShowScanDialog(true)}>
                  Start New Scan
                </Button>
              </CardContent>
            </Card>
          )}

          {/* View Results Card */}
          <Card className="hover:shadow-lg transition-shadow cursor-pointer">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FileSearch className="w-5 h-5 text-primary" />
                View Results
              </CardTitle>
              <CardDescription>
                Review previous scan results
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Button variant="outline" className="w-full" onClick={() => navigate("/scanner")}>
                View All Results
              </Button>
            </CardContent>
          </Card>

          {/* Team Management Card - Admin Only */}
          {canManageSettings && (
            <Card className="hover:shadow-lg transition-shadow cursor-pointer">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Users className="w-5 h-5 text-primary" />
                  Team Management
                </CardTitle>
                <CardDescription>
                  Manage team members and permissions
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Button variant="outline" className="w-full" disabled>
                  Coming Soon
                </Button>
              </CardContent>
            </Card>
          )}

          {/* Organization Settings Card - Admin Only */}
          {canManageSettings && (
            <Card className="hover:shadow-lg transition-shadow cursor-pointer">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Settings className="w-5 h-5 text-primary" />
                  Organization Settings
                </CardTitle>
                <CardDescription>
                  Configure organization preferences
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Button variant="outline" className="w-full" disabled>
                  Coming Soon
                </Button>
              </CardContent>
            </Card>
          )}
        </div>
      </main>

      <ScanConfigDialog open={showScanDialog} onOpenChange={setShowScanDialog} />
    </div>
  );
};

export default Dashboard;
