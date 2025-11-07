/**
 * Organization Switcher Component (Week 4: RBAC)
 *
 * Dropdown to switch between user's organizations
 */

import { useState } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Building2, Check, ChevronDown, LogOut, Settings, User } from 'lucide-react';
import { Badge } from '@/components/ui/badge';

export const OrganizationSwitcher = () => {
  const { user, organizations, switchOrganization, logout } = useAuth();
  const [isOpen, setIsOpen] = useState(false);

  if (!user) return null;

  const handleSwitchOrg = async (orgId: string) => {
    if (orgId === user.organization_id) return;
    await switchOrganization(orgId);
    setIsOpen(false);
  };

  const getRoleBadge = (role: string) => {
    const variants: Record<string, string> = {
      admin: 'bg-purple-500/20 text-purple-700 border-purple-300',
      analyst: 'bg-blue-500/20 text-blue-700 border-blue-300',
      viewer: 'bg-gray-500/20 text-gray-700 border-gray-300',
    };

    return (
      <Badge variant="outline" className={`text-xs ${variants[role] || ''}`}>
        {role.charAt(0).toUpperCase() + role.slice(1)}
      </Badge>
    );
  };

  return (
    <DropdownMenu open={isOpen} onOpenChange={setIsOpen}>
      <DropdownMenuTrigger asChild>
        <Button
          variant="outline"
          className="flex items-center gap-2 min-w-[200px] justify-between"
        >
          <div className="flex items-center gap-2">
            <Building2 className="h-4 w-4" />
            <span className="truncate max-w-[120px]">{user.organization_name}</span>
          </div>
          <ChevronDown className="h-4 w-4 opacity-50" />
        </Button>
      </DropdownMenuTrigger>

      <DropdownMenuContent align="end" className="w-[280px]">
        <DropdownMenuLabel className="flex items-center justify-between">
          <span>Organizations</span>
          {user.is_superuser && (
            <Badge variant="destructive" className="text-xs">
              Superuser
            </Badge>
          )}
        </DropdownMenuLabel>

        <DropdownMenuSeparator />

        <div className="max-h-[300px] overflow-y-auto">
          {organizations.length > 0 ? (
            organizations.map((org) => (
              <DropdownMenuItem
                key={org.organization_id}
                onClick={() => handleSwitchOrg(org.organization_id)}
                className="cursor-pointer flex items-center justify-between py-2"
              >
                <div className="flex flex-col gap-1 flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    {org.organization_id === user.organization_id && (
                      <Check className="h-4 w-4 text-primary flex-shrink-0" />
                    )}
                    <span className="font-medium truncate">{org.name}</span>
                  </div>
                  <div className="flex items-center gap-2 ml-6">
                    {getRoleBadge(org.role)}
                    <span className="text-xs text-muted-foreground truncate">
                      {org.tier}
                    </span>
                  </div>
                </div>
              </DropdownMenuItem>
            ))
          ) : (
            <div className="p-4 text-center text-sm text-muted-foreground">
              No other organizations
            </div>
          )}
        </div>

        <DropdownMenuSeparator />

        <DropdownMenuItem className="flex items-center gap-2">
          <User className="h-4 w-4" />
          <div className="flex flex-col flex-1 min-w-0">
            <span className="text-sm font-medium truncate">{user.username}</span>
            <span className="text-xs text-muted-foreground truncate">{user.email}</span>
          </div>
        </DropdownMenuItem>

        <DropdownMenuItem className="flex items-center gap-2 cursor-pointer">
          <Settings className="h-4 w-4" />
          <span>Account Settings</span>
        </DropdownMenuItem>

        <DropdownMenuSeparator />

        <DropdownMenuItem
          onClick={logout}
          className="cursor-pointer text-destructive focus:text-destructive flex items-center gap-2"
        >
          <LogOut className="h-4 w-4" />
          <span>Logout</span>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
};
