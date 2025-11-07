"use client";

import { useState, useEffect } from "react";
import { User, Loader2, UserPlus } from "lucide-react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

interface AssigneeSelectorProps {
  findingId: string;
  currentAssignee?: string | null;
  onChange?: (newAssignee: string | null) => void;
  disabled?: boolean;
  size?: "sm" | "md" | "lg";
}

// Mock team members - in production, this would come from an API
const TEAM_MEMBERS = [
  { id: "unassigned", name: "Unassigned", email: null, color: "bg-gray-400" },
  { id: "alice", name: "Alice Chen", email: "alice@company.com", color: "bg-blue-500" },
  { id: "bob", name: "Bob Smith", email: "bob@company.com", color: "bg-green-500" },
  { id: "carol", name: "Carol Davis", email: "carol@company.com", color: "bg-purple-500" },
  { id: "david", name: "David Lee", email: "david@company.com", color: "bg-orange-500" },
];

const getInitials = (name: string) => {
  return name
    .split(" ")
    .map((n) => n[0])
    .join("")
    .toUpperCase()
    .slice(0, 2);
};

export const AssigneeSelector = ({
  findingId,
  currentAssignee = null,
  onChange,
  disabled = false,
  size = "md",
}: AssigneeSelectorProps) => {
  const [isUpdating, setIsUpdating] = useState(false);
  const [assignee, setAssignee] = useState<string | null>(currentAssignee);

  const handleAssigneeChange = async (newAssigneeId: string) => {
    if (newAssigneeId === assignee) return;

    setIsUpdating(true);

    try {
      const member = TEAM_MEMBERS.find((m) => m.id === newAssigneeId);
      const assignedTo = newAssigneeId === "unassigned" ? null : member?.email || null;

      // Call API to update assignee
      if (assignedTo) {
        const response = await fetch(`http://localhost:8000/api/finding/${findingId}/assign`, {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
            // TODO: Add JWT token from auth context
          },
          body: JSON.stringify({
            assigned_to: assignedTo,
          }),
        });

        if (!response.ok) {
          throw new Error(`Failed to assign finding: ${response.statusText}`);
        }
      }

      setAssignee(newAssigneeId);

      if (onChange) {
        onChange(assignedTo);
      }

      if (assignedTo) {
        toast.success(`Assigned to ${member?.name}`);
      } else {
        toast.success(`Unassigned finding`);
      }
    } catch (error) {
      console.error("Failed to update assignee:", error);
      toast.error("Failed to update assignee. Please try again.");
    } finally {
      setIsUpdating(false);
    }
  };

  const currentMember = TEAM_MEMBERS.find((m) => m.id === assignee) || TEAM_MEMBERS[0];

  return (
    <div className="relative">
      <Select
        value={assignee || "unassigned"}
        onValueChange={handleAssigneeChange}
        disabled={disabled || isUpdating}
      >
        <SelectTrigger
          className={cn(
            "w-full",
            size === "sm" && "h-7 text-xs",
            size === "md" && "h-9 text-sm",
            size === "lg" && "h-10 text-base",
            isUpdating && "opacity-50 cursor-not-allowed"
          )}
        >
          <div className="flex items-center gap-2">
            {isUpdating ? (
              <Loader2 className="h-3 w-3 animate-spin" />
            ) : (
              <Avatar className="h-5 w-5">
                <AvatarFallback className={cn("text-xs text-white", currentMember.color)}>
                  {currentMember.id === "unassigned" ? (
                    <UserPlus className="h-3 w-3" />
                  ) : (
                    getInitials(currentMember.name)
                  )}
                </AvatarFallback>
              </Avatar>
            )}
            <SelectValue>
              <span className="text-sm">{currentMember.name}</span>
            </SelectValue>
          </div>
        </SelectTrigger>
        <SelectContent>
          {TEAM_MEMBERS.map((member) => (
            <SelectItem key={member.id} value={member.id} className="cursor-pointer">
              <div className="flex items-center gap-3">
                <Avatar className="h-6 w-6">
                  <AvatarFallback className={cn("text-xs text-white", member.color)}>
                    {member.id === "unassigned" ? (
                      <UserPlus className="h-3 w-3" />
                    ) : (
                      getInitials(member.name)
                    )}
                  </AvatarFallback>
                </Avatar>
                <div>
                  <div className="font-medium">{member.name}</div>
                  {member.email && (
                    <div className="text-xs text-muted-foreground">{member.email}</div>
                  )}
                </div>
              </div>
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
};

/**
 * Compact assignee avatar for displaying in tables/lists
 */
export const AssigneeAvatar = ({
  assignee,
  size = "default",
  showTooltip = true,
}: {
  assignee: string | null;
  size?: "sm" | "default" | "lg";
  showTooltip?: boolean;
}) => {
  const member = TEAM_MEMBERS.find((m) => m.email === assignee) || TEAM_MEMBERS[0];

  const sizeClass = size === "sm" ? "h-5 w-5" : size === "lg" ? "h-8 w-8" : "h-6 w-6";
  const textSize = size === "sm" ? "text-xs" : size === "lg" ? "text-sm" : "text-xs";

  return (
    <div className="relative group">
      <Avatar className={sizeClass}>
        <AvatarFallback className={cn(textSize, "text-white", member.color)}>
          {member.id === "unassigned" ? (
            <UserPlus className={cn(size === "sm" ? "h-2.5 w-2.5" : "h-3 w-3")} />
          ) : (
            getInitials(member.name)
          )}
        </AvatarFallback>
      </Avatar>
      {showTooltip && (
        <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-2 py-1 bg-gray-900 text-white text-xs rounded opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none whitespace-nowrap z-10">
          {member.name}
          {member.email && <div className="text-xs text-gray-400">{member.email}</div>}
        </div>
      )}
    </div>
  );
};

/**
 * Export team members for use in filters
 */
export const getTeamMembers = () => TEAM_MEMBERS;
