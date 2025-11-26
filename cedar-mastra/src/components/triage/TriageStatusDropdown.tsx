"use client";

import { useState } from "react";
import { Check, Loader2 } from "lucide-react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

export type TriageStatus =
  | "new"
  | "validated"
  | "false_positive"
  | "duplicate"
  | "risk_accepted"
  | "in_progress"
  | "resolved"
  | "wont_fix";

interface TriageStatusDropdownProps {
  findingId: string;
  currentStatus?: TriageStatus;
  onChange?: (newStatus: TriageStatus) => void;
  disabled?: boolean;
  size?: "sm" | "md" | "lg";
}

const STATUS_CONFIG: Record<
  TriageStatus,
  { label: string; color: string; bgColor: string; description: string }
> = {
  new: {
    label: "New",
    color: "text-blue-600",
    bgColor: "bg-blue-50 border-blue-200",
    description: "Newly discovered, needs validation"
  },
  validated: {
    label: "Validated",
    color: "text-purple-600",
    bgColor: "bg-purple-50 border-purple-200",
    description: "Confirmed as real vulnerability"
  },
  false_positive: {
    label: "False Positive",
    color: "text-gray-600",
    bgColor: "bg-gray-50 border-gray-200",
    description: "Not a real vulnerability"
  },
  duplicate: {
    label: "Duplicate",
    color: "text-gray-600",
    bgColor: "bg-gray-50 border-gray-200",
    description: "Duplicate of another finding"
  },
  risk_accepted: {
    label: "Risk Accepted",
    color: "text-yellow-600",
    bgColor: "bg-yellow-50 border-yellow-200",
    description: "Risk acknowledged and accepted"
  },
  in_progress: {
    label: "In Progress",
    color: "text-orange-600",
    bgColor: "bg-orange-50 border-orange-200",
    description: "Being actively remediated"
  },
  resolved: {
    label: "Resolved",
    color: "text-green-600",
    bgColor: "bg-green-50 border-green-200",
    description: "Fixed and verified"
  },
  wont_fix: {
    label: "Won't Fix",
    color: "text-gray-600",
    bgColor: "bg-gray-50 border-gray-200",
    description: "Decided not to fix"
  },
};

export const TriageStatusDropdown = ({
  findingId,
  currentStatus = "new",
  onChange,
  disabled = false,
  size = "md",
}: TriageStatusDropdownProps) => {
  const [isUpdating, setIsUpdating] = useState(false);
  const [status, setStatus] = useState<TriageStatus>(currentStatus);

  const handleStatusChange = async (newStatus: TriageStatus) => {
    if (newStatus === status) return;

    setIsUpdating(true);

    try {
      // Call API to update status
      const response = await fetch(`http://localhost:8000/api/finding/${findingId}/status`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          // TODO: Add JWT token from auth context
        },
        body: JSON.stringify({
          new_status: newStatus,
          change_reason: `Status changed via UI`,
        }),
      });

      if (!response.ok) {
        throw new Error(`Failed to update status: ${response.statusText}`);
      }

      const data = await response.json();

      setStatus(newStatus);

      if (onChange) {
        onChange(newStatus);
      }

      toast.success(`Status updated to "${STATUS_CONFIG[newStatus].label}"`);
    } catch (error) {
      console.error("Failed to update triage status:", error);
      toast.error("Failed to update status. Please try again.");
    } finally {
      setIsUpdating(false);
    }
  };

  const config = STATUS_CONFIG[status];

  return (
    <div className="relative">
      <Select
        value={status}
        onValueChange={(value) => handleStatusChange(value as TriageStatus)}
        disabled={disabled || isUpdating}
      >
        <SelectTrigger
          className={cn(
            "w-full border",
            config.bgColor,
            size === "sm" && "h-7 text-xs",
            size === "md" && "h-9 text-sm",
            size === "lg" && "h-10 text-base",
            isUpdating && "opacity-50 cursor-not-allowed"
          )}
        >
          <div className="flex items-center gap-2">
            {isUpdating && <Loader2 className="h-3 w-3 animate-spin" />}
            <SelectValue>
              <span className={config.color}>{config.label}</span>
            </SelectValue>
          </div>
        </SelectTrigger>
        <SelectContent>
          {(Object.keys(STATUS_CONFIG) as TriageStatus[]).map((statusKey) => {
            const statusConfig = STATUS_CONFIG[statusKey];
            return (
              <SelectItem key={statusKey} value={statusKey} className="cursor-pointer">
                <div className="flex items-center justify-between w-full">
                  <div>
                    <div className={cn("font-medium", statusConfig.color)}>
                      {statusConfig.label}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      {statusConfig.description}
                    </div>
                  </div>
                  {status === statusKey && (
                    <Check className="h-4 w-4 ml-4 text-green-600" />
                  )}
                </div>
              </SelectItem>
            );
          })}
        </SelectContent>
      </Select>
    </div>
  );
};

/**
 * Status badge component for displaying status in tables/lists
 */
export const TriageStatusBadge = ({
  status,
  size = "default",
}: {
  status: TriageStatus;
  size?: "sm" | "default" | "lg";
}) => {
  const config = STATUS_CONFIG[status];

  return (
    <Badge
      variant="outline"
      className={cn(
        "border",
        config.bgColor,
        config.color,
        size === "sm" && "text-xs px-2 py-0",
        size === "lg" && "text-base px-3 py-1"
      )}
    >
      {config.label}
    </Badge>
  );
};

/**
 * Get status config for use in other components
 */
export const getStatusConfig = (status: TriageStatus) => {
  return STATUS_CONFIG[status];
};
