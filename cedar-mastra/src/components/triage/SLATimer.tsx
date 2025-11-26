"use client";

import { useState, useEffect } from "react";
import { Clock, AlertTriangle, CheckCircle2, AlertCircle } from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";

interface SLATimerProps {
  slaDeadline: string | null; // ISO 8601 timestamp
  status?: string;
  size?: "sm" | "md" | "lg";
  showIcon?: boolean;
  showLabel?: boolean;
}

const calculateTimeRemaining = (deadline: string | null): {
  days: number;
  hours: number;
  minutes: number;
  totalHours: number;
  isOverdue: boolean;
  isExpired: boolean;
} => {
  if (!deadline) {
    return {
      days: 0,
      hours: 0,
      minutes: 0,
      totalHours: 0,
      isOverdue: false,
      isExpired: false,
    };
  }

  const now = new Date();
  const deadlineDate = new Date(deadline);
  const diffMs = deadlineDate.getTime() - now.getTime();

  const isOverdue = diffMs < 0;
  const isExpired = diffMs < 0;

  const absDiffMs = Math.abs(diffMs);
  const days = Math.floor(absDiffMs / (1000 * 60 * 60 * 24));
  const hours = Math.floor((absDiffMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
  const minutes = Math.floor((absDiffMs % (1000 * 60 * 60)) / (1000 * 60));
  const totalHours = Math.floor(absDiffMs / (1000 * 60 * 60));

  return {
    days,
    hours,
    minutes,
    totalHours,
    isOverdue,
    isExpired,
  };
};

const formatTimeRemaining = (time: ReturnType<typeof calculateTimeRemaining>): string => {
  if (!time) return "No SLA";

  if (time.isOverdue) {
    if (time.days > 0) {
      return `${time.days}d ${time.hours}h overdue`;
    } else if (time.hours > 0) {
      return `${time.hours}h ${time.minutes}m overdue`;
    } else {
      return `${time.minutes}m overdue`;
    }
  }

  if (time.days > 7) {
    return `${time.days} days`;
  } else if (time.days > 0) {
    return `${time.days}d ${time.hours}h`;
  } else if (time.hours > 0) {
    return `${time.hours}h ${time.minutes}m`;
  } else {
    return `${time.minutes}m`;
  }
};

const getSLAColor = (
  time: ReturnType<typeof calculateTimeRemaining>,
  status?: string
): {
  bgColor: string;
  textColor: string;
  borderColor: string;
  icon: React.ReactNode;
} => {
  // If status is resolved/closed, show green
  if (status === "resolved" || status === "false_positive" || status === "risk_accepted") {
    return {
      bgColor: "bg-green-50",
      textColor: "text-green-700",
      borderColor: "border-green-200",
      icon: <CheckCircle2 className="h-3 w-3" />,
    };
  }

  if (!time || time.totalHours === 0) {
    return {
      bgColor: "bg-gray-50",
      textColor: "text-gray-600",
      borderColor: "border-gray-200",
      icon: <Clock className="h-3 w-3" />,
    };
  }

  // Overdue
  if (time.isOverdue) {
    return {
      bgColor: "bg-red-50",
      textColor: "text-red-700",
      borderColor: "border-red-300",
      icon: <AlertCircle className="h-3 w-3" />,
    };
  }

  // Less than 24 hours
  if (time.totalHours < 24) {
    return {
      bgColor: "bg-orange-50",
      textColor: "text-orange-700",
      borderColor: "border-orange-300",
      icon: <AlertTriangle className="h-3 w-3" />,
    };
  }

  // Less than 3 days
  if (time.days < 3) {
    return {
      bgColor: "bg-yellow-50",
      textColor: "text-yellow-700",
      borderColor: "border-yellow-300",
      icon: <Clock className="h-3 w-3" />,
    };
  }

  // More than 3 days
  return {
    bgColor: "bg-blue-50",
    textColor: "text-blue-700",
    borderColor: "border-blue-200",
    icon: <Clock className="h-3 w-3" />,
  };
};

export const SLATimer = ({
  slaDeadline,
  status,
  size = "md",
  showIcon = true,
  showLabel = true,
}: SLATimerProps) => {
  const [timeRemaining, setTimeRemaining] = useState(() =>
    calculateTimeRemaining(slaDeadline)
  );

  useEffect(() => {
    if (!slaDeadline) return;

    // Update every minute
    const interval = setInterval(() => {
      setTimeRemaining(calculateTimeRemaining(slaDeadline));
    }, 60000);

    // Initial update
    setTimeRemaining(calculateTimeRemaining(slaDeadline));

    return () => clearInterval(interval);
  }, [slaDeadline]);

  if (!slaDeadline) {
    return (
      <Badge
        variant="outline"
        className={cn(
          "border bg-gray-50 text-gray-600 border-gray-200",
          size === "sm" && "text-xs px-2 py-0",
          size === "lg" && "text-base px-3 py-1"
        )}
      >
        <div className="flex items-center gap-1.5">
          {showIcon && <Clock className="h-3 w-3" />}
          <span>No SLA</span>
        </div>
      </Badge>
    );
  }

  const colorConfig = getSLAColor(timeRemaining, status);
  const formattedTime = formatTimeRemaining(timeRemaining);

  return (
    <Badge
      variant="outline"
      className={cn(
        "border",
        colorConfig.bgColor,
        colorConfig.textColor,
        colorConfig.borderColor,
        size === "sm" && "text-xs px-2 py-0",
        size === "lg" && "text-base px-3 py-1",
        timeRemaining.isOverdue && "animate-pulse"
      )}
    >
      <div className="flex items-center gap-1.5">
        {showIcon && colorConfig.icon}
        {showLabel && <span className="text-xs font-medium">SLA:</span>}
        <span className="font-medium">{formattedTime}</span>
      </div>
    </Badge>
  );
};

/**
 * Compact SLA indicator for tables/lists
 */
export const SLAIndicator = ({
  slaDeadline,
  status,
}: {
  slaDeadline: string | null;
  status?: string;
}) => {
  const timeRemaining = calculateTimeRemaining(slaDeadline);
  const colorConfig = getSLAColor(timeRemaining, status);

  if (!slaDeadline) {
    return (
      <div className="flex items-center gap-1 text-gray-400">
        <Clock className="h-3 w-3" />
        <span className="text-xs">-</span>
      </div>
    );
  }

  return (
    <div className={cn("flex items-center gap-1", colorConfig.textColor)}>
      {colorConfig.icon}
      <span className="text-xs font-medium">{formatTimeRemaining(timeRemaining)}</span>
    </div>
  );
};

/**
 * Detailed SLA breakdown for details view
 */
export const SLADetails = ({
  slaDeadline,
  sla Days,
  status,
}: {
  slaDeadline: string | null;
  slaDays?: number;
  status?: string;
}) => {
  const timeRemaining = calculateTimeRemaining(slaDeadline);
  const colorConfig = getSLAColor(timeRemaining, status);

  if (!slaDeadline) {
    return (
      <div className="text-sm text-muted-foreground">
        No SLA deadline set
      </div>
    );
  }

  const deadlineDate = new Date(slaDeadline);

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <SLATimer
          slaDeadline={slaDeadline}
          status={status}
          size="md"
          showIcon={true}
          showLabel={true}
        />
      </div>
      <div className="text-xs text-muted-foreground space-y-1">
        <div>Deadline: {deadlineDate.toLocaleString()}</div>
        {slaDays && <div>SLA Policy: {slaDays} days</div>}
        {timeRemaining.isOverdue && (
          <div className={colorConfig.textColor}>
            ⚠️ This finding is {timeRemaining.days}d {timeRemaining.hours}h overdue
          </div>
        )}
      </div>
    </div>
  );
};
