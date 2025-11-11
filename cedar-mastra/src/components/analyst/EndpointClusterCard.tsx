"use client";

import { AlertTriangle, Code2, TrendingUp } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { getSeverityColor } from "@/lib/utils/severity";

export interface EndpointCluster {
  endpoint: string;
  method: string;
  vuln_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  max_severity: string;
  vuln_types: string[];
  findings: Array<{
    id: string;
    title: string;
    severity: string;
    rule: string;
    description: string;
    score: number;
    method: string;
    endpoint: string;
    triage_status: string;
    assignee: string | null;
  }>;
}

interface EndpointClusterCardProps {
  cluster: EndpointCluster;
  onClick: () => void;
}

export const EndpointClusterCard = ({ cluster, onClick }: EndpointClusterCardProps) => {
  const severityColor = getSeverityColor(cluster.max_severity as any);

  // Build severity breakdown text
  const severityBreakdown: string[] = [];
  if (cluster.critical_count > 0) severityBreakdown.push(`${cluster.critical_count} Critical`);
  if (cluster.high_count > 0) severityBreakdown.push(`${cluster.high_count} High`);
  if (cluster.medium_count > 0) severityBreakdown.push(`${cluster.medium_count} Medium`);
  if (cluster.low_count > 0) severityBreakdown.push(`${cluster.low_count} Low`);
  if (cluster.info_count > 0) severityBreakdown.push(`${cluster.info_count} Info`);

  return (
    <Card
      className={cn(
        "cursor-pointer transition-all hover:shadow-lg border-l-4",
        severityColor.border
      )}
      onClick={onClick}
    >
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-1">
              <Code2 className="h-4 w-4 text-muted-foreground" />
              <Badge variant="outline" className="font-mono text-xs">
                {cluster.method}
              </Badge>
              <span className="font-mono text-sm font-medium">{cluster.endpoint}</span>
            </div>
          </div>
          <Badge variant="destructive" className={cn("ml-2", severityColor.badge)}>
            {cluster.max_severity}
          </Badge>
        </div>
      </CardHeader>

      <CardContent className="space-y-3">
        {/* Vulnerability Count */}
        <div className="flex items-center gap-2">
          <AlertTriangle className={cn("h-4 w-4", severityColor.text)} />
          <span className="text-2xl font-bold">{cluster.vuln_count}</span>
          <span className="text-sm text-muted-foreground">
            {cluster.vuln_count === 1 ? "vulnerability" : "vulnerabilities"}
          </span>
        </div>

        {/* Severity Breakdown */}
        <div className="text-sm text-muted-foreground">
          {severityBreakdown.join(" • ")}
        </div>

        {/* Vulnerability Types */}
        <div className="flex flex-wrap gap-1.5">
          {cluster.vuln_types.slice(0, 3).map((type, index) => (
            <Badge key={index} variant="secondary" className="text-xs">
              {type}
            </Badge>
          ))}
          {cluster.vuln_types.length > 3 && (
            <Badge variant="secondary" className="text-xs">
              +{cluster.vuln_types.length - 3} more
            </Badge>
          )}
        </div>

        {/* Blast Radius Indicator */}
        <div className="flex items-center gap-2 pt-2 border-t text-xs text-muted-foreground">
          <TrendingUp className="h-3 w-3" />
          <span>
            Blast Radius: {cluster.vuln_count} related {cluster.vuln_count === 1 ? "finding" : "findings"}
          </span>
        </div>
      </CardContent>
    </Card>
  );
};
