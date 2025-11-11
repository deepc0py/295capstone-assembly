"use client";

import { X, AlertTriangle, Code2, ChevronDown, ChevronUp } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import { getSeverityColor } from "@/lib/utils/severity";
import { EndpointCluster } from "./EndpointClusterCard";
import { Finding } from "@/types/finding";
import { useState } from "react";

interface EndpointClusterDrawerProps {
  cluster: EndpointCluster | null;
  onClose: () => void;
  onFindingClick: (finding: Finding) => void;
}

export const EndpointClusterDrawer = ({
  cluster,
  onClose,
  onFindingClick,
}: EndpointClusterDrawerProps) => {
  const [expandedTypes, setExpandedTypes] = useState<Set<string>>(new Set());

  if (!cluster) return null;

  const severityColor = getSeverityColor(cluster.max_severity as any);

  // Group findings by vulnerability type
  const findingsByType = cluster.findings.reduce((acc, finding) => {
    const type = finding.rule || "Unknown";
    if (!acc[type]) {
      acc[type] = [];
    }
    acc[type].push(finding);
    return acc;
  }, {} as Record<string, typeof cluster.findings>);

  // Sort vulnerability types by severity (most critical first)
  const sortedTypes = Object.keys(findingsByType).sort((a, b) => {
    const aFindings = findingsByType[a];
    const bFindings = findingsByType[b];

    const severityOrder = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

    // Find max severity for each type
    const aMaxSeverity = Math.min(
      ...aFindings.map((f) => severityOrder[f.severity as keyof typeof severityOrder] ?? 999)
    );
    const bMaxSeverity = Math.min(
      ...bFindings.map((f) => severityOrder[f.severity as keyof typeof severityOrder] ?? 999)
    );

    if (aMaxSeverity !== bMaxSeverity) {
      return aMaxSeverity - bMaxSeverity;
    }

    // If same severity, sort by count (descending)
    return bFindings.length - aFindings.length;
  });

  const toggleType = (type: string) => {
    const newExpanded = new Set(expandedTypes);
    if (newExpanded.has(type)) {
      newExpanded.delete(type);
    } else {
      newExpanded.add(type);
    }
    setExpandedTypes(newExpanded);
  };

  const convertToFinding = (f: typeof cluster.findings[0]): Finding => {
    return {
      id: f.id,
      title: f.title,
      severity: f.severity,
      rule: f.rule,
      description: f.description,
      score: f.score,
      method: f.method,
      endpoint: f.endpoint,
      evidenceId: "temp",
      status: "open",
      triageStatus: f.triage_status || "untriaged",
      assignee: f.assignee || null,
      cve: [],
      cwe: [],
      scanner: "VentiAPI",
    } as Finding;
  };

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/50 z-40"
        onClick={onClose}
      />

      {/* Drawer */}
      <div className="fixed right-0 top-0 h-full w-[800px] bg-background border-l shadow-lg z-50 flex flex-col">
        {/* Header */}
        <div className={cn("p-6 border-b border-l-4", severityColor.border)}>
          <div className="flex items-start justify-between mb-4">
            <div className="flex-1">
              <div className="flex items-center gap-2 mb-2">
                <Code2 className="h-5 w-5 text-muted-foreground" />
                <Badge variant="outline" className="font-mono">
                  {cluster.method}
                </Badge>
                <h2 className="text-2xl font-bold font-mono">{cluster.endpoint}</h2>
              </div>
            </div>
            <Button variant="ghost" size="icon" onClick={onClose}>
              <X className="h-4 w-4" />
            </Button>
          </div>

          {/* Summary Stats */}
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2">
              <AlertTriangle className={cn("h-5 w-5", severityColor.text)} />
              <div>
                <div className="text-3xl font-bold">{cluster.vuln_count}</div>
                <div className="text-xs text-muted-foreground">
                  {cluster.vuln_count === 1 ? "Vulnerability" : "Vulnerabilities"}
                </div>
              </div>
            </div>

            <div className="flex gap-3">
              {cluster.critical_count > 0 && (
                <div>
                  <div className="text-xl font-bold text-red-600">{cluster.critical_count}</div>
                  <div className="text-xs text-muted-foreground">Critical</div>
                </div>
              )}
              {cluster.high_count > 0 && (
                <div>
                  <div className="text-xl font-bold text-orange-600">{cluster.high_count}</div>
                  <div className="text-xs text-muted-foreground">High</div>
                </div>
              )}
              {cluster.medium_count > 0 && (
                <div>
                  <div className="text-xl font-bold text-yellow-600">{cluster.medium_count}</div>
                  <div className="text-xs text-muted-foreground">Medium</div>
                </div>
              )}
              {cluster.low_count > 0 && (
                <div>
                  <div className="text-xl font-bold text-blue-600">{cluster.low_count}</div>
                  <div className="text-xs text-muted-foreground">Low</div>
                </div>
              )}
            </div>
          </div>

          {/* Blast Radius */}
          <div className="mt-4 p-3 bg-muted/50 rounded-lg">
            <div className="text-sm">
              <span className="font-semibold">Blast Radius:</span>{" "}
              <span className="text-muted-foreground">
                {cluster.vuln_count} related {cluster.vuln_count === 1 ? "finding" : "findings"} in this endpoint.
                Single endpoint typically owned by one developer.
              </span>
            </div>
          </div>
        </div>

        {/* Content - Findings Grouped by Type */}
        <ScrollArea className="flex-1">
          <div className="p-6 space-y-4">
            <h3 className="text-lg font-semibold mb-4">
              Vulnerabilities by Type ({sortedTypes.length} {sortedTypes.length === 1 ? "type" : "types"})
            </h3>

            {sortedTypes.map((type) => {
              const typeFindings = findingsByType[type];
              const isExpanded = expandedTypes.has(type);

              // Get max severity for this type
              const typeSeverity = typeFindings.reduce((max, f) => {
                const severityOrder = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
                const currentRank = severityOrder[f.severity as keyof typeof severityOrder] ?? 0;
                const maxRank = severityOrder[max as keyof typeof severityOrder] ?? 0;
                return currentRank > maxRank ? f.severity : max;
              }, typeFindings[0].severity);

              const typeSeverityColor = getSeverityColor(typeSeverity as any);

              return (
                <div key={type} className="border rounded-lg overflow-hidden">
                  {/* Type Header */}
                  <div
                    className={cn(
                      "p-4 cursor-pointer hover:bg-muted/50 transition-colors border-l-4",
                      typeSeverityColor.border
                    )}
                    onClick={() => toggleType(type)}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        {isExpanded ? (
                          <ChevronUp className="h-4 w-4 text-muted-foreground" />
                        ) : (
                          <ChevronDown className="h-4 w-4 text-muted-foreground" />
                        )}
                        <div>
                          <div className="font-semibold">{type}</div>
                          <div className="text-sm text-muted-foreground">
                            {typeFindings.length} {typeFindings.length === 1 ? "finding" : "findings"}
                          </div>
                        </div>
                      </div>
                      <Badge variant="destructive" className={typeSeverityColor.badge}>
                        {typeSeverity}
                      </Badge>
                    </div>
                  </div>

                  {/* Findings List */}
                  {isExpanded && (
                    <div className="border-t bg-muted/20">
                      {typeFindings.map((finding, index) => {
                        const findingSeverityColor = getSeverityColor(finding.severity as any);
                        return (
                          <div
                            key={finding.id}
                            className={cn(
                              "p-4 cursor-pointer hover:bg-muted/50 transition-colors",
                              index > 0 && "border-t"
                            )}
                            onClick={() => onFindingClick(convertToFinding(finding))}
                          >
                            <div className="flex items-start justify-between gap-3">
                              <div className="flex-1 min-w-0">
                                <div className="font-medium mb-1">{finding.title}</div>
                                <div className="text-sm text-muted-foreground line-clamp-2">
                                  {finding.description}
                                </div>
                                <div className="flex items-center gap-2 mt-2">
                                  <Badge variant="outline" className="text-xs">
                                    Score: {finding.score.toFixed(1)}
                                  </Badge>
                                  {finding.triage_status && (
                                    <Badge variant="secondary" className="text-xs">
                                      {finding.triage_status}
                                    </Badge>
                                  )}
                                  {finding.assignee && (
                                    <Badge variant="secondary" className="text-xs">
                                      {finding.assignee}
                                    </Badge>
                                  )}
                                </div>
                              </div>
                              <Badge variant="destructive" className={findingSeverityColor.badge}>
                                {finding.severity}
                              </Badge>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </ScrollArea>

        {/* Footer */}
        <div className="p-6 border-t bg-muted/20">
          <div className="text-sm text-muted-foreground">
            💡 <strong>Tip:</strong> Click any finding to view detailed information and add to AI context.
            All findings in this endpoint are related and can likely be fixed by the endpoint owner.
          </div>
        </div>
      </div>
    </>
  );
};
