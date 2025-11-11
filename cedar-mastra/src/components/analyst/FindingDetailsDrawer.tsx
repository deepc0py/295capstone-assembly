"use client";

import { X, Copy, Plus, Search, Terminal, FileText } from "lucide-react";
import { Finding } from "@/types/finding";
import { mockEvidence } from "@/data/mockFindings";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { cedar, cedarPayloadShapes } from "@/lib/cedar/actions";
import { getSeverityColor, Severity } from "@/lib/utils/severity";
import { useFindingActions } from "@/lib/cedar/useFindingActions";
import { TriageStatusDropdown } from "@/components/triage/TriageStatusDropdown";
import { AssigneeSelector } from "@/components/triage/AssigneeSelector";
import { SLADetails } from "@/components/triage/SLATimer";
import { CommentsSection } from "@/components/triage/CommentsSection";
import { useState } from "react";

interface FindingDetailsDrawerProps {
  finding: Finding | null;
  onClose: () => void;
}

export const FindingDetailsDrawer = ({ finding, onClose }: FindingDetailsDrawerProps) => {
  const { addCustomToChat } = useFindingActions();
  const [checkingExploits, setCheckingExploits] = useState(false);
  const [exploitData, setExploitData] = useState<any>(null);
  const [generatingCurl, setGeneratingCurl] = useState(false);
  const [curlData, setCurlData] = useState<any>(null);
  const [exportingJira, setExportingJira] = useState(false);

  if (!finding) return null;

  const evidence = mockEvidence[finding.evidenceId];

  const handleCopyCode = (code: string) => {
    cedar.util.copy(code);
    toast.success("Copied to clipboard");
  };

  const handleCheckExploits = async () => {
    setCheckingExploits(true);
    try {
      // Get auth token from localStorage
      const token = localStorage.getItem('auth_token');
      if (!token) {
        toast.error("Authentication required");
        return;
      }

      const API_BASE = process.env.NEXT_PUBLIC_SCANNER_API_URL || 'http://localhost:8000';
      const response = await fetch(`${API_BASE}/api/finding/${finding.id}/check-exploits`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error(`API error: ${response.status}`);
      }

      const data = await response.json();
      setExploitData(data);

      if (data.success && data.exploit_present) {
        toast.success(data.message);
      } else if (data.success) {
        toast.info(data.message);
      } else {
        toast.error(data.message);
      }
    } catch (error: any) {
      console.error('Failed to check exploits:', error);
      toast.error(`Failed to check exploits: ${error.message}`);
    } finally {
      setCheckingExploits(false);
    }
  };

  const handleGenerateCurl = async () => {
    setGeneratingCurl(true);
    try {
      const token = localStorage.getItem('auth_token');
      if (!token) {
        toast.error("Authentication required");
        return;
      }

      const API_BASE = process.env.NEXT_PUBLIC_SCANNER_API_URL || 'http://localhost:8000';
      const response = await fetch(`${API_BASE}/api/finding/${finding.id}/generate-curl`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error(`API error: ${response.status}`);
      }

      const data = await response.json();
      setCurlData(data);
      toast.success("cURL command generated");
    } catch (error: any) {
      console.error('Failed to generate cURL:', error);
      toast.error(`Failed to generate cURL: ${error.message}`);
    } finally {
      setGeneratingCurl(false);
    }
  };

  const handleExportJira = async () => {
    setExportingJira(true);
    try {
      const token = localStorage.getItem('auth_token');
      if (!token) {
        toast.error("Authentication required");
        return;
      }

      const API_BASE = process.env.NEXT_PUBLIC_SCANNER_API_URL || 'http://localhost:8000';
      const response = await fetch(`${API_BASE}/api/finding/${finding.id}/export-jira`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error(`API error: ${response.status}`);
      }

      const data = await response.json();

      // Copy markdown to clipboard
      cedar.util.copy(data.markdown);
      toast.success("Jira ticket markdown copied to clipboard");
    } catch (error: any) {
      console.error('Failed to export to Jira:', error);
      toast.error(`Failed to export to Jira: ${error.message}`);
    } finally {
      setExportingJira(false);
    }
  };

  const handleAddToChat = (type: "full" | "overview" | "evidence" | "compliance") => {
    let payload: any;
    let label: string;

    switch (type) {
      case "full":
        payload = cedarPayloadShapes.fullFindingWithEvidenceAndMappings(finding, evidence);
        label = `Full details: ${finding.endpoint.method} ${finding.endpoint.path}`;
        break;
      case "overview":
        payload = cedarPayloadShapes.minimalFinding(finding);
        label = `Overview: ${finding.endpoint.method} ${finding.endpoint.path}`;
        break;
      case "evidence":
        payload = cedarPayloadShapes.evidenceLite(evidence);
        label = `Evidence: ${finding.evidenceId}`;
        break;
      case "compliance":
        payload = cedarPayloadShapes.complianceOnly(finding);
        label = `Compliance: ${finding.endpoint.method} ${finding.endpoint.path}`;
        break;
    }

    addCustomToChat(`analyst-${type}-${finding.id}`, payload, label, finding.severity);
    toast.success("Added to Context Basket");
  };

  return (
    <div className="fixed inset-y-0 right-0 w-[720px] bg-card border-l border-border shadow-lg z-50 flex flex-col">
      {/* Header */}
      <div className="border-b border-border p-6 space-y-3">
        <div className="flex items-start justify-between">
          <div className="space-y-2 flex-1">
            <div className="flex items-center gap-2">
              <Badge className={cn("uppercase text-xs font-semibold", getSeverityColor(finding.severity as Severity, 'border'))}>
                {finding.severity}
              </Badge>
              <span className="font-mono text-sm">
                <code className="text-primary font-semibold">{finding.endpoint.method}</code>{" "}
                {finding.endpoint.path}
              </span>
            </div>
            <div className="text-sm text-muted-foreground">
              CVSS {finding.cvss} · {finding.exploitPresent ? "Public exploit" : "No known exploit"} · {finding.status}
            </div>
            <div className="flex gap-2 flex-wrap">
              <Badge variant="outline" className="text-xs">OWASP: {finding.owasp}</Badge>
              <Badge variant="outline" className="text-xs">CWE: {finding.cwe.join(", ")}</Badge>
            </div>
          </div>
          <Button variant="ghost" size="icon" onClick={onClose}>
            <X className="h-4 w-4" />
          </Button>
        </div>
        <div className="flex gap-2">
          <Button
            onClick={() => handleAddToChat("full")}
            size="sm"
            className="bg-gradient-primary hover:opacity-90"
          >
            <Plus className="mr-2 h-3 w-3" />
            Add Full Details to Chat
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <ScrollArea className="flex-1">
        <Tabs defaultValue="overview" className="p-6">
          <TabsList className="grid w-full grid-cols-5">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="evidence">Evidence & Repro</TabsTrigger>
            <TabsTrigger value="compliance">Compliance</TabsTrigger>
            <TabsTrigger value="triage">Triage</TabsTrigger>
            <TabsTrigger value="history">History</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-4 mt-4">
            <div className="prose prose-sm max-w-none">
              <p className="text-foreground">{finding.summaryHumanReadable}</p>
            </div>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div>
                <span className="font-medium text-foreground">Service:</span>{" "}
                <span className="text-muted-foreground">{finding.endpoint.service}</span>
              </div>
              <div>
                <span className="font-medium text-foreground">Scanners:</span>{" "}
                <span className="text-muted-foreground">{finding.scanners.join(", ")}</span>
              </div>
              <div>
                <span className="font-medium text-foreground">First seen:</span>{" "}
                <span className="text-muted-foreground">{new Date(finding.firstSeen).toLocaleDateString()}</span>
              </div>
              <div>
                <span className="font-medium text-foreground">Last seen:</span>{" "}
                <span className="text-muted-foreground">{new Date(finding.lastSeen).toLocaleDateString()}</span>
              </div>
            </div>
            <Button variant="outline" size="sm" onClick={() => handleAddToChat("overview")}>
              <Plus className="mr-2 h-3 w-3" />
              Add Overview to Chat
            </Button>
          </TabsContent>

          <TabsContent value="evidence" className="space-y-4 mt-4">
            {evidence ? (
              <>
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="font-medium text-sm text-foreground">Request</h4>
                    <Button variant="ghost" size="sm" onClick={() => handleCopyCode(evidence.request)}>
                      <Copy className="h-3 w-3 mr-1" />
                      Copy
                    </Button>
                  </div>
                  <pre className="bg-secondary p-4 rounded text-xs font-mono overflow-x-auto">
                    {evidence.request}
                  </pre>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="font-medium text-sm text-foreground">Response (redacted)</h4>
                    <Button variant="ghost" size="sm" onClick={() => handleCopyCode(evidence.response)}>
                      <Copy className="h-3 w-3 mr-1" />
                      Copy
                    </Button>
                  </div>
                  <pre className="bg-secondary p-4 rounded text-xs font-mono overflow-x-auto">
                    {evidence.response}
                  </pre>
                </div>

                {/* Week 6: Check for Exploits Button */}
                <div className="border-t pt-4">
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={handleCheckExploits}
                    disabled={checkingExploits}
                    className="mb-3"
                  >
                    <Search className="mr-2 h-3 w-3" />
                    {checkingExploits ? "Searching GitHub..." : "Check for Public Exploits"}
                  </Button>

                  {exploitData && exploitData.success && (
                    <div className="space-y-3">
                      {exploitData.exploit_present ? (
                        <>
                          <div className="flex items-center gap-2">
                            <Badge variant="destructive" className="text-xs">
                              ⚠️ Exploits Found
                            </Badge>
                            <span className="text-sm text-muted-foreground">
                              Signal: {exploitData.exploit_signal}/10
                            </span>
                          </div>
                          <div>
                            <h4 className="font-medium text-sm mb-2 text-foreground">
                              Public PoC Repositories ({exploitData.poc_repos.length})
                            </h4>
                            <ul className="space-y-2">
                              {exploitData.poc_repos.map((repo: any, i: number) => (
                                <li key={i} className="border-l-2 border-primary pl-3">
                                  <a
                                    href={repo.url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-primary hover:underline text-sm font-medium"
                                  >
                                    {repo.name}
                                  </a>
                                  {repo.description && (
                                    <p className="text-xs text-muted-foreground mt-1">
                                      {repo.description}
                                    </p>
                                  )}
                                  <div className="flex gap-3 text-xs text-muted-foreground mt-1">
                                    <span>⭐ {repo.stars} stars</span>
                                    {repo.language && <span>📝 {repo.language}</span>}
                                    <span>Updated: {new Date(repo.last_updated).toLocaleDateString()}</span>
                                  </div>
                                </li>
                              ))}
                            </ul>
                          </div>
                          <div className="text-xs text-muted-foreground bg-secondary p-3 rounded">
                            <strong>Stats:</strong> {exploitData.stats.total_repos_found} total repos found
                            {exploitData.stats.high_quality_repos > 0 && (
                              <>, {exploitData.stats.high_quality_repos} high-quality (10+ stars)</>
                            )}
                            {exploitData.stats.recent_repos > 0 && (
                              <>, {exploitData.stats.recent_repos} recently updated</>
                            )}
                          </div>
                        </>
                      ) : (
                        <div className="text-sm text-muted-foreground bg-secondary p-3 rounded">
                          ✅ No public exploits found for this vulnerability
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* Week 7: Evidence Collection Automation */}
                <div className="border-t pt-4 space-y-3">
                  <h4 className="font-medium text-sm text-foreground">Reproduction Tools</h4>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={handleGenerateCurl}
                      disabled={generatingCurl}
                    >
                      <Terminal className="mr-2 h-3 w-3" />
                      {generatingCurl ? "Generating..." : "Generate cURL"}
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={handleExportJira}
                      disabled={exportingJira}
                    >
                      <FileText className="mr-2 h-3 w-3" />
                      {exportingJira ? "Exporting..." : "Export to Jira"}
                    </Button>
                  </div>

                  {curlData && curlData.success && (
                    <div className="space-y-3">
                      <div>
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="font-medium text-sm text-foreground">cURL Command</h4>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleCopyCode(curlData.curl_command)}
                          >
                            <Copy className="h-3 w-3 mr-1" />
                            Copy
                          </Button>
                        </div>
                        <pre className="bg-secondary p-4 rounded text-xs font-mono overflow-x-auto">
                          {curlData.curl_command}
                        </pre>
                      </div>

                      <div className="bg-secondary p-3 rounded">
                        <h5 className="font-medium text-xs text-foreground mb-2">Reproduction Steps:</h5>
                        <ol className="text-xs text-muted-foreground space-y-1 list-decimal list-inside">
                          {curlData.reproduction_steps.map((step: string, i: number) => (
                            <li key={i}>{step.replace(/^\d+\.\s*/, '')}</li>
                          ))}
                        </ol>
                      </div>

                      {curlData.expected_response && (
                        <div>
                          <h5 className="font-medium text-xs text-foreground mb-2">Expected Response (truncated):</h5>
                          <pre className="bg-secondary p-3 rounded text-xs font-mono overflow-x-auto max-h-32">
                            {curlData.expected_response}
                          </pre>
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {evidence.pocLinks.length > 0 && (
                  <div className="border-t pt-4">
                    <h4 className="font-medium text-sm mb-2 text-foreground">POC Links (from Evidence)</h4>
                    <ul className="space-y-1">
                      {evidence.pocLinks.map((link, i) => (
                        <li key={i}>
                          <a href={link} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline text-sm">
                            {link}
                          </a>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                <Button variant="outline" size="sm" onClick={() => handleAddToChat("evidence")} className="mt-4">
                  <Plus className="mr-2 h-3 w-3" />
                  Add Evidence to Chat
                </Button>
              </>
            ) : (
              <p className="text-sm text-muted-foreground">No evidence available</p>
            )}
          </TabsContent>

          <TabsContent value="compliance" className="space-y-4 mt-4">
            <div className="space-y-3">
              <div>
                <h4 className="font-medium text-sm mb-2 text-foreground">OWASP</h4>
                <Badge variant="outline">{finding.owasp}</Badge>
              </div>
              <div>
                <h4 className="font-medium text-sm mb-2 text-foreground">CWE</h4>
                <div className="flex gap-2 flex-wrap">
                  {finding.cwe.map((c) => (
                    <Badge key={c} variant="outline">{c}</Badge>
                  ))}
                </div>
              </div>
              {finding.nistCsf && finding.nistCsf.length > 0 && (
                <div>
                  <h4 className="font-medium text-sm mb-2 text-foreground">NIST CSF</h4>
                  <div className="flex gap-2 flex-wrap">
                    {finding.nistCsf.map((n) => (
                      <Badge key={n} variant="outline">{n}</Badge>
                    ))}
                  </div>
                </div>
              )}
              {finding.nist80053 && finding.nist80053.length > 0 && (
                <div>
                  <h4 className="font-medium text-sm mb-2 text-foreground">NIST 800-53</h4>
                  <div className="flex gap-2 flex-wrap">
                    {finding.nist80053.map((n) => (
                      <Badge key={n} variant="outline">{n}</Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
            <Button variant="outline" size="sm" onClick={() => handleAddToChat("compliance")}>
              <Plus className="mr-2 h-3 w-3" />
              Add Compliance to Chat
            </Button>
          </TabsContent>

          <TabsContent value="triage" className="space-y-6 mt-4">
            {finding.triage ? (
              <>
                <div className="space-y-4">
                  <div>
                    <h4 className="font-medium text-sm mb-3 text-foreground">Status</h4>
                    <TriageStatusDropdown
                      findingId={finding.id}
                      currentStatus={finding.triage.status as any}
                      size="md"
                      onChange={() => {
                        toast.success("Triage status updated");
                      }}
                    />
                  </div>

                  <div>
                    <h4 className="font-medium text-sm mb-3 text-foreground">Assignee</h4>
                    <AssigneeSelector
                      findingId={finding.id}
                      currentAssignee={finding.triage.assigned_to}
                      size="md"
                      onChange={() => {
                        toast.success("Assignee updated");
                      }}
                    />
                  </div>

                  <div>
                    <h4 className="font-medium text-sm mb-3 text-foreground">SLA</h4>
                    <SLADetails
                      slaDeadline={finding.triage.sla_deadline}
                      status={finding.triage.status}
                    />
                  </div>
                </div>

                <div className="border-t pt-6">
                  <CommentsSection
                    findingId={finding.id}
                    onCommentAdded={() => {
                      toast.success("Comment added");
                    }}
                  />
                </div>
              </>
            ) : (
              <div className="text-sm text-muted-foreground">
                <p className="mb-4">This finding has not been triaged yet.</p>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={async () => {
                    try {
                      const response = await fetch(`http://localhost:8000/api/finding/${finding.id}/triage`, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ auto_sla: true }),
                      });

                      if (!response.ok) throw new Error("Failed to create triage");

                      toast.success("Triage created successfully");
                      // In a real app, you'd refresh the finding data here
                    } catch (error) {
                      toast.error("Failed to create triage");
                    }
                  }}
                >
                  Create Triage Record
                </Button>
              </div>
            )}
          </TabsContent>

          <TabsContent value="history" className="space-y-4 mt-4">
            <div className="space-y-3">
              <div className="flex gap-2">
                {finding.flags.isNew && <Badge className="bg-info/20 text-info">New</Badge>}
                {finding.flags.isRegressed && <Badge className="bg-high/20 text-high">Regressed</Badge>}
                {finding.flags.isResolved && <Badge className="bg-low/20 text-low">Resolved</Badge>}
              </div>
              <div className="text-sm space-y-2">
                <div>
                  <span className="font-medium text-foreground">Owner:</span>{" "}
                  <span className="text-muted-foreground">{finding.owner}</span>
                </div>
                <div>
                  <span className="font-medium text-foreground">SLA Due:</span>{" "}
                  <span className="text-muted-foreground">{new Date(finding.slaDue).toLocaleDateString()}</span>
                </div>
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </ScrollArea>
    </div>
  );
};
