"use client";

import { useState, useMemo } from "react";
import { ExecutiveKPICards } from "./ExecutiveKPICards";
import { ExecutiveTrendChart } from "./ExecutiveTrendChart";
import { ExecutiveTopRisks } from "./ExecutiveTopRisks";
import { ExecutiveComplianceSnapshot } from "./ExecutiveComplianceSnapshot";
import { ExecutiveOwnershipTable } from "./ExecutiveOwnershipTable";
import { ChatPresets } from "@/components/shared/ChatPresets";
import { executivePresets } from "@/config/chatPresets";
import { BoardBriefWizard } from "./BoardBriefWizard";
import { DashboardHeader } from "@/components/shared/DashboardHeader";
import { useExecutiveReportBridge } from "@/hooks/useExecutiveReportBridge";
import { useRegisterExecutiveData } from "@/lib/cedar/useRegisterExecutiveData";
import { Button } from "@/components/ui/button";
import { FileText, AlertCircle } from "lucide-react";
import { useScanResultsState } from "@/app/cedar-os/scanState";
import {
  calculateExecutiveKPIs,
  extractTopRisks,
  calculateComplianceSnapshot,
  generateTrendData,
} from "@/lib/executive-kpi-calculator";
import {
  mockExecSummary,
  mockExecTrend,
  mockExecTopRisks,
  mockExecCompliance,
  mockExecSlaOwners,
} from "@/data/mockExecutiveData";

export const ExecutiveView = () => {
  const [wizardOpen, setWizardOpen] = useState(false);
  const { scanResults } = useScanResultsState();

  // Calculate KPIs from real scan data or fall back to mock data
  const kpis = useMemo(() => {
    if (!scanResults) return mockExecSummary;

    const calculated = calculateExecutiveKPIs(scanResults);
    return {
      riskScore: calculated.riskScore,
      critical: calculated.criticalCount,
      high: calculated.highCount,
      pastSlaPct: 100 - calculated.slaCompliance,
      mttrMedian: calculated.mttrMedian,
      mttrP95: calculated.mttrP95,
      publicExploitCount: calculated.publicExploitCount,
      internetFacingCount: calculated.internetFacingCount,
    };
  }, [scanResults]);

  // Extract top risks from real findings
  const topRisks = useMemo(() => {
    if (!scanResults) return mockExecTopRisks;

    const realRisks = extractTopRisks(scanResults.findings, 5);
    return realRisks.map(risk => ({
      id: risk.id,
      title: risk.title,
      systems: risk.affectedSystems,
      severity: risk.severity,
      exploitPresent: risk.exploitStatus === 'public',
      internetFacing: risk.internetFacing,
      isNewOrRegressed: "New" as const, // Would come from historical comparison
      recommendedAction: `Fix ${risk.severity} vulnerability affecting ${risk.affectedSystems.length} endpoint(s)`,
      owner: risk.owner,
      eta: new Date(Date.now() + (risk.severity === 'Critical' ? 2 : 7) * 24 * 60 * 60 * 1000).toISOString(),
      relatedBreachIds: risk.relatedBreaches || [],
    }));
  }, [scanResults]);

  // Calculate compliance snapshot
  const compliance = useMemo(() => {
    if (!scanResults) return mockExecCompliance;

    const calculated = calculateComplianceSnapshot(scanResults.findings);
    return {
      owaspCounts: calculated.owaspCounts,
      nistCsf: calculated.nistStatus,
    };
  }, [scanResults]);

  // Generate trend data
  const trendData = useMemo(() => {
    if (!scanResults) return mockExecTrend;

    const trend = generateTrendData(scanResults);
    const currentRisk = kpis.riskScore;
    const previousRisk = trend.riskScores[0];
    const deltaPct = previousRisk > 0
      ? Math.round(((currentRisk - previousRisk) / previousRisk) * 100)
      : 0;

    return {
      window: "30d",
      deltaPct,
      points: trend.riskScores.slice(-7), // Last 7 days for chart
    };
  }, [scanResults, kpis]);

  // SLA owners (using mock data for now - would come from triage data)
  const owners = mockExecSlaOwners;

  // Register executive data with Cedar for @mention functionality
  const { risks: registeredRisks, owners: registeredOwners } = useRegisterExecutiveData(topRisks, owners);

  const { addCardToReport, setReportMeta, reportItems, reportMeta } = useExecutiveReportBridge({
    kpis,
    topRiskCards: registeredRisks,
    complianceSnapshot: compliance,
    ownershipRows: registeredOwners
  });

  return (
    <div className="space-y-6">
      <DashboardHeader
        title="Risk & Compliance Overview"
        description="Current security posture, trends, and prioritized business risks"
        action={
          <Button onClick={() => setWizardOpen(true)} size="lg">
            <FileText className="h-4 w-4 mr-2" />
            Generate Board Brief
          </Button>
        }
      />

      {/* Show warning if using mock data */}
      {!scanResults && (
        <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-4 flex items-start gap-3">
          <AlertCircle className="h-5 w-5 text-yellow-500 mt-0.5 flex-shrink-0" />
          <div>
            <p className="text-sm font-semibold text-yellow-500">Using Sample Data</p>
            <p className="text-xs text-yellow-500/80 mt-1">
              No scan results loaded. Displaying sample executive dashboard.
              Load a scan from the Security page to see real data.
            </p>
          </div>
        </div>
      )}

      <ExecutiveKPICards summary={kpis} onAddToReport={addCardToReport} />

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7">
          <ExecutiveTrendChart trend={trendData} />
        </div>
        <div className="lg:col-span-5">
          <ExecutiveTrendChart trend={trendData} isSLA />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-8">
          <ExecutiveTopRisks risks={registeredRisks} onAddToReport={addCardToReport} />
        </div>
        <div className="lg:col-span-4">
          <ExecutiveComplianceSnapshot compliance={compliance} onAddToReport={addCardToReport} />
        </div>
      </div>

      <ExecutiveOwnershipTable owners={registeredOwners} onAddToReport={addCardToReport} />

      <ChatPresets
        presets={executivePresets}
        title="Quick AI Actions (Executive)"
        gridCols={{ base: 1, md: 2, lg: 4 }}
        variant="card-wrapped"
      />

      <BoardBriefWizard
        open={wizardOpen}
        onOpenChange={setWizardOpen}
        reportMeta={reportMeta}
        setReportMeta={setReportMeta}
        reportItems={reportItems}
      />
    </div>
  );
};
