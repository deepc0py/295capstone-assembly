"use client";

import { useState, useMemo } from "react";
import { mockFindings } from "@/data/mockFindings";
import { Finding } from "@/types/finding";
import { FindingsTable } from "./FindingsTable";
import { FindingDetailsDrawer } from "./FindingDetailsDrawer";
import { DiffViewModal } from "./DiffViewModal";
import { ChatPresets } from "@/components/shared/ChatPresets";
import { analystPresets } from "@/config/chatPresets";
import { DashboardHeader } from "@/components/shared/DashboardHeader";
import { useRegisterFindings } from "@/lib/cedar/useRegisterFindings";
import { useScanResultsState } from "@/app/cedar-os/scanState";
import { transformFindings, calculateDiffCounts } from "@/lib/transform-findings";
import { AlertCircle } from "lucide-react";

interface SecurityAnalystViewProps {
  selectedFindings?: Set<string>;
  onSelectionChange?: (selected: Set<string>) => void;
}

export const SecurityAnalystView = ({ selectedFindings, onSelectionChange }: SecurityAnalystViewProps = {}) => {
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [showDiffModal, setShowDiffModal] = useState(false);
  const { scanResults } = useScanResultsState();

  // Transform real scan findings to analyst format or use mock data
  const realFindings = useMemo(() => {
    if (!scanResults) return mockFindings;
    return transformFindings(scanResults.findings);
  }, [scanResults]);

  // Register findings with Cedar for @mention functionality
  const { findings } = useRegisterFindings(realFindings);

  // Calculate diff counts
  const diffCounts = useMemo(() => {
    return calculateDiffCounts(realFindings);
  }, [realFindings]);

  return (
    <div className="space-y-6">
      <DashboardHeader
        title="Deduped Findings"
        description="Prioritized by exploitability, CVSS, exposure, and recency. Click any row for full details."
        size="md"
      />

      {/* Show warning if using mock data */}
      {!scanResults && (
        <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-4 flex items-start gap-3">
          <AlertCircle className="h-5 w-5 text-yellow-500 mt-0.5 flex-shrink-0" />
          <div>
            <p className="text-sm font-semibold text-yellow-500">Using Sample Data</p>
            <p className="text-xs text-yellow-500/80 mt-1">
              No scan results loaded. Displaying sample findings for demonstration.
              Load a scan to see real vulnerability data.
            </p>
          </div>
        </div>
      )}

      <FindingsTable
        findings={realFindings}
        onRowClick={setSelectedFinding}
        onOpenDiff={() => setShowDiffModal(true)}
        diffCounts={diffCounts}
        selectedFindings={selectedFindings}
        onSelectionChange={onSelectionChange}
      />

      <ChatPresets
        presets={analystPresets}
        title="Quick AI Actions"
        subtitle="Pre-configured prompts for common security analyst workflows"
        gridCols={{ base: 1, md: 2, lg: 4 }}
      />

      <FindingDetailsDrawer finding={selectedFinding} onClose={() => setSelectedFinding(null)} />

      <DiffViewModal
        open={showDiffModal}
        onOpenChange={setShowDiffModal}
        findings={realFindings}
      />
    </div>
  );
};
