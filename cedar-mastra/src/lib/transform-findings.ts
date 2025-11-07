/**
 * Transform raw scan findings to analyst Finding format
 *
 * Converts VulnerabilityFinding from scanner to Finding format
 * expected by analyst dashboard components
 */

import { VulnerabilityFinding } from '@/app/cedar-os/scanState';
import { Finding } from '@/types/finding';

/**
 * Calculate priority score (0-100) based on severity, exploitability, and exposure
 */
function calculatePriorityScore(finding: VulnerabilityFinding): number {
  // Base score from severity
  const severityScore = {
    Critical: 90,
    High: 70,
    Medium: 50,
    Low: 30,
  }[finding.severity] || 50;

  // Boost for injection vulnerabilities (highly exploitable)
  const exploitabilityBoost = finding.rule === 'API8' ? 10 : 0;

  // Boost for auth/authz issues (commonly exploited)
  const authBoost = ['API1', 'API2', 'API5'].includes(finding.rule) ? 5 : 0;

  // Penalty for non-public endpoints
  const exposurePenalty = finding.endpoint.includes('/admin') ||
                          finding.endpoint.includes('/internal') ? -10 : 0;

  return Math.min(100, Math.max(0, severityScore + exploitabilityBoost + authBoost + exposurePenalty));
}

/**
 * Determine fixability difficulty (trivial, easy, moderate, hard)
 */
function calculateFixability(finding: VulnerabilityFinding): 'trivial' | 'easy' | 'moderate' | 'hard' {
  // Map OWASP API rules to fix difficulty
  const fixabilityMap: Record<string, 'trivial' | 'easy' | 'moderate' | 'hard'> = {
    'API7': 'easy',      // Misconfiguration - usually config change
    'API4': 'easy',      // Rate limiting - add middleware
    'API10': 'easy',     // Logging - add logging calls
    'API2': 'moderate',  // Auth - requires middleware integration
    'API5': 'moderate',  // BFLA - requires auth checks
    'API3': 'moderate',  // Exposure - requires field filtering
    'API6': 'moderate',  // Mass assignment - requires input validation
    'API8': 'hard',      // Injection - requires code refactoring
    'API1': 'hard',      // BOLA - requires authorization logic
    'API9': 'moderate',  // Asset mgmt - requires documentation
  };

  return fixabilityMap[finding.rule] || 'moderate';
}

/**
 * Assess evidence quality based on available evidence data
 */
function assessEvidenceQuality(finding: VulnerabilityFinding): 'complete' | 'partial' | 'missing' {
  if (!finding.evidence || Object.keys(finding.evidence).length === 0) {
    return 'missing';
  }

  const evidenceKeys = Object.keys(finding.evidence);
  const hasRichEvidence = evidenceKeys.some(key =>
    ['unauth', 'bogus', 'statuses', 'fields', 'sample'].includes(key)
  );

  if (hasRichEvidence && evidenceKeys.length >= 2) {
    return 'complete';
  }

  return 'partial';
}

/**
 * Determine auth level from evidence
 */
function determineAuthLevel(finding: VulnerabilityFinding): 'none' | 'user' | 'admin' {
  // Check if endpoint pattern suggests admin
  if (finding.endpoint.includes('/admin')) {
    return 'admin';
  }

  // Check if evidence shows authentication testing
  if (finding.evidence?.unauth || finding.evidence?.bogus) {
    return 'none'; // Vulnerability exists with no auth
  }

  // Check endpoint patterns
  if (finding.endpoint.includes('/users') || finding.endpoint.includes('/profile')) {
    return 'user';
  }

  return 'none';
}

/**
 * Transform VulnerabilityFinding to analyst Finding format
 */
export function transformFinding(vulnFinding: VulnerabilityFinding, index: number): Finding {
  const priorityScore = calculatePriorityScore(vulnFinding);
  const fixability = calculateFixability(vulnFinding);
  const evidenceQuality = assessEvidenceQuality(vulnFinding);
  const authLevel = determineAuthLevel(vulnFinding);

  return {
    id: vulnFinding.id,
    rule: vulnFinding.rule,
    title: vulnFinding.title,
    endpoint: vulnFinding.endpoint,
    method: vulnFinding.method,
    cvss: vulnFinding.score,
    priorityScore,
    fixability,
    status: 'new', // Would come from triage data in production
    evidenceQuality,
    authLevel,
    flags: {
      isNew: true, // Would come from historical comparison
      isRegressed: false,
      isResolved: false,
    },
    severity: vulnFinding.severity,
    description: vulnFinding.description,
    scanner: vulnFinding.scanner,
    evidence: vulnFinding.evidence,
  };
}

/**
 * Transform array of vulnerability findings to analyst format
 */
export function transformFindings(vulnFindings: VulnerabilityFinding[]): Finding[] {
  return vulnFindings.map((finding, index) => transformFinding(finding, index));
}

/**
 * Calculate diff counts (placeholder - would come from historical comparison)
 */
export function calculateDiffCounts(findings: Finding[]): {
  new: number;
  regressed: number;
  resolved: number;
} {
  return {
    new: findings.filter(f => f.flags.isNew).length,
    regressed: findings.filter(f => f.flags.isRegressed).length,
    resolved: findings.filter(f => f.flags.isResolved).length,
  };
}
