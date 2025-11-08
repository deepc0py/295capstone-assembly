/**
 * False Positive Filtering Utilities (Week 5)
 *
 * Simple utilities to exclude false positive findings from agent context.
 * Keeps the implementation minimal and focused.
 */

import { Finding } from "@/types/finding";

/**
 * Filter out findings marked as false positives
 * @param findings - Array of findings to filter
 * @returns Findings without false positives
 */
export function filterFalsePositives(findings: Finding[]): Finding[] {
  return findings.filter(finding => {
    // Exclude findings with triage status = 'false_positive'
    if (finding.triage?.status === 'false_positive') {
      return false;
    }
    return true;
  });
}

/**
 * Check if a single finding is marked as a false positive
 * @param finding - Finding to check
 * @returns True if the finding is a false positive
 */
export function isFalsePositive(finding: Finding): boolean {
  return finding.triage?.status === 'false_positive';
}

/**
 * Count how many findings are false positives
 * @param findings - Array of findings
 * @returns Count of false positives
 */
export function countFalsePositives(findings: Finding[]): number {
  return findings.filter(isFalsePositive).length;
}

/**
 * Separate findings into real and false positives
 * @param findings - Array of findings
 * @returns Object with real and falsePositive arrays
 */
export function separateFalsePositives(findings: Finding[]): {
  real: Finding[];
  falsePositives: Finding[];
} {
  const real: Finding[] = [];
  const falsePositives: Finding[] = [];

  findings.forEach(finding => {
    if (isFalsePositive(finding)) {
      falsePositives.push(finding);
    } else {
      real.push(finding);
    }
  });

  return { real, falsePositives };
}
