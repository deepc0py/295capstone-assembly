/**
 * Search GitHub PoC Tool
 *
 * Searches GitHub repositories for public exploit/PoC (Proof-of-Concept) code
 * related to specific vulnerabilities.
 *
 * This tool helps analysts assess real-world exploitability by:
 * - Searching for exploit repositories on GitHub
 * - Calculating exploit availability signal (0-10 scale)
 * - Returning links to PoC code
 * - Assessing exploit quality (star count, recency)
 *
 * Used for Week 6: Exploit Intelligence Integration
 */

import { createTool } from '@mastra/core';
import { z } from 'zod';

// Valid programming languages for filtering
const VALID_LANGUAGES = [
  'python',
  'javascript',
  'java',
  'go',
  'ruby',
  'php',
  'c',
  'cpp',
  'csharp',
  'rust',
  'shell',
] as const;

export const searchGitHubPocTool = createTool({
  id: 'search-github-poc',
  description: `Search GitHub for public exploit/PoC repositories.

Use this tool when:
- Analyzing a vulnerability to assess real-world exploitability
- Finding has a CVE ID that might have public exploits
- User asks "are there exploits for this vulnerability?"
- Analyst needs to understand attacker advantage

The tool will:
1. Search GitHub repositories for exploit/PoC code
2. Calculate exploit availability signal (0-10 scale)
3. Return top PoC repos with quality indicators (stars, recency)
4. Assess exploit prevalence and quality

Examples:
- "Check if CVE-2021-44228 has exploits" → { cveId: "CVE-2021-44228" }
- "Find SQL injection PoCs in Python" → { vulnerabilityType: "SQL injection", language: "python" }
- "Search for BOLA exploits" → { vulnerabilityType: "BOLA" }
- "Are there PoCs for CVE-2023-12345?" → { cveId: "CVE-2023-12345" }`,

  inputSchema: z.object({
    findingId: z
      .string()
      .optional()
      .describe('Finding ID to associate results with (optional)'),

    cveId: z
      .string()
      .optional()
      .describe('CVE ID to search for (e.g., "CVE-2021-44228")'),

    vulnerabilityType: z
      .string()
      .optional()
      .describe('Vulnerability type to search for (e.g., "SQL injection", "BOLA", "XSS")'),

    language: z
      .enum(VALID_LANGUAGES)
      .optional()
      .describe('Filter results by programming language'),

    maxResults: z
      .number()
      .int()
      .min(1)
      .max(20)
      .default(5)
      .describe('Maximum number of repos to return (default: 5, max: 20)'),
  }),

  outputSchema: z.object({
    success: z.boolean(),
    message: z.string(),
    exploitPresent: z.boolean().describe('Whether public exploits were found'),
    exploitSignal: z.number().min(0).max(10).describe('Exploit availability score (0-10)'),
    pocRepos: z.array(
      z.object({
        name: z.string().describe('Repository full name (owner/repo)'),
        url: z.string().describe('GitHub repository URL'),
        description: z.string().nullable().describe('Repository description'),
        stars: z.number().describe('Star count (quality indicator)'),
        language: z.string().nullable().describe('Primary programming language'),
        lastUpdated: z.string().describe('Last update timestamp'),
      })
    ),
    stats: z.object({
      totalReposFound: z.number().describe('Total repos matching search'),
      highQualityRepos: z.number().describe('Repos with 10+ stars'),
      recentRepos: z.number().describe('Repos updated in last 6 months'),
    }),
    error: z.string().optional(),
  }),

  execute: async ({ context }) => {
    const { findingId, cveId, vulnerabilityType, language, maxResults = 5 } = context;

    console.log(`\n🔍 Searching GitHub for PoC repositories`);
    console.log(`   Finding ID: ${findingId || 'none'}`);
    console.log(`   CVE: ${cveId || 'none'}`);
    console.log(`   Vulnerability Type: ${vulnerabilityType || 'none'}`);
    console.log(`   Language: ${language || 'any'}`);
    console.log(`   Max Results: ${maxResults}`);

    try {
      // 1. Validate input
      if (!cveId && !vulnerabilityType) {
        return {
          success: false,
          message: 'Must provide either cveId or vulnerabilityType',
          exploitPresent: false,
          exploitSignal: 0,
          pocRepos: [],
          stats: {
            totalReposFound: 0,
            highQualityRepos: 0,
            recentRepos: 0,
          },
          error: 'Missing required search parameter',
        };
      }

      // 2. Check for GITHUB_TOKEN
      if (!process.env.GITHUB_TOKEN) {
        return {
          success: false,
          message: 'GITHUB_TOKEN environment variable not set. Cannot query GitHub API.',
          exploitPresent: false,
          exploitSignal: 0,
          pocRepos: [],
          stats: {
            totalReposFound: 0,
            highQualityRepos: 0,
            recentRepos: 0,
          },
          error: 'Missing GITHUB_TOKEN configuration',
        };
      }

      // 3. Build search query
      let query = '';
      if (cveId) {
        // Search for CVE-specific exploits
        query = `${cveId} (exploit OR PoC OR poc OR "proof of concept")`;
      } else if (vulnerabilityType) {
        // Search for vulnerability type exploits
        query = `"${vulnerabilityType}" (exploit OR PoC OR "proof of concept")`;
      }

      // Add language filter if specified
      if (language) {
        query += ` language:${language}`;
      }

      // 4. Query GitHub Repository Search API
      const GITHUB_API_BASE = 'https://api.github.com';
      const params = new URLSearchParams({
        q: query,
        sort: 'stars', // Most starred repos = highest quality
        order: 'desc',
        per_page: Math.min(maxResults, 20).toString(),
      });

      const url = `${GITHUB_API_BASE}/search/repositories?${params.toString()}`;

      console.log(`📡 Fetching from GitHub API...`);
      console.log(`   Query: "${query}"`);

      const response = await fetch(url, {
        headers: {
          'Accept': 'application/vnd.github+json',
          'Authorization': `Bearer ${process.env.GITHUB_TOKEN}`,
          'X-GitHub-Api-Version': '2022-11-28',
        },
      });

      if (!response.ok) {
        const error = await response.text();
        throw new Error(`GitHub API error: ${response.status} - ${error}`);
      }

      const data = await response.json();

      // 5. Process results
      const pocRepos = data.items.slice(0, maxResults).map((repo: any) => ({
        name: repo.full_name,
        url: repo.html_url,
        description: repo.description,
        stars: repo.stargazers_count,
        language: repo.language,
        lastUpdated: repo.updated_at,
      }));

      const totalReposFound = data.total_count;

      // 6. Calculate statistics
      const highQualityRepos = pocRepos.filter((r: any) => r.stars >= 10).length;

      const sixMonthsAgo = new Date();
      sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);
      const recentRepos = pocRepos.filter((r: any) => {
        const updated = new Date(r.lastUpdated);
        return updated > sixMonthsAgo;
      }).length;

      // 7. Calculate exploit signal (0-10 scale)
      // Scoring heuristic:
      // - Any repos found: +2
      // - Multiple repos (5+): +2
      // - High quality repos (10+ stars): +3
      // - Recent activity (updated in 6 months): +2
      // - Very popular top repo (50+ stars): +1
      let exploitSignal = 0;

      if (totalReposFound > 0) exploitSignal += 2; // Any repos found
      if (totalReposFound >= 5) exploitSignal += 2; // Multiple repos
      if (highQualityRepos > 0) exploitSignal += 3; // Quality repos exist
      if (recentRepos > 0) exploitSignal += 2; // Recent activity
      if (pocRepos.length > 0 && pocRepos[0].stars >= 50) exploitSignal += 1; // Very popular PoC

      const exploitPresent = totalReposFound > 0;

      // 8. Format result message
      let message = '';
      if (totalReposFound === 0) {
        message = cveId
          ? `No public exploits found for ${cveId}`
          : `No public exploits found for ${vulnerabilityType}`;
      } else {
        const qualityText = highQualityRepos > 0 ? ` (${highQualityRepos} high-quality)` : '';
        const recentText = recentRepos > 0 ? `, ${recentRepos} recently updated` : '';
        message = `Found ${totalReposFound} PoC repository(ies)${qualityText}${recentText}`;
      }

      console.log(`✅ ${message}`);
      console.log(`   Exploit Signal: ${exploitSignal}/10`);

      return {
        success: true,
        message,
        exploitPresent,
        exploitSignal,
        pocRepos,
        stats: {
          totalReposFound,
          highQualityRepos,
          recentRepos,
        },
      };
    } catch (error: any) {
      console.error('❌ GitHub PoC search failed:', error);

      return {
        success: false,
        message: `Failed to search GitHub: ${error.message}`,
        exploitPresent: false,
        exploitSignal: 0,
        pocRepos: [],
        stats: {
          totalReposFound: 0,
          highQualityRepos: 0,
          recentRepos: 0,
        },
        error: error.message,
      };
    }
  },
});
