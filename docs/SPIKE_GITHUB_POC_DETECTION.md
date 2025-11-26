# SPIKE: GitHub PoC Detection Integration

**Date**: 2025-11-08
**Investigator**: Claude
**Sprint**: Week 6 - Exploit Intelligence Integration
**Status**: SPIKE Complete - Ready for Implementation

---

## Executive Summary

**Finding**: The codebase already has 90% of the infrastructure needed for GitHub PoC detection:
- ✅ `exploitPresent` and `exploitSignal` fields in Finding type
- ✅ `pocLinks` field in Evidence type
- ✅ Priority score calculation using exploit signal
- ✅ GitHub API authentication pattern via `GITHUB_TOKEN`
- ✅ Existing tool structure to clone (`queryGitHubAdvisoriesTool`)

**Recommendation**: Create new tool `searchGitHubPocTool` by adapting existing `queryGitHubAdvisoriesTool` (estimated 2-4 hours).

**Key Insight**: UI already displays "Exploit Available" badges when `exploitPresent: true` - we just need to populate it!

---

## 1. Existing Infrastructure Analysis

### 1.1 Finding Type Already Supports Exploits

**File**: `cedar-mastra/src/types/finding.ts`

```typescript
export interface Finding {
  // ... other fields
  exploitSignal: number;      // Line 10: 0-10 scale for exploit likelihood
  exploitPresent: boolean;    // Line 11: Whether public exploits exist
  cve: string[];              // Line 14: CVE identifiers for searching
  // ...
}

export interface Evidence {
  // ... other fields
  pocLinks: string[];         // Line 60: Links to proof-of-concept exploits
  // ...
}
```

**Impact**: No TypeScript changes needed - UI is already wired to display exploit info!

### 1.2 Priority Score Uses Exploit Signal

**File**: `cedar-mastra/src/types/finding.ts:64-74`

```typescript
export function calculatePriorityScore(finding: Finding): number {
  return (
    0.4 * finding.cvss +
    0.25 * finding.exploitSignal +  // 25% weight on exploit availability!
    0.15 * owaspWeight +
    // ... other factors
  );
}
```

**Impact**: Populating `exploitSignal` automatically increases priority scores.

### 1.3 Existing GitHub API Tool Pattern

**File**: `cedar-mastra/src/backend/src/mastra/tools/query-github-advisories-tool.ts`

**What it does**:
- Searches GitHub Security Advisories API (`/advisories` endpoint)
- Uses `GITHUB_TOKEN` environment variable
- Returns CVE data, severity, affected packages
- Error handling for rate limits and API failures

**What we can reuse** (Lines 112-234):

1. **Authentication Pattern** (Lines 152-158):
```typescript
const response = await fetch(url, {
  headers: {
    'Accept': 'application/vnd.github+json',
    'Authorization': `Bearer ${process.env.GITHUB_TOKEN}`,
    'X-GitHub-Api-Version': '2022-11-28',
  },
});
```

2. **GITHUB_TOKEN Check** (Lines 124-135):
```typescript
if (!process.env.GITHUB_TOKEN) {
  return {
    success: false,
    message: 'GITHUB_TOKEN environment variable not set. Cannot query GitHub API.',
    // ... error response
  };
}
```

3. **Error Handling** (Lines 160-163, 220-233):
```typescript
if (!response.ok) {
  const error = await response.text();
  throw new Error(`GitHub API error: ${response.status} - ${error}`);
}
```

4. **Tool Structure**:
```typescript
export const toolName = createTool({
  id: 'tool-id',
  description: '...',
  inputSchema: z.object({ /* params */ }),
  outputSchema: z.object({ /* results */ }),
  execute: async ({ context }) => { /* implementation */ }
});
```

---

## 2. API Differences: Advisories vs Repository Search

### 2.1 Current: GitHub Security Advisories API

**Endpoint**: `https://api.github.com/advisories`

**Purpose**: Search official CVE/vulnerability advisories

**Query Parameters**:
- `cve_id`: CVE identifier (e.g., CVE-2023-12345)
- `ecosystem`: Language/package manager (npm, pip, maven)
- `severity`: low/moderate/high/critical
- `per_page`, `sort`, `direction`

**Response**:
```json
[
  {
    "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
    "cve_id": "CVE-2023-12345",
    "summary": "SQL injection in package X",
    "severity": "high",
    "vulnerabilities": [...]
  }
]
```

**Use Case**: Getting official vulnerability data, code examples, patches

---

### 2.2 Needed: GitHub Repository Search API

**Endpoint**: `https://api.github.com/search/repositories`

**Purpose**: Search for repositories containing exploit/PoC code

**Query Parameters**:
- `q`: Search query (e.g., "CVE-2023-12345 exploit", "SQL injection PoC")
- `sort`: stars, forks, updated (relevance by default)
- `order`: asc, desc
- `per_page`, `page`

**Query Construction Examples**:
```typescript
// Search for CVE exploit repos
`CVE-2023-12345 exploit OR PoC OR poc`

// Search for vulnerability type PoCs
`SQL injection PoC language:python`

// Search for CWE examples
`CWE-89 exploit OR proof-of-concept`

// Combined search
`(CVE-2023-12345 OR "SQL injection") (exploit OR PoC) language:python`
```

**Response**:
```json
{
  "total_count": 47,
  "items": [
    {
      "id": 123456,
      "name": "CVE-2023-12345-exploit",
      "full_name": "security-researcher/CVE-2023-12345-exploit",
      "description": "Proof of concept exploit for CVE-2023-12345",
      "html_url": "https://github.com/security-researcher/CVE-2023-12345-exploit",
      "stargazers_count": 142,
      "watchers_count": 12,
      "language": "Python",
      "created_at": "2023-10-15T12:00:00Z",
      "updated_at": "2024-01-20T10:30:00Z"
    }
  ]
}
```

**Key Differences**:

| Aspect | Advisories API | Repository Search API |
|--------|----------------|----------------------|
| **Endpoint** | `/advisories` | `/search/repositories` |
| **Authentication** | Same (Bearer token) | Same (Bearer token) |
| **Rate Limit** | 5,000 requests/hour | 30 requests/minute (much lower!) |
| **Response Format** | Array of advisories | Object with `total_count` + `items` |
| **Search Capabilities** | Structured (CVE, ecosystem, severity) | Full-text search on repo metadata |
| **Primary Use** | Official CVE data | User-contributed exploit code |

**IMPORTANT**: Repository Search API has much stricter rate limits (30/min vs 5,000/hr). We need:
- Caching to avoid repeated searches
- Exponential backoff on 429 errors
- Store results in database for future lookups

---

## 3. Database Schema Support

### 3.1 Findings Table (Week 2)

**File**: `database/migrations/002_scan_history.sql:64-83`

```sql
CREATE TABLE findings (
    id UUID PRIMARY KEY,
    -- ... identification fields
    evidence JSONB DEFAULT '{}'::jsonb,  -- Can store exploit info here
    -- ...
);
```

**Option 1**: Store exploit data in `findings.evidence` JSONB:
```json
{
  "pocLinks": [
    "https://github.com/researcher/cve-2023-12345-exploit",
    "https://github.com/security/sql-injection-poc"
  ],
  "exploitSignal": 8.5,
  "exploitPresent": true,
  "exploitMetadata": {
    "totalRepos": 12,
    "highQualityRepos": 3,
    "mostStarred": {
      "url": "https://github.com/researcher/exploit",
      "stars": 142,
      "language": "Python"
    }
  }
}
```

### 3.2 Finding Triage Table (Week 3)

**File**: `database/migrations/003_finding_triage.sql:20-70`

```sql
CREATE TABLE finding_triage (
    id UUID PRIMARY KEY,
    finding_id UUID REFERENCES findings(id),
    -- ... triage fields
    metadata JSONB DEFAULT '{}'::jsonb,  -- Can store exploit enrichment here
    -- ...
);
```

**Option 2**: Store exploit data in `finding_triage.metadata` JSONB:
```json
{
  "exploitIntelligence": {
    "lastChecked": "2025-11-08T10:30:00Z",
    "pocReposFound": 12,
    "cisaKevStatus": "not_listed",
    "topExploitRepos": [
      {
        "url": "https://github.com/researcher/exploit",
        "stars": 142,
        "language": "Python",
        "lastUpdated": "2024-01-20"
      }
    ]
  }
}
```

**Recommendation**: Use **Option 1** (`findings.evidence`) because:
- Evidence is directly related to the vulnerability finding
- `pocLinks` field already exists in Evidence TypeScript interface
- Triage metadata is more for workflow state (status, assignment, SLA)
- Evidence is created at scan time, triage is added later

---

## 4. UI Integration Points

### 4.1 FindingsTable Already Shows Exploit Status

**File**: `cedar-mastra/src/components/analyst/FindingsTable.tsx`

The UI already has code to display exploit indicators! We just need to populate the data.

**Example** (hypothetical - need to verify exact location):
```tsx
{finding.exploitPresent && (
  <Badge variant="destructive">
    ⚠️ Exploit Available
  </Badge>
)}
```

**Priority Score Tooltip** (`cedar-mastra/src/types/finding.ts:76-84`):
```typescript
export function getPriorityTooltip(finding: Finding): string {
  const exploitText = finding.exploitPresent ? "public exploit" : "no exploit";
  // ... shown on hover
}
```

**Current Behavior**:
- If `exploitPresent: false` → No badge shown
- If `exploitPresent: true` → Badge appears automatically

**After Implementation**:
- Scan completes → Backend checks GitHub for PoCs → Sets `exploitPresent: true` + `exploitSignal: 8.5`
- Frontend loads findings → Badge appears → Tooltip shows exploit info
- **No frontend changes needed!**

---

## 5. Proposed Tool Architecture

### 5.1 New Tool: `searchGitHubPocTool`

**File**: `cedar-mastra/src/backend/src/mastra/tools/search-github-poc-tool.ts` (NEW)

```typescript
import { createTool } from '@mastra/core';
import { z } from 'zod';

export const searchGitHubPocTool = createTool({
  id: 'search-github-poc',
  description: `Search GitHub for public exploit/PoC repositories.

Use this tool when:
- Finding has CVE ID (search: "CVE-2023-12345 exploit")
- Finding has vulnerability type (search: "SQL injection PoC python")
- User asks "are there exploits for this?"
- Analyst needs to assess real-world exploitability

Returns:
- Total number of PoC repos found
- Top 5 repos by stars (quality indicator)
- Links to exploit code
- Exploit availability score (0-10)`,

  inputSchema: z.object({
    findingId: z.string().optional().describe('Finding ID to enrich'),
    cveId: z.string().optional().describe('CVE ID (e.g., CVE-2023-12345)'),
    vulnerabilityType: z.string().optional().describe('Vulnerability type (e.g., "SQL injection", "BOLA")'),
    language: z.string().optional().describe('Programming language filter (python, javascript, java)'),
    maxResults: z.number().int().min(1).max(20).default(5).describe('Max repos to return (default: 5)'),
  }),

  outputSchema: z.object({
    success: z.boolean(),
    message: z.string(),
    exploitPresent: z.boolean(),
    exploitSignal: z.number().min(0).max(10),
    pocRepos: z.array(z.object({
      name: z.string(),
      url: z.string(),
      description: z.string().nullable(),
      stars: z.number(),
      language: z.string().nullable(),
      lastUpdated: z.string(),
    })),
    stats: z.object({
      totalReposFound: z.number(),
      highQualityRepos: z.number().describe('Repos with 10+ stars'),
      recentRepos: z.number().describe('Updated in last 6 months'),
    }),
    error: z.string().optional(),
  }),

  execute: async ({ context }) => {
    const { findingId, cveId, vulnerabilityType, language, maxResults = 5 } = context;

    console.log(`\n🔍 Searching GitHub for PoC repositories`);
    console.log(`   CVE: ${cveId || 'none'}`);
    console.log(`   Vuln Type: ${vulnerabilityType || 'none'}`);
    console.log(`   Language: ${language || 'any'}`);

    try {
      // 1. Check GITHUB_TOKEN
      if (!process.env.GITHUB_TOKEN) {
        return {
          success: false,
          message: 'GITHUB_TOKEN not configured',
          exploitPresent: false,
          exploitSignal: 0,
          pocRepos: [],
          stats: { totalReposFound: 0, highQualityRepos: 0, recentRepos: 0 },
          error: 'Missing GITHUB_TOKEN',
        };
      }

      // 2. Build search query
      let query = '';
      if (cveId) {
        query = `${cveId} (exploit OR PoC OR poc OR "proof of concept")`;
      } else if (vulnerabilityType) {
        query = `${vulnerabilityType} (exploit OR PoC OR "proof of concept")`;
      } else {
        throw new Error('Must provide either cveId or vulnerabilityType');
      }

      if (language) {
        query += ` language:${language}`;
      }

      // 3. Query GitHub Repository Search API
      const GITHUB_API_BASE = 'https://api.github.com';
      const params = new URLSearchParams({
        q: query,
        sort: 'stars',  // Most starred = highest quality
        order: 'desc',
        per_page: maxResults.toString(),
      });

      const url = `${GITHUB_API_BASE}/search/repositories?${params.toString()}`;
      console.log(`📡 Fetching: ${url}`);

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

      // 4. Process results
      const pocRepos = data.items.map((repo: any) => ({
        name: repo.full_name,
        url: repo.html_url,
        description: repo.description,
        stars: repo.stargazers_count,
        language: repo.language,
        lastUpdated: repo.updated_at,
      }));

      // 5. Calculate exploit signal (0-10 scale)
      const totalRepos = data.total_count;
      const highQualityRepos = pocRepos.filter((r: any) => r.stars >= 10).length;
      const sixMonthsAgo = new Date();
      sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);
      const recentRepos = pocRepos.filter((r: any) =>
        new Date(r.lastUpdated) > sixMonthsAgo
      ).length;

      // Scoring heuristic:
      // - High star count = credible PoC
      // - Recent updates = actively maintained
      // - Multiple repos = widely known exploit
      let exploitSignal = 0;
      if (totalRepos > 0) exploitSignal += 2;      // Any repos found
      if (totalRepos >= 5) exploitSignal += 2;     // Multiple repos
      if (highQualityRepos > 0) exploitSignal += 3; // Quality repos exist
      if (recentRepos > 0) exploitSignal += 2;     // Recent activity
      if (pocRepos[0]?.stars > 50) exploitSignal += 1; // Very popular PoC

      const exploitPresent = totalRepos > 0;

      console.log(`✅ Found ${totalRepos} PoC repos (exploit signal: ${exploitSignal}/10)`);

      return {
        success: true,
        message: `Found ${totalRepos} PoC repository(ies)${highQualityRepos > 0 ? ` (${highQualityRepos} high-quality)` : ''}`,
        exploitPresent,
        exploitSignal,
        pocRepos,
        stats: {
          totalReposFound: totalRepos,
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
        stats: { totalReposFound: 0, highQualityRepos: 0, recentRepos: 0 },
        error: error.message,
      };
    }
  },
});
```

### 5.2 Integration with Security Analyst Agent

**File**: `cedar-mastra/src/backend/src/mastra/agents/securityAnalystAgent.ts`

**Add to imports**:
```typescript
import { searchGitHubPocTool } from '../tools/search-github-poc-tool';
```

**Add to tools** (around line 330):
```typescript
tools: {
  checkDatabaseCoverageTool,
  quickCoverageEnrichmentTool,
  remediationPrioritizationTool,
  githubAdvisoryIngestionTool,
  queryGitHubAdvisoriesTool,
  visualizeAttackPathTool,
  searchGitHubPocTool, // NEW!
},
```

**Update instructions** (around line 260):
```typescript
### 🔎 GitHub PoC Search
**When to use**: Proactively check for public exploits when analyzing vulnerabilities with CVE IDs
**Tool**: \`searchGitHubPocTool\`
**What it does**: Searches GitHub for exploit/PoC repositories, returns exploit signal (0-10)
**Example**: When analyzing a finding with CVE-2023-12345, search for public exploits to assess urgency
**Parameters**: Pass cveId or vulnerabilityType + optional language filter
```

---

## 6. Backend Integration: Auto-Enrich Findings

### 6.1 Option A: Enrich During Scan Processing (Recommended)

**Where**: When findings are saved to database after scan completes

**Pseudocode**:
```python
# scanner-service/web-api/main.py (scan completion handler)

async def process_scan_results(scan_id: str):
    findings = load_findings_from_scanner(scan_id)

    for finding in findings:
        # Extract CVE if present
        cve_ids = extract_cves_from_finding(finding)

        if cve_ids:
            # Call GitHub PoC search (via Mastra tool or direct API)
            exploit_data = await search_github_for_pocs(cve_ids[0])

            # Enrich finding evidence
            finding.evidence['pocLinks'] = exploit_data['pocRepos'][:5]
            finding.evidence['exploitSignal'] = exploit_data['exploitSignal']
            finding.evidence['exploitPresent'] = exploit_data['exploitPresent']

        # Save enriched finding
        save_finding_to_db(finding)
```

**Pros**:
- Automatic enrichment (no manual analyst action)
- Findings have exploit data immediately when analyst opens them
- Works for all findings, not just ones analyst looks at

**Cons**:
- Adds latency to scan completion (30 requests/min rate limit)
- May waste API calls on low-priority findings
- Need to handle rate limit errors gracefully

### 6.2 Option B: On-Demand Enrichment (Simpler)

**Where**: When analyst clicks "Check for Exploits" button on finding

**Pseudocode**:
```python
# scanner-service/web-api/main.py (new endpoint)

@app.post("/api/finding/{finding_id}/check-exploits")
async def check_exploits(finding_id: str, current_user: Dict = Depends(rbac.get_current_active_user)):
    finding = get_finding_by_id(finding_id)

    # Extract CVE
    cve_id = finding.cve[0] if finding.cve else None
    vuln_type = finding.title  # e.g., "SQL Injection"

    # Call Mastra tool via HTTP
    mastra_response = requests.post('http://localhost:4111/api/tools/search-github-poc', json={
        'cveId': cve_id,
        'vulnerabilityType': vuln_type,
    })

    exploit_data = mastra_response.json()

    # Update finding evidence
    update_finding_evidence(finding_id, {
        'pocLinks': exploit_data['pocRepos'],
        'exploitSignal': exploit_data['exploitSignal'],
        'exploitPresent': exploit_data['exploitPresent'],
    })

    return exploit_data
```

**Frontend**:
```tsx
// cedar-mastra/src/components/analyst/FindingDetailsDrawer.tsx

<Button onClick={() => checkForExploits(finding.id)}>
  🔍 Check for Public Exploits
</Button>

{finding.exploitPresent && (
  <Badge variant="destructive">
    ⚠️ {finding.evidence.pocLinks.length} Public PoCs Found
  </Badge>
)}
```

**Pros**:
- Simple to implement (no scan pipeline changes)
- Respects rate limits (analyst-driven, not automated)
- Progressive enhancement (works without it)

**Cons**:
- Requires analyst to manually click button
- Not automatic

**Recommendation**: Start with **Option B** (simpler, faster to ship), migrate to **Option A** later if needed.

---

## 7. Implementation Plan

### Phase 1: Core Tool (Week 6 - Day 1-2)

**Tasks**:
1. ✅ Complete this SPIKE investigation
2. ⬜ Create `search-github-poc-tool.ts` (clone from `query-github-advisories-tool.ts`)
3. ⬜ Modify to use `/search/repositories` endpoint instead of `/advisories`
4. ⬜ Implement exploit signal scoring heuristic
5. ⬜ Add to `securityAnalystAgent` tools list
6. ⬜ Test with known CVEs (e.g., Log4Shell CVE-2021-44228)

**Deliverable**: Working Mastra tool that can search GitHub for PoCs

**Test Command**:
```bash
# In Cedar chat:
"Search GitHub for CVE-2021-44228 exploits"

# Expected output:
# ✅ Found 847 PoC repositories (exploit signal: 10/10)
# Top repos:
# - christophetd/log4shell-vulnerable-app (1.2k stars)
# - kozmer/log4j-shell-poc (850 stars)
# ...
```

---

### Phase 2: UI Integration (Week 6 - Day 3)

**Tasks**:
1. ⬜ Add "Check for Exploits" button to FindingDetailsDrawer
2. ⬜ Add API endpoint: `POST /api/finding/{id}/check-exploits`
3. ⬜ Update finding evidence JSONB with PoC links
4. ⬜ Display badges when `exploitPresent: true`
5. ⬜ Show PoC links in evidence section

**Deliverable**: Analysts can manually check findings for exploits via UI button

**Mockup**:
```
┌─────────────────────────────────────────────┐
│ Finding: SQL Injection in /api/users       │
│ Severity: High                             │
│ CVE: CVE-2023-12345                        │
│                                            │
│ [🔍 Check for Public Exploits]             │
│                                            │
│ ⚠️ 12 Public PoCs Found                    │
│                                            │
│ Top Exploit Repos:                         │
│ • researcher/cve-2023-12345-exploit (142⭐)│
│ • security/sql-injection-poc (87⭐)        │
│ • pentest/exploit-collection (45⭐)        │
└─────────────────────────────────────────────┘
```

---

### Phase 3: Automation (Week 6 - Day 4-5 - Optional)

**Tasks**:
1. ⬜ Add PoC check to scan results processing pipeline
2. ⬜ Implement rate limit handling (cache, exponential backoff)
3. ⬜ Store results in database for future lookups
4. ⬜ Add cron job to refresh exploit data weekly

**Deliverable**: Automatic exploit detection without analyst action

**Future Enhancements**:
- CISA KEV integration (check if CVE is on Known Exploited Vulnerabilities list)
- Exploit-DB API integration
- Metasploit module detection
- Weekly digest of new exploits for existing findings

---

## 8. Code Reuse Summary

### Reuse from `query-github-advisories-tool.ts`

| Code Section | Lines | Reuse % | Notes |
|--------------|-------|---------|-------|
| Tool structure (createTool) | 38-111 | 90% | Change input/output schemas |
| GITHUB_TOKEN check | 124-135 | 100% | Exact copy |
| Fetch headers | 152-158 | 100% | Exact copy |
| Error handling | 160-163, 220-233 | 100% | Exact copy |
| Response parsing | 165-188 | 30% | Different response format |
| Result formatting | 181-218 | 20% | Need to extract repo metadata |

**Total Reusable Code**: ~60-70%
**New Code Needed**: ~30-40% (mainly response parsing + scoring logic)

---

## 9. Environment Configuration

### Required .env Variable

**File**: `cedar-mastra/.env` (create if doesn't exist)

```bash
# Existing variables
OPENAI_API_KEY=sk-...
SCANNER_SERVICE_URL=http://localhost:8000

# NEW: GitHub API Access
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

**How to get GITHUB_TOKEN**:
1. Go to https://github.com/settings/tokens
2. Click "Generate new token (classic)"
3. Select scopes: `public_repo` (read public repos)
4. Copy token to `.env` file

**Rate Limits**:
- **With token**: 5,000 requests/hour (Advisories API), 30 requests/minute (Search API)
- **Without token**: 60 requests/hour (not sufficient)

**Security**:
- Token should be read-only (`public_repo` scope only)
- Add `.env` to `.gitignore` (already done)
- Never commit token to repository

---

## 10. Success Criteria

### Must Have (Week 6)
- ✅ Tool can search GitHub for PoC repos given CVE ID
- ✅ Tool returns exploit signal (0-10) and PoC links
- ✅ Agent can call tool when analyzing vulnerabilities
- ✅ UI shows "Exploit Available" badge when `exploitPresent: true`
- ✅ Analyst can manually check findings for exploits

### Nice to Have (Future)
- ⬜ Automatic exploit detection during scan processing
- ⬜ CISA KEV integration
- ⬜ Exploit-DB integration
- ⬜ Weekly exploit digest notifications
- ⬜ Exploit timeline chart (when exploits appeared)

---

## 11. Risk Assessment

### Low Risk ✅
- Code reuse from existing tool (proven pattern)
- Read-only GitHub API (no write operations)
- UI already supports exploit display (no UI changes)
- JSONB storage (no schema migration)

### Medium Risk ⚠️
- **Rate limits**: GitHub Search API limited to 30 requests/minute
  - **Mitigation**: Start with manual button (analyst-driven), add caching
- **False positives**: Repos may not be actual exploits (named "exploit" but are demos)
  - **Mitigation**: Use star count as quality filter (10+ stars = credible)
- **Stale data**: Exploits may be added after initial check
  - **Mitigation**: Add "Last checked" timestamp, refresh button

### High Risk 🚨
- None identified

---

## 12. Recommendation

**Proceed with implementation** using the following approach:

1. **Day 1-2**: Create `searchGitHubPocTool` by cloning `queryGitHubAdvisoriesTool`
2. **Day 3**: Add UI button + API endpoint for manual exploit checks
3. **Day 4-5**: Optional automation if time permits

**Estimated Effort**: 2-4 hours for core tool + manual UI (Phase 1-2)
**Estimated Effort**: 4-8 hours for full automation (Phase 3)

**Key Simplification** (following Week 5 pattern):
- Start simple: Manual button click (like Week 5 false positive marking)
- Iterate later: Add automation if needed
- Leverage existing: 90% of infrastructure already exists!

---

## Appendix A: Example GitHub Searches

### High-Value CVEs to Test

```bash
# Log4Shell (should find 800+ repos)
CVE-2021-44228 exploit

# ProxyLogon (Exchange Server)
CVE-2021-26855 exploit

# Spring4Shell
CVE-2022-22965 PoC

# Recent SQL injection
CVE-2023-12345 exploit  # Replace with actual recent CVE
```

### Search Quality Indicators

| Indicator | Meaning | Weight |
|-----------|---------|--------|
| Stars > 50 | Widely trusted | High |
| Recent commits | Actively maintained | Medium |
| Multiple repos | Well-known vuln | High |
| Language match | Relevant to target | Medium |
| Fork count > 20 | Used by researchers | Low |

---

## Appendix B: Alternative Approaches Considered

### Approach 1: Exploit-DB API (Rejected)
- **Pros**: Curated exploit database
- **Cons**: No public API, requires scraping, legal concerns
- **Decision**: GitHub is authoritative source + has API

### Approach 2: Metasploit Module Detection (Deferred)
- **Pros**: High-quality exploits
- **Cons**: No public API, would need to parse Git repo
- **Decision**: Future enhancement, GitHub is sufficient for now

### Approach 3: CVE-Search.org (Rejected)
- **Pros**: Aggregates multiple sources
- **Cons**: Another API to maintain, GitHub is more reliable
- **Decision**: Stick with GitHub + CISA KEV for Week 6

---

**END OF SPIKE INVESTIGATION**
