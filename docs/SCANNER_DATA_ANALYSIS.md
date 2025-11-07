# VentiAPI Scanner Data Structure & Explainability Layer Analysis

## Executive Summary

The VentiAPI Scanner is a modular API security testing platform that captures vulnerability data across the **OWASP API Security Top 10**. The system supports multiple scanner engines (VentiAPI, OWASP ZAP, Nuclei) with a unified JSON finding format, enabling AI-powered explainability at different personas (executive, analyst, developer).

---

## 1. Vulnerability Finding Structure

### Core Finding Model (scanner/core/models.py)

```python
class Finding(BaseModel):
    rule: str                          # API Rule ID (e.g., "API1", "API2")
    title: str                         # Human-readable title
    severity: str                      # Low, Medium, High, Critical
    score: float                       # Risk score (0-10, calculated)
    endpoint: str                      # API path (e.g., "/users/v1")
    method: str                        # HTTP method (GET, POST, etc.)
    description: str                   # Detailed description
    evidence: Dict[str, Any] = {}      # Probe-specific evidence data
```

### Real Example (findings.json)

```json
{
  "rule": "API2",
  "title": "Broken Authentication",
  "severity": "High",
  "score": 7.2,
  "endpoint": "/users/v1",
  "method": "GET",
  "description": "Endpoint returns success for unauthenticated/invalid credentials requests.",
  "evidence": {
    "unauth": {
      "status": 200,
      "headers": {"content-type": "application/json"},
      "len": 236,
      "excerpt": "{\n  \"users\": [\n    {\n      \"email\": \"mail1@mail.com\",\n      \"username\": \"name1\"\n    }"
    },
    "bogus": {
      "status": 200,
      "headers": {"content-type": "application/json"},
      "len": 236,
      "excerpt": "same response without auth"
    }
  }
}
```

---

## 2. OWASP API Top 10 Mappings & Probe Details

Each probe tests for specific vulnerability categories with specialized evidence collection:

### API1: Broken Object Level Authorization (BOLA)

**Probe**: `scanner/probes/bola.py`

**Detection Logic**:
- Targets GET endpoints with ID parameters (e.g., `/users/{id}`)
- Tests access to different object IDs (1 vs 2) without authentication
- Flags if both return 200/206 status codes

**Evidence Captured**:
```
evidence:
  resp1:                    # Response for ID=1
    status: 200
    headers: {content-type, retry-after, rate-limit headers}
    excerpt: "first 200 chars of response"
  resp2:                    # Response for ID=2
    status: 200
    headers: {...}
    excerpt: "..."
```

**Data Quality**: Direct HTTP response comparison; straightforward for explanation

---

### API2: Broken Authentication

**Probe**: `scanner/probes/auth_matrix.py`

**Detection Logic**:
- Tests endpoints with: no auth, invalid bearer token, optional basic auth
- Flags if any return success (200-206) without credentials

**Evidence Captured**:
```
evidence:
  unauth:           # No Authorization header
    status: 200
    headers: {...}
  bogus:            # Bearer invalid.invalid.invalid
    status: 200
    headers: {...}
  basic_default:    # Basic auth with "admin:admin"
    status: 200
    headers: {...}
```

**Data Quality**: Multiple authentication scenarios tested; clear failure criteria

---

### API3: Excessive Data Exposure

**Probe**: `scanner/probes/exposure.py`

**Detection Logic**:
- Parses JSON responses from GET endpoints
- Searches for sensitive field names: password, token, secret, apiKey, ssn, dob, email
- Case-insensitive field name matching

**Evidence Captured**:
```
evidence:
  fields: ["email", "password"]      # Sensitive fields found
  sample:
    status: 200
    headers: {...}
    excerpt: "..."
```

**Data Quality**: Field-name heuristic only; prone to false positives (e.g., "email" in "username")

**Gap**: No data classification or sensitivity weighting

---

### API4: Lack of Rate Limiting

**Probe**: `scanner/probes/ratelimit.py`

**Detection Logic**:
- Sends 15 parallel burst requests to health/status endpoint
- Checks for 429 (Too Many Requests) response
- Checks for rate-limit headers: X-RateLimit-Remaining, Retry-After

**Evidence Captured**:
```
evidence:
  statuses: [200, 200, 200, 200, ..., 200]  # First 10 response codes
  headers_sample: [
    {},                              # Sample 1: no rate limit headers
    {},                              # Sample 2
    {}                               # Sample 3
  ]
```

**Data Quality**: Quantitative metric; clear pass/fail

---

### API5: Broken Function Level Authorization (BFLA)

**Probe**: `scanner/probes/bfla.py`

**Detection Logic**:
- Identifies admin-tagged endpoints (admin in path or tags)
- Tests access without credentials
- Flags if successful (200-204)

**Evidence Captured**:
```
evidence:
  response:
    status: 200
    headers: {...}
    len: 382
    excerpt: "..."
```

**Data Quality**: Tag-based detection; limited without explicit authorization metadata

---

### API6: Mass Assignment

**Probe**: `scanner/probes/mass_assign.py`

**Detection Logic**:
- Only runs in `dangerous` mode (requires explicit opt-in)
- Sends POST/PUT/PATCH with sensitive fields: role, isAdmin, ownerId, balance
- Flags if server accepts with 200-202 response

**Evidence Captured**:
```
evidence:
  request: {"role": true, "isAdmin": true, ...}
  response:
    status: 201
    headers: {...}
    excerpt: "..."
```

**Data Quality**: Direct field-mutation test; clear binary result

---

### API7: Security Misconfiguration

**Probe**: `scanner/probes/misconfig.py`

**Detection Logic**:
1. Plain HTTP check (server_base starts with http://)
2. CORS check via OPTIONS preflight:
   - Access-Control-Allow-Origin: * + Credentials=true
3. HSTS check (missing on HTTPS servers)

**Evidence Captured**:
```
evidence:
  server_base: "http://localhost:5002"
  status: 200
  headers: {"Access-Control-Allow-Origin": "*"}
  hsts_missing: true
  cors: ["CORS allows any origin with credentials=true"]
```

**Data Quality**: Multiple configuration checks; specific remediation paths

---

### API8: Injection

**Probe**: `scanner/probes/injection.py`

**Detection Logic**:
- Tests GET endpoints with fuzzing payloads:
  - Query params: SQL injection, path traversal, XSS, XXE
  - Headers: User-Agent fuzzing
  - JSON body (dangerous mode): JSON injection
- Detects error patterns: SQL syntax, MongoDB, traceback, stack trace

**Payloads Tested**:
```
Query fuzz:
  - ' OR '1'='1
  - " OR "1"="1
  - ')--
  - ../../etc/passwd
  - <script>alert(1)</script>
  - <?xml ...XXE payload...?>

Headers:
  - User-Agent: ' OR '1'='1

Body (dangerous):
  - {"name": " OR \"1\"=\"1"}
```

**Evidence Captured**:
```
evidence:
  status: 500
  param: "q"
  payload: "' OR '1'='1"
  excerpt: "SQL syntax error near..."
```

**Data Quality**: Pattern-based detection; moderate false positive risk

---

### API9: Improper Assets Management

**Probe**: `scanner/probes/inventory.py`

**Detection Logic**:
1. Alternate method detection:
   - For each GET endpoint, try HEAD/POST/PUT/DELETE
   - Flag if undocumented method succeeds (200-204)
2. Hidden endpoint discovery:
   - Guess common suffixes: search, _search, export, debug, internal, v1, v2
   - Flag if responds with 200-204

**Evidence Captured**:
```
evidence:
  status: 200
  hint: "alt-method" | "hidden-sibling"
```

**Data Quality**: Discovery-based; high risk of false positives (valid alternative methods)

**Gap**: No context about whether alternate methods are intentional

---

### API10: Insufficient Logging & Monitoring

**Probe**: `scanner/probes/logging.py`

**Detection Logic**:
- Sends 5 requests with invalid bearer token
- Checks for correlation headers: X-Request-Id, X-Correlation-Id, Trace-Id, X-Trace-Id
- Flags if: no correlation headers AND (success responses OR inconsistent status codes)

**Evidence Captured**:
```
evidence:
  codes: [200, 200, 200, 200, 200]      # Response codes from 5 requests
  obs_headers_seen: 0                   # Count of correlation headers found
```

**Data Quality**: Indirect heuristic; false positives if API doesn't use correlation IDs

---

## 3. Risk Scoring System

### Severity Calculation (scanner/scoring/risk.py)

```python
# Default scores per API rule (likelihood, impact)
DEFAULT_SCORES = {
    "API1": (0.9, 0.9),      # BOLA: Very likely, very impactful
    "API2": (0.8, 0.9),      # Auth: Very likely, critical
    "API3": (0.6, 0.7),      # Exposure: Moderate, moderate
    "API4": (0.5, 0.6),      # Rate Limiting: Less critical
    "API5": (0.8, 0.9),      # BFLA: Very likely, critical
    "API6": (0.7, 0.8),      # Mass Assignment: Likely, significant
    "API7": (0.6, 0.8),      # Misconfiguration: Moderate, significant
    "API8": (0.6, 0.8),      # Injection: Moderate, very significant
    "API9": (0.5, 0.6),      # Asset Management: Moderate, moderate
    "API10": (0.4, 0.5),     # Logging: Less critical
}

# Score calculation: likelihood * impact * 10
score = round(likelihood * impact * 10, 1)

# Severity bucketing
SEV_BUCKETS = [
    (9, "Critical"),     # score >= 9
    (7, "High"),         # score >= 7
    (4, "Medium"),       # score >= 4
    (1, "Low"),          # score >= 1
    (0, "Info")          # score >= 0
]
```

### Example Scoring

```
API1 (BOLA):     0.9 * 0.9 * 10 = 8.1 → "High"
API2 (Auth):     0.8 * 0.9 * 10 = 7.2 → "High"
API3 (Exposure): 0.6 * 0.7 * 10 = 4.2 → "Medium"
API4 (Rate Lim): 0.5 * 0.6 * 10 = 3.0 → "Low"
```

**Customization**: Scores can be overridden per-finding with custom likelihood/impact values

---

## 4. Multi-Scanner Aggregation

### Scanner Integration Architecture

The system supports parallel execution of multiple scanners through `scanner_engines.py`:

#### VentiAPI Scanner
- **Type**: API-specific security testing
- **Output**: `/shared/results/{scan_id}_ventiapi/findings.json`
- **Format**: Array of Finding objects (native format)
- **Engine**: VentiAPI Scanner Docker image

#### OWASP ZAP Scanner
- **Type**: General web vulnerability scanner
- **Output**: `/shared/results/zap/{scan_id}_zap.json`
- **Format**: ZAP JSON format (site[0].alerts[])
- **Parsing Transformation** (main.py, parse_zap_results):
```python
# ZAP structure:
{
  "site": [{
    "alerts": [{
      "pluginid": "10010",
      "name": "Cookie without HttpOnly flag",
      "riskcode": "2",           # 3=High, 2=Medium, 1=Low, 0=Info
      "desc": "Description",
      "solution": "Remediation",
      "reference": "URL",
      "cweid": "614",
      "wascid": "4",
      "instances": [{
        "uri": "http://localhost:8080/path",
        "method": "GET"
      }]
    }]
  }]
}

# Normalized to Finding:
{
  "rule": "10010",
  "title": "Cookie without HttpOnly flag",
  "severity": "Medium",           # Mapped from riskcode
  "score": 5,                     # Mapped from severity
  "endpoint": "/path",
  "method": "GET",
  "scanner": "zap",
  "evidence": {
    "alert_ref": "ref_value",
    "solution": "...",
    "reference": "...",
    "cwe_id": "614",
    "wasc_id": "4"
  }
}
```

#### Nuclei Scanner (Planned)
- **Type**: Community-powered vulnerability detection
- **Output Format**: JSONL (one JSON object per line)
- **Normalization**: Template-ID → rule, severity mapping

### Aggregation in API Response

**Endpoint**: `GET /api/scan/{scan_id}/findings`

```python
# Returns findings organized by scanner
{
  "scan_id": "abc123",
  "total": 15,
  "findings": [
    {
      "rule": "API2",
      "title": "Broken Authentication",
      "severity": "High",
      "score": 7.2,
      "endpoint": "/users/v1",
      "method": "GET",
      "scanner": "ventiapi",                              # ← Scanner attribution
      "scanner_description": "VentiAPI - OWASP API...",
      "evidence": {...}
    },
    {
      "rule": "10010",
      "title": "Cookie without HttpOnly flag",
      "severity": "Medium",
      "score": 5,
      "endpoint": "/",
      "method": "GET",
      "scanner": "zap",                                   # ← Different scanner
      "scanner_description": "OWASP ZAP - Web...",
      "evidence": {
        "alert_ref": "...",
        "solution": "...",
        "cwe_id": "614"
      }
    }
  ]
}
```

**Report Endpoint**: `GET /api/scan/{scan_id}/report`

```python
# Comprehensive report with scanner breakdown
{
  "scan_id": "abc123",
  "scan_status": "completed",
  "scanners_used": ["ventiapi", "zap"],
  "total_findings": 15,
  "summary": {
    "total_scanners": 2,
    "total_findings": 15,
    "severity_breakdown": {
      "critical": 0,
      "high": 5,
      "medium": 7,
      "low": 3
    }
  },
  "scanner_stats": {
    "ventiapi": {
      "total_findings": 11,
      "critical": 0,
      "high": 5,
      "medium": 4,
      "low": 2,
      "scanner_description": "VentiAPI - OWASP API..."
    },
    "zap": {
      "total_findings": 4,
      "critical": 0,
      "high": 0,
      "medium": 3,
      "low": 1,
      "scanner_description": "OWASP ZAP - Web..."
    }
  },
  "scanner_configs": {
    "ventiapi": {
      "scanner_name": "ventiapi",
      "scan_type": "api-specific",
      "endpoints_scanned": 20,
      "total_endpoints": 25
    },
    "zap": {
      "scanner_name": "zap",
      "scan_type": "baseline",
      "endpoints_scanned": 25
    }
  },
  "findings_by_scanner": {
    "ventiapi": [...],
    "zap": [...]
  }
}
```

---

## 5. Available Metadata Fields Per Finding

### Universal Fields (All Scanners)
```
rule               # Vulnerability rule/CVE ID
title              # Human-readable title
severity           # Low, Medium, High, Critical, Info
score              # Numeric risk score (0-10)
endpoint           # API path affected
method             # HTTP method (GET, POST, etc.)
description        # Detailed finding description
scanner            # Source scanner name
scanner_description # Scanner tool description
evidence           # Probe-specific evidence (dict)
```

### VentiAPI-Specific Evidence Fields

**BOLA (API1)**:
```
resp1: {status, headers, len, excerpt}
resp2: {status, headers, len, excerpt}
```

**Auth (API2)**:
```
unauth: {status, headers, len, excerpt}
bogus: {status, headers, len, excerpt}
basic_default: {status, headers, len, excerpt} (optional)
```

**Exposure (API3)**:
```
fields: [list of sensitive field names]
sample: {status, headers, len, excerpt}
```

**Rate Limiting (API4)**:
```
statuses: [array of response codes]
headers_sample: [array of rate-limit header objects]
```

**Mass Assignment (API6)**:
```
request: {payload sent}
response: {status, headers, len, excerpt}
```

**Misconfiguration (API7)**:
```
server_base: "http://localhost:5002"
status: 200
headers: {full header dict}
hsts_missing: boolean
cors: [list of CORS issues]
```

**Injection (API8)**:
```
status: 500
param: "q"            # or "header" or "json_key"
payload: "injection payload"
excerpt: "error message excerpt"
```

**Asset Management (API9)**:
```
status: 200
hint: "alt-method" | "hidden-sibling"
```

**Logging (API10)**:
```
codes: [array of 5 response codes]
obs_headers_seen: 0 | 1 | 2 | ...
```

### ZAP-Specific Evidence Fields

```
alert_ref: "10010"                       # ZAP plugin reference
solution: "Ensure the HttpOnly flag..."
reference: "https://owasp.org/..."
cwe_id: "614"                            # MITRE CWE ID
wasc_id: "4"                             # Web Application Security Consortium ID
```

### Nuclei-Specific Evidence Fields

```
template: "template-id"
severity: "critical" | "high" | "medium" | "low" | "info"
description: "vulnerability description"
url: "matched-at URL"
```

---

## 6. Data Gaps for Explainability Dashboards

### Critical Gaps

1. **Confidence Score / Detection Certainty**
   - Current state: Binary detection (found or not found)
   - Gap: No confidence metric on false positives
   - Impact: Analyst can't distinguish high-confidence from heuristic detections
   - Example: API9 (hidden endpoints) has 30-50% false positive rate
   - Recommendation: Add `confidence: 0.0-1.0` field to each finding

2. **Remediation Steps (Persona-Specific)**
   - Current state: Generic OWASP descriptions available in ZAP reference
   - Gap: No actionable step-by-step remediation per technology stack
   - Impact: Developers don't know how to fix issues
   - Example: API2 (broken auth) fix depends on: JWT vs OAuth vs API keys vs mTLS
   - Recommendation: Add `remediation_steps: [...]` with code examples per stack

3. **Context & Root Cause Analysis**
   - Current state: Just detection evidence (response codes, headers)
   - Gap: No explanation of WHY the vulnerability exists
   - Impact: Executives see "high risk" but can't understand business impact
   - Example: Rate limiting missing due to: reversed proxy handling it / API tier service limitation / developer oversight
   - Recommendation: Add `root_cause_categories: ["misconfiguration" | "design" | "missing_implementation"]`

4. **Business Impact & Attack Scenarios**
   - Current state: Technical severity only
   - Gap: No business context or attack chain
   - Impact: Executive dashboard shows "High" but executives need to understand impact
   - Example: API3 (exposure) of email is lower risk than API3 of SSN
   - Recommendation: Add `business_impact: {...}` with data classification

5. **Temporal/Trend Data**
   - Current state: Point-in-time scan results
   - Gap: No historical comparison or trend analysis
   - Impact: Can't show improvement/regression over time
   - Recommendation: Track findings with timestamps and status (new/recurring/resolved)

6. **Affected User/Resource Count**
   - Current state: Single endpoint flagged
   - Gap: No estimate of affected resources or users
   - Impact: Prioritization based on technical risk alone
   - Example: API1 BOLA on /users/{id} affects ALL users vs /test-endpoint/{id} affects nothing
   - Recommendation: Add `affected_resources: [...]` and `user_impact_estimate: "..."

7. **Testing Coverage Metrics**
   - Current state: Just finding counts
   - Gap: No metric on endpoints tested vs total endpoints
   - Impact: Can't determine if scan was thorough
   - Example: Scanned 15/25 endpoints due to request budget
   - Recommendation: Add `scan_coverage: {endpoints_total, endpoints_tested, ...}`

8. **CVSS/CVSSV3 Scoring**
   - Current state: Custom likelihood * impact formula
   - Gap: No industry-standard CVSS alignment
   - Impact: Can't compare with industry benchmarks
   - Recommendation: Add `cvss_v3: "CVSS:3.1/AV:N/AC:L/..."` vector

9. **Detection Method / Test Type**
   - Current state: Implicit in evidence
   - Gap: No explicit classification of detection (active, passive, heuristic)
   - Impact: Analyst can't validate testing approach
   - Recommendation: Add `detection_type: "active_test" | "passive_analysis" | "heuristic"` and `testing_approach: "..."`

10. **Proof of Concept / Reproduction Steps**
    - Current state: Evidence shows raw data
    - Gap: No explicit steps to reproduce
    - Impact: Developers can't verify the issue
    - Recommendation: Add `poc_steps: [...]` with curl/code examples

---

## 7. Data Availability by Persona

### Executive Dashboard Needs

**Currently Available**:
- Total findings count
- Severity distribution (critical/high/medium/low)
- Scanner attribution

**Missing for Executive Context**:
- Business impact metrics (affected users, data sensitivity, revenue risk)
- Trend over time (improving/worsening)
- Risk prioritization (which fix first?)
- Compliance impact (GDPR, PCI, HIPAA)

**Recommended Fields**:
```
{
  "business_impact": {
    "data_sensitivity": "PII | PHI | Financial | Public",
    "affected_users_estimate": 1000000,
    "attack_complexity": "low | medium | high",
    "compliance_violation": ["GDPR", "PCI-DSS"]
  },
  "risk_priority": 1-5,
  "trend": "improving | stable | worsening",
  "days_since_detection": 45
}
```

### Security Analyst Dashboard Needs

**Currently Available**:
- Full finding details
- Evidence data
- Multi-scanner attribution
- Rule/API mapping

**Missing for Analyst Triage**:
- False positive likelihood
- Known exploits in the wild
- Similar findings in adjacent endpoints
- Mitigation complexity estimate

**Recommended Fields**:
```
{
  "confidence": 0.85,
  "likelihood_false_positive": 0.1,
  "similar_findings": ["endpoint2", "endpoint3"],
  "known_exploits": ["CVE-2023-1234"],
  "mitigation_effort": "1-2 days",
  "detection_method_notes": "Endpoint returned 200 without auth check"
}
```

### Developer Dashboard Needs

**Currently Available**:
- Endpoint path
- HTTP method
- Description
- Evidence showing the problem

**Missing for Developers**:
- Step-by-step remediation code
- Technology-specific guidance (Node.js/Python/Go/Java)
- Security best practices links
- Test case to verify fix

**Recommended Fields**:
```
{
  "remediation": {
    "steps": [
      "1. Add auth middleware to route",
      "2. Verify JWT token validity",
      "3. Check user permissions"
    ],
    "code_examples": {
      "nodejs": "const verify = require('...')",
      "python": "from fastapi import Depends",
      "go": "middleware.Auth(...)"
    },
    "test_case": "curl -H 'Authorization: Bearer invalid' ...",
    "related_docs": ["https://owasp.org/..."]
  },
  "affected_code_location": "src/routes/users.js:45",
  "framework_specific_fix": "Express: use authenticateToken middleware"
}
```

---

## 8. Complete Finding Example (Multi-Field)

```json
{
  "rule": "API2",
  "title": "Broken Authentication",
  "severity": "High",
  "score": 7.2,
  "endpoint": "/users/v1",
  "method": "GET",
  "description": "Endpoint returns success for unauthenticated/invalid credentials requests.",
  "scanner": "ventiapi",
  "scanner_description": "VentiAPI - OWASP API Security Top 10",
  
  "evidence": {
    "unauth": {
      "status": 200,
      "headers": {"content-type": "application/json"},
      "len": 236,
      "excerpt": "{ \"users\": [...] }"
    },
    "bogus": {
      "status": 200,
      "headers": {"content-type": "application/json"},
      "len": 236
    }
  },

  "metadata": {
    "detection_type": "active_test",
    "testing_approach": "unauthenticated_access_attempt",
    "confidence": 0.95,
    "likelihood_false_positive": 0.02
  },

  "impact": {
    "data_sensitivity": "PII",
    "affected_endpoints_similar": ["/users/v1/_debug", "/books/v1"],
    "affected_users_estimate": 500000,
    "business_impact_category": "unauthorized_data_access"
  },

  "remediation": {
    "steps": [
      "1. Add JWT verification middleware",
      "2. Extract userId from token",
      "3. Verify user can only access their own data"
    ],
    "code_example_nodejs": "app.use('/users', authenticateJWT);",
    "complexity": "medium",
    "priority": 1,
    "test_verification": "curl -H 'Authorization: Bearer invalid' http://api/users/v1 should return 401"
  },

  "trend": {
    "first_detected": "2024-01-15",
    "last_detected": "2024-01-20",
    "status": "recurring",
    "days_open": 5
  }
}
```

---

## 9. Summary: Data Ready for AI Explainability

### Strong Signals for AI Analysis

1. **Evidence Data**: Rich HTTP response details enable reconstruction of attacks
2. **Rule Mapping**: All findings map to OWASP API Top 10 with consistent scoring
3. **Multi-Scanner Attribution**: Can explain which tool discovered which vulnerability
4. **Endpoint Context**: Path + method provides API surface understanding
5. **Temporal Potential**: API includes scan timestamps enabling trend analysis

### Data Enrichment Opportunities

1. **Confidence Scoring**: Add ML-based false positive detection
2. **Remediation Chains**: Build decision trees for tech-stack-specific fixes
3. **Business Mapping**: Link findings to data classifications and compliance
4. **Context Enrichment**: Pull endpoint documentation and framework info
5. **Exploit Intelligence**: Integrate CVE/exploit databases
6. **Trend Analysis**: Compare findings across scans to show improvement

---

## 10. Recommended Additions for Explainability

### Short-term (Low effort, high impact)

1. Add `confidence: 0.0-1.0` to Finding model
2. Add `remediation_summary: "..."` string to each finding type
3. Add `test_verification: "..."` showing how to verify fix
4. Add `affected_count: N` for batch findings (e.g., API9 hidden endpoints)

### Medium-term (Medium effort, medium impact)

1. Build `remediation_templates` by framework/language
2. Add `severity_justification: "..."` explaining the score calculation
3. Implement trend tracking (findings table with created/resolved dates)
4. Add `related_findings: [...]` linking similar issues

### Long-term (High effort, high value)

1. CVSS v3.1 vector generation
2. Business impact metadata and compliance mapping
3. False positive ML classifier
4. Automatic remediation code generation
5. Integration with known exploit databases

---

## 11. Key Files Reference

**Core Models**: `/home/user/295capstone-assembly/scanner-service/scanner/core/models.py`
**Probes**: `/home/user/295capstone-assembly/scanner-service/scanner/probes/` (10 files)
**Analysis/Mapping**: `/home/user/295capstone-assembly/scanner-service/scanner/analysis/mapping.py`
**Risk Scoring**: `/home/user/295capstone-assembly/scanner-service/scanner/scoring/risk.py`
**Report Rendering**: `/home/user/295capstone-assembly/scanner-service/scanner/report/render.py`
**API Endpoints**: `/home/user/295capstone-assembly/scanner-service/web-api/main.py`
**Multi-Scanner**: `/home/user/295capstone-assembly/scanner-service/web-api/scanner_engines.py`
**Example Output**: `/home/user/295capstone-assembly/scanner-service/results/findings.json`

