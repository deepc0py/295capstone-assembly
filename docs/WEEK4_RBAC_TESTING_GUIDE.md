# Week 4 RBAC Testing Guide

Complete testing guide for the RBAC & Organization Isolation implementation.

## 🎯 What Was Implemented

### Backend (9 commits)
1. **Database Schema** - Multi-tenant RBAC tables with Row-Level Security
2. **Authentication System** - JWT tokens, API keys, permission decorators
3. **User Management** - 16 API endpoints for auth, organizations, team management
4. **Scan Endpoints** - Organization isolation on all 19 scan endpoints
5. **Triage Endpoints** - Organization isolation on all 11 triage endpoints

### Frontend (1 commit)
1. **Authentication UI** - Login/Register pages with RBAC backend integration
2. **AuthContext** - JWT token management with localStorage
3. **Organization Switcher** - Dropdown to switch between organizations
4. **API Client** - Automatic auth token injection for all requests

---

## 🚀 Getting Started

### 1. Start the Backend

```bash
# Start database
docker compose up -d postgres redis

# Apply RBAC migration
docker compose exec postgres psql -U venti -d ventiapi -f /docker-entrypoint-initdb.d/004_rbac_organizations.sql

# Start web API
cd scanner-service/web-api
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### 2. Start the Frontend

```bash
cd frontend
npm install
npm run dev

# Frontend will be at http://localhost:5173
```

### 3. Configure Environment

Create `frontend/.env`:
```env
VITE_API_URL=http://localhost:8000
```

---

## 📝 Testing Scenarios

### Scenario 1: User Registration

**Test:** Create a new organization with admin user

1. Navigate to http://localhost:5173/auth
2. Click "Sign up"
3. Enter:
   - Email: `alice@acme.com`
   - Password: `password123`
   - Username: `alice`
   - Organization Name: `Acme Corp`
4. Select role (optional): Analyst
5. Click "Create Account"

**Expected:**
- ✅ Account created successfully
- ✅ Auto-logged in
- ✅ Redirected to `/scanner`
- ✅ Organization created with slug `acme-corp`
- ✅ User assigned as `admin` role

**Backend Check:**
```bash
# Verify in database
docker compose exec postgres psql -U venti -d ventiapi -c \
  "SELECT u.username, u.email, o.name, om.role
   FROM users u
   JOIN organization_memberships om ON u.id = om.user_id
   JOIN organizations o ON om.organization_id = o.id
   WHERE u.email = 'alice@acme.com';"
```

---

### Scenario 2: Login with Organization Selection

**Test:** Login with existing demo account

1. Navigate to http://localhost:5173/auth
2. Enter:
   - Email: `admin@demo.com`
   - Password: `admin123`
3. Click "Sign In"

**Expected:**
- ✅ Login successful
- ✅ JWT token stored in localStorage
- ✅ Redirected to `/dashboard`
- ✅ Organization context set to "Demo Organization"

**JWT Token Check:**
```javascript
// Open browser DevTools console
const token = localStorage.getItem('venti_auth_token');
const payload = JSON.parse(atob(token.split('.')[1]));
console.log(payload);
/*
Expected payload:
{
  sub: "UUID",
  username: "admin",
  email: "admin@demo.com",
  organization_id: "00000000-0000-0000-0000-000000000001",
  role: "admin",
  is_superuser: false,
  exp: <timestamp>
}
*/
```

---

### Scenario 3: Multi-Tenant Isolation

**Test:** Verify users can only see their organization's data

**Setup:**
1. Create Org A: `alice@acme.com` (Acme Corp)
2. Create Org B: `bob@betaco.com` (Beta Co)

**Test Steps:**

1. **Login as Alice** (`alice@acme.com`)
2. **Create a scan** for Acme Corp's API
3. **Logout**
4. **Login as Bob** (`bob@betaco.com`)
5. **View scans** - should NOT see Alice's scan
6. **Create a scan** for Beta Co's API
7. **Logout**
8. **Login as Alice**
9. **View scans** - should ONLY see Acme Corp scans

**API Tests:**
```bash
# Login as Alice
ALICE_TOKEN=$(curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@acme.com", "password": "password123"}' \
  | jq -r '.access_token')

# Login as Bob
BOB_TOKEN=$(curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "bob@betaco.com", "password": "password123"}' \
  | jq -r '.access_token')

# Alice creates a scan
curl -X POST http://localhost:8000/api/scan/start \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -F "server_url=http://api.acme.com"

# Bob lists scans - should be empty
curl http://localhost:8000/api/scans \
  -H "Authorization: Bearer $BOB_TOKEN" \
  | jq '.scans | length'  # Expected: 0

# Alice lists scans - should see 1
curl http://localhost:8000/api/scans \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  | jq '.scans | length'  # Expected: 1+
```

---

### Scenario 4: Role-Based Permissions

**Test:** Verify role permissions (admin, analyst, viewer)

**Setup:**
1. Login as admin: `admin@demo.com`
2. Invite users with different roles:
   ```bash
   # Invite analyst
   curl -X POST http://localhost:8000/api/organizations/current/invite \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"email": "analyst@demo.com", "role": "analyst"}'

   # Invite viewer
   curl -X POST http://localhost:8000/api/organizations/current/invite \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"email": "viewer@demo.com", "role": "viewer"}'
   ```

**Permission Matrix:**

| Action | Admin | Analyst | Viewer |
|--------|-------|---------|--------|
| View Scans | ✅ | ✅ | ✅ |
| Create Scans | ✅ | ✅ | ❌ |
| Dangerous Scans | ✅ | ❌ | ❌ |
| Triage Findings | ✅ | ✅ | ❌ |
| Invite Users | ✅ | ❌ | ❌ |
| Create API Keys | ✅ | ❌ | ❌ |
| Manage Settings | ✅ | ❌ | ❌ |

**Test: Analyst can triage but can't run dangerous scans**
```bash
ANALYST_TOKEN="..."  # Login as analyst

# Should succeed - triage finding
curl -X POST http://localhost:8000/api/finding/{finding_id}/triage \
  -H "Authorization: Bearer $ANALYST_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status": "in_progress"}'

# Should fail - dangerous scan (403 Forbidden)
curl -X POST http://localhost:8000/api/scan/start \
  -H "Authorization: Bearer $ANALYST_TOKEN" \
  -F "server_url=http://api.demo.com" \
  -F "dangerous=true"
# Expected: {"detail": "Admin privileges required"}
```

---

### Scenario 5: Organization Switching

**Test:** User switches between multiple organizations

**Setup:**
1. Login as `admin@demo.com` (belongs to Demo Organization)
2. Invite admin to Acme Corp

**Test Steps:**

1. **View organizations:**
```bash
curl http://localhost:8000/api/user/organizations \
  -H "Authorization: Bearer $TOKEN" \
  | jq '.'
# Expected: Array with multiple organizations
```

2. **Switch to Acme Corp:**
```bash
NEW_TOKEN=$(curl -X POST http://localhost:8000/api/user/switch-organization \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"organization_id": "{acme_org_id}"}' \
  | jq -r '.access_token')
```

3. **Verify new context:**
```bash
# Decode new JWT
echo $NEW_TOKEN | cut -d. -f2 | base64 -d | jq '.'
# Expected: organization_id changed to Acme Corp
```

4. **In Frontend:**
   - Click Organization Switcher dropdown
   - Select "Acme Corp"
   - Page reloads
   - Now viewing Acme Corp's scans

---

### Scenario 6: API Key Authentication

**Test:** Create and use API keys

**Setup:**
1. Login as admin
2. Create API key via UI or API

**Create API Key:**
```bash
curl -X POST http://localhost:8000/api/api-keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "CI/CD Scanner",
    "scopes": ["read:scans", "write:scans"],
    "expires_in_days": 90
  }' | jq '.'

# Response contains full key (ONLY SHOWN ONCE):
# {
#   "api_key": "venti_sk_abc123...",
#   "name": "CI/CD Scanner",
#   ...
# }
```

**Use API Key:**
```bash
API_KEY="venti_sk_abc123..."

# List scans using API key
curl http://localhost:8000/api/scans \
  -H "Authorization: Bearer $API_KEY" \
  | jq '.scans | length'

# Create scan using API key
curl -X POST http://localhost:8000/api/scan/start \
  -H "Authorization: Bearer $API_KEY" \
  -F "server_url=http://api.demo.com"
```

**Test Scope Restrictions:**
```bash
# API key with only read:scans scope
READONLY_KEY=$(curl -X POST http://localhost:8000/api/api-keys \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"name": "Read-Only", "scopes": ["read:scans"]}' \
  | jq -r '.api_key')

# Should succeed - read scans
curl http://localhost:8000/api/scans \
  -H "Authorization: Bearer $READONLY_KEY"

# Should fail - write scans (403 Forbidden)
curl -X POST http://localhost:8000/api/scan/start \
  -H "Authorization: Bearer $READONLY_KEY" \
  -F "server_url=http://api.demo.com"
```

---

### Scenario 7: Audit Logging

**Test:** Verify all RBAC actions are logged

**Check Audit Log:**
```bash
docker compose exec postgres psql -U venti -d ventiapi -c \
  "SELECT
     action,
     resource_type,
     details->>'email' as user_email,
     ip_address,
     created_at
   FROM audit_log
   ORDER BY created_at DESC
   LIMIT 10;"
```

**Expected Events:**
- `user.registered` - User registration
- `user.login` - User login
- `scan.created` - Scan creation
- `finding.triaged` - Finding triage
- `user.invited` - User invitation
- `api_key.created` - API key creation

---

### Scenario 8: Row-Level Security

**Test:** Verify RLS policies enforce isolation

**Database Test:**
```bash
# Set current user context (simulating app.current_user_id)
docker compose exec postgres psql -U venti -d ventiapi -c \
  "SET app.current_user_id = '00000000-0000-0000-0000-000000000002';
   SELECT s.scan_id, o.name
   FROM scans s
   JOIN organizations o ON s.organization_id = o.id;"

# Should ONLY show scans from Demo Organization

# Switch context to different user
docker compose exec postgres psql -U venti -d ventiapi -c \
  "SET app.current_user_id = '{alice_user_id}';
   SELECT s.scan_id, o.name
   FROM scans s
   JOIN organizations o ON s.organization_id = o.id;"

# Should ONLY show scans from Alice's organization
```

---

## 🔍 Debugging Tips

### Check JWT Token
```javascript
// In browser console
const token = localStorage.getItem('venti_auth_token');
console.log('Token:', token);
console.log('Payload:', JSON.parse(atob(token.split('.')[1])));
```

### Check Auth State
```javascript
// In browser console
const user = JSON.parse(localStorage.getItem('venti_user'));
console.log('Current User:', user);
```

### Backend Logs
```bash
# Watch web-api logs
docker compose logs -f web-api

# Or if running locally
# Check terminal where uvicorn is running
```

### Database Queries
```bash
# Check organizations
docker compose exec postgres psql -U venti -d ventiapi -c \
  "SELECT id, name, slug, tier FROM organizations;"

# Check memberships
docker compose exec postgres psql -U venti -d ventiapi -c \
  "SELECT
     u.username,
     o.name as org_name,
     om.role
   FROM organization_memberships om
   JOIN users u ON om.user_id = u.id
   JOIN organizations o ON om.organization_id = o.id;"
```

---

## ✅ Success Criteria

- [ ] Can register new user with organization
- [ ] Can login with email/password
- [ ] JWT token stored in localStorage
- [ ] Organization switcher shows all organizations
- [ ] Can switch between organizations
- [ ] Users only see their organization's scans
- [ ] Admin can invite users
- [ ] Admin can create API keys
- [ ] Analyst can triage but not run dangerous scans
- [ ] Viewer can only read
- [ ] API keys work for authentication
- [ ] Audit log records all actions
- [ ] RLS policies enforce data isolation

---

## 🐛 Known Issues

1. **Password Reset** - Not implemented yet (placeholder in UI)
2. **Email Verification** - Not implemented (all emails auto-verified)
3. **Organization Settings Page** - UI not created yet (API ready)
4. **Team Member Management UI** - Not created yet (API ready)

---

## 📚 API Documentation

Full API documentation available at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

Key Endpoints:
- `POST /api/auth/register` - Register new user + org
- `POST /api/auth/login` - Login with email/password
- `GET /api/user/organizations` - List user's organizations
- `POST /api/user/switch-organization` - Switch to different org
- `POST /api/organizations/current/invite` - Invite user (admin only)
- `POST /api/api-keys` - Create API key (admin only)
- `GET /api/scans` - List scans (org-filtered)
- `POST /api/finding/{id}/triage` - Triage finding (analyst+)

---

## 🎓 Next Steps

After testing RBAC:
1. Add Protected Routes component for frontend
2. Add role-based UI controls (hide admin buttons for non-admins)
3. Add API key management UI
4. Add team member management UI
5. Add organization settings UI
6. Implement password reset workflow
7. Add email verification
