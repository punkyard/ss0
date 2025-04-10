Here’s a **restructured and complete roadmap** for your SSO system — with *no information lost*, just reordered and clarified for flow, modularity, and collaboration:

---

# 🛠️ Project Overview

**Goal**: Build a lightweight custom PHP SSO system for seamless authentication across multiple services (WordPress, Nextcloud, etc.) on subdomains, using a shared root-domain cookie.  
**Environment**: Debian VPS (Contabo) + OVH domain  
**Stack**: Vanilla PHP (no frameworks), SQLite/MariaDB, HTML/CSS/JS frontend

---

# 🧭 System Architecture

## Core Components

- PHP SSO Backend API (Vanilla PHP)
- Admin Web Interface (HTML/CSS/JS)
- Per-service Plugins/Adapters (e.g., WP plugin)
- Shared Root-Domain Cookie Auth
- SQLite (initially) → MariaDB later

## Authentication Flow

1. User logs into any service
2. Service forwards login to SSO backend for validation
3. Backend creates session + JWT + root-domain cookie
4. Visiting another service → detects cookie → validates token → user auto-logged in

## Data Flow

```
[Services] ←→ [Adapters] ←→ [SSO API] ←→ [DB] ←→ [Admin UI]
```

---

# 🧩 Database Schema

Tables:

- `users`
- `services`
- `permissions`
- `sessions`
- `logs`

(Full SQL schema preserved in your original roadmap — to be applied directly.)

---

# ✅ Project Phases & Timeline

---

## Phase 1: Backend Core Authentication Service (Weeks 1–4)

### Week 1: Foundation Setup

- Define project structure (no framework)
- Start with SQLite (switch to MariaDB later)
- Set up DB schema:
  - `users`, `services`, `sessions`, `permissions`, `logs`
- Basic API structure + config system

### Week 2: Authentication Core

- Implement login validation
- JWT generation + validation
- Root-domain cookie handling (secure flags)
- Session management (create/destroy/validate)
- User registration w/ email verification
- Optional: TOTP 2FA

### Week 3: Integration Layer

- Develop adapters for:
  - WordPress
  - Nextcloud
  - HumHub
  - Ghost
- Implement user sync & password compatibility

### Week 4: Cookie & Session Enhancements

- Token refresh mechanism
- Token invalidation & logout
- Cookie-based auto-login system

---

## Phase 2: Admin System (Weeks 5–6)

### Week 5: Admin API

- Admin authentication
- Create secure admin-only endpoints:
  - `/api/admin/users`, `/services`, `/permissions`, `/logs`
- Permissions management (user-to-service mapping)

### Week 6: Security Enhancements

- Rate limiting
- Audit logs (every auth event)
- IP allow/block list
- Session expiration policies
- Additional 2FA options

---

## Phase 3: Frontend (Weeks 1–6 in parallel or after backend)

### Week 1–2: Admin Dashboard Setup

- Login screen for admin access
- Responsive layout with dashboard overview:
  - Active sessions
  - Services status
  - Recent events

### Week 3–4: Management Interfaces

- User management interface:
  - List/search/edit/status
- Service management UI:
  - Add/edit/configure/monitor
- Permissions editor UI

### Week 5–6: Analytics & Settings

- Log viewer with filters
- Audit trail visualization
- System settings panel
- Theme, backup/restore, notifications

---

## Phase 4: Service-Specific Integrations (Weeks 7–9)

### Week 7:

- WordPress plugin
  - Hooks for login/logout
  - Cookie/token validation
  - Sync with SSO

### Week 8:

- Nextcloud app
  - Custom user backend
  - Login override + provisioning

### Week 9:

- HumHub & Ghost:
  - Minimal adapter modules
- Nginx helper script
- Portainer SSO handling

---

## Phase 5: Testing & Optimization (Weeks 10–11)

- Unit tests + Integration tests
- Performance testing
- Security audit
- Token validation caching
- Debug tools (connectivity, session, token status)

---

## Phase 6: Documentation & Deployment

- 📖 Docs:
  
  - Installation guide
  - Admin manual
  - Dev guide (for writing new adapters)
- 🚀 Deployment:
  
  - CI/CD scripts
  - Docker-compose setup for containerized deployment

---

# 🧪 Technical Notes

## JWT Structure

```json
{
  "sub": "user_id",
  "name": "username",
  "email": "user@example.com",
  "roles": ["admin"],
  "permissions": ["wordpress", "nextcloud"],
  "exp": 1710000000,
  "jti": "unique_token_id"
}
```

## Cookie Security

- `HttpOnly`, `Secure`, `SameSite=Lax`
- Root-domain `.yourdomain.com`

## Questions/Considerations

- ✅ No PHP framework: everything is hand-built
- ✅ SSO system handles user registration
- ✅ One user DB across all services
- ✅ Access control: service-level (not feature-level)
- ❓ Any further security requirements beyond standard best practices?

---

# ✅ Next Steps

1. [ ] Set up GitHub repo & project layout
2. [ ] Start backend (Week 1 tasks)
3. [ ] Define CI/CD flow
4. [ ] Define plugin structure for each target service
5. [ ] Begin tests once integration layer is stable

---

Let me know if you'd like a **separate GitHub `README.md` version** of this, or a **Notion/Trello-style breakdown** for task tracking.