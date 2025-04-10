# Full Roadmap for a Vanilla PHP-Based SSO Service with Multi‑Platform Integration

---

## 1. Project Overview

**Goal:**  
Build a custom SSO service that enables seamless authentication across containerized services (WordPress, Nextcloud, Ghost, Humhub, etc.) on subdomains. The solution is written entirely in vanilla PHP (no frameworks or external libraries) and uses minimal external services.  

**Deployment Environment:**  

- Debian VPS (e.g., Contabo)  
- Domain from OVH  
- Initial storage via SQLite or JSON flat files, with a migration path to MariaDB

---

## 2. System Architecture

### A. Core Components

- **SSO Backend API (Vanilla PHP):**  
  
  - Provides endpoints for login, token creation, validation, and logout
  - Handles session management and secure cookie issuance across subdomains

- **Admin Web Interface:**  
  
  - Simple HTML/CSS/JavaScript frontend for managing users, services, permissions, and logs

- **Service Plugins/Adapters:**  
  
  - Custom code, or minimal plugins, to integrate each consuming application (WordPress, Nextcloud, Ghost, Humhub)
  - Each adapter ensures that when a user is authenticated via SSO, the local session in the respective service is automatically created

- **Data Persistence:**  
  
  - Start with SQLite or JSON file storage for sessions and user data, later migrating to a full MariaDB schema if needed

### B. Communication & Data Flow

```
[User] → [Service Login (WP, Nextcloud, etc.)] → [SSO Validation (API)] → [Auth Token & Cookie Set]
↓                             ↑                                ↓
[Local Session Creation in Each Service (via Plugin/Adapter) based on validated token]
```

---

## 3. Detailed Phases & Timeline

### **Phase 1: SSO Server - Backend Core Implementation (Weeks 1–4)**

#### Week 1: Foundation Setup

- **Project Structure:**  
  
  - Define a clean folder hierarchy (e.g., `/api`, `/admin`, `/data`)
  - Decide on using vanilla PHP (no frameworks)

- **Database/Storage Setup:**  
  
  - Create the initial storage for sessions and users  
    - Options: Flat JSON files or SQLite  
  - Define a basic schema:
    - **Users:** id, username, email, password hash, profile info, 2FA (if implemented)
    - **Services:** id, name, domain, API keys/secrets (if needed)
    - **Sessions:** token, user_id, ip, user agent, expires_at
    - **Permissions/Logs:** For audit trail and access controls

- **Configuration System:**  
  
  - Create a simple PHP config file for secrets, database settings, and environment flags

#### Week 2: Authentication and Token Management

- **User Login Flow:**  
  
  - Create a login form on the SSO server (`sso.example.com/auth`)
  - Upon submission, validate credentials (password verification, etc.)

- **Token Generation:**  
  
  - Generate a secure token (optionally as a JWT-like structure with claims such as user id, timestamp, expiration, and a unique jti)
  - Store token details and expiration in your sessions storage

- **Cookie Management:**  
  
  - Set a secure cookie:
    
    ```php
    setcookie("sso_token", $token, [
      'expires'  => time() + 900, // 15 minutes
      'path'     => '/',
      'domain'   => '.example.com',
      'secure'   => true,
      'httponly' => true,
      'samesite' => 'Strict',
    ]);
    ```

- **CSRF Protection:**  
  
  - Implement double-submit tokens on all state-changing POST requests (generate a CSRF token and set it in both a cookie and a hidden form field)

- **XSS Prevention:**  
  
  - Escape all output with `htmlspecialchars` and deploy a strict Content-Security-Policy header

#### Week 3: Create Core API Endpoints

- **Endpoints to build:**  
  - `/auth` – handles user login, token generation, and sets cookies  
  - `/validate_token` – accepts a token parameter (via GET or header) and returns JSON with user info if valid:
    - Validate expiration, check token existence in storage
    - Return structured JSON with fields: `valid`, and if valid, user data (email, username, name, etc.)
  - `/logout` – invalidate session tokens, clear cookies on SSO server
  - Additional endpoints (if needed): `/register` for new users, `/sync` for cross-service user sync (password/hashes)

#### Week 4: Enhance Security and Session Management

- **Token Replay Protection:**  
  - Optionally store `jti` values and reject tokens if reused after logout
- **Implement Automatic Refresh:**  
  - Consider a short-lived token with refresh support (e.g., by issuing a new token before expiration)
- **Centralized Logging:**  
  - Capture all auth events into a logs table/file for later auditing
- **Rate Limiting:**  
  - Manually enforce limits on critical endpoints (especially login and validation)

---

### **Phase 2: Admin Interface & Extended Features (Weeks 5–6)**

#### Week 5: Administrative API & UI

- **Admin Authentication:**  
  - Build an admin login page with elevated privileges
- **Management Endpoints:**  
  - Create RESTful endpoints under `/admin` for:
    - **User Management:** CRUD operations for users
    - **Service Management:** Register and configure services (WordPress, Nextcloud, etc.)
    - **Permission Assignments:** Map which users have access to which services
    - **Logs Review:** Query recent authentication events
- **Frontend Admin Dashboard:**  
  - Develop a basic dashboard with HTML/CSS/JS that shows system stats, active sessions, and recent logins

#### Week 6: Security Hardening & Testing

- **Implement Additional Security Measures:**  
  - Enforce input validation, session expiries, and IP tracking
  - Develop custom error messages and proper HTTP status responses
- **Manual Pen Testing:**  
  - Simulate CSRF, XSS attacks, and token replay scenarios to verify resilience

---

### **Phase 3: Client Application Integrations (Weeks 7–9)**

For each service, create a minimal adapter or plugin using the native facilities of that platform. The following provides an outline for each:

#### **Integration Strategy (General)**

- **Token Verification:**  
  - The client app (or its custom plugin) checks for the SSO cookie (`sso_token`)
  - It then makes an HTTP call to your SSO `/validate_token` endpoint
  - If validated, the client creates a local user session (and registers the user if not already existing)
- **Preferred Methods:**  
  - **Cookie-based:** Automatically read the token
  - **URL-token redirect:** Fall-back method where SSO redirects with `?token=xyz`

---

#### A. **WordPress Integration (Week 7)**

- **Plugin/Theme Functionality:**  
  - In your `functions.php` or a small custom plugin:
    - Check if `$_COOKIE['sso_token']` exists on `init`
    - If the user is not logged in, call the SSO `/validate_token` endpoint
    - Use `wp_create_user` (if necessary) and `wp_set_auth_cookie` to log the user in
- **Security Considerations:**  
  - Verify the user’s email and match to an existing WordPress user
  - Ensure HTTPS is used and rate-limit validation calls

#### B. **Nextcloud Integration (Week 8)**

- **Plugin/Adapter:**  
  - Either develop a Nextcloud “app” or adapt existing modules (for example, using “user_external”) to validate SSO tokens:
    - On login, redirect to your SSO service (or have the user present a token)
    - The Nextcloud adapter then calls the SSO `/validate_token` endpoint
    - Create a local Nextcloud user session on success
- **Notes:**  
  - Nextcloud’s plugin system offers hooks that let you override the default authentication process

#### C. **Ghost Integration (Week 8–9)**

- **Middleware or Reverse Proxy Option:**  
  - Given Ghost’s simplicity, you can either modify a custom middleware or run Ghost behind a reverse proxy that intercepts requests:
    - Validate token from the cookie/URL header
    - Inject local session headers for Ghost to accept
- **Fallback:**  
  - Alternatively, integrate a small login widget that calls your SSO and sets a local session

#### D. **Humhub Integration (Week 9)**

- **Custom AuthClient:**  
  - Use Humhub’s built-in `authclient` module to create a custom client that communicates with your SSO:
    - On login, redirect to your SSO endpoint for token validation
    - On return, create/validate the Humhub session
- **Considerations:**  
  - Ensure consistency with your permission system (service-level access mapping)

---

### **Phase 4: Testing, Optimization, and Documentation (Weeks 10–11)**

#### Testing & Quality Assurance

- **Unit Testing:**  
  - Write tests for each API endpoint (login, validate_token, logout)
- **Integration Testing:**  
  - Simulate full login flow from SSO to each client app (WordPress, Nextcloud, etc.)
- **Security Testing:**  
  - Test against CSRF, XSS, and session hijacking vulnerabilities
  - Validate token expiry and replay prevention
- **Performance Testing:**  
  - Ensure the token validation endpoint and session management are performant under load

#### Documentation

- **Installation Guide:**  
  - Instructions for setting up the SSO server, including environment configuration and data storage options
- **Admin Manual:**  
  - How to use the admin dashboard to manage users, services, and review logs
- **Developer Documentation:**  
  - Clear guides on writing additional adapters/plugins for new services
  - API documentation for `/auth`, `/validate_token`, and `/logout`

#### Deployment Scripts

- **CI/CD Setup:**  
  - Build simple shell scripts or makefiles to deploy updates to your Debian VPS
- **Containerization (Optional):**  
  - If desired later, prepare Docker-compose setups that still follow your vanilla code base but allow easy scaling

---

### **Phase 5: Project Maintenance & Upgrades (Ongoing)**

- **User Feedback Loop:**  
  - Collect user reports from early adopters, refine the UX and security hardening
- **Feature Upgrades:**  
  - Consider adding more secure token refresh workflows, detailed logging, and eventual expansion to support features like user impersonation or magic link logins
- **Community & Open Source Considerations:**  
  - Prepare the codebase for open source release, complete with clear documentation and contribution guidelines

---

## Summary Checklist

1. **SSO Server Setup:**  
   
   - Implement login, token generation (JWT-like), CSRF & XSS protection, secure cookies  
   - Create `/auth`, `/validate_token`, `/logout` endpoints

2. **Admin Dashboard:**  
   
   - Develop management UI and API endpoints for users, services, permissions, and logs

3. **Client Integrations:**  
   
   - **WordPress:** Plugin to intercept logins via `sso_token` cookie  
   - **Nextcloud:** Adapter or Nextcloud app for external authentication  
   - **Ghost & Humhub:** Custom middleware or authclient modules to auto-login users

4. **Security and Testing:**  
   
   - Enforce HTTPS, short-lived tokens, rate limiting, input sanitation  
   - Develop manual pen testing routines and automated tests

5. **Documentation & Deployment:**  
   
   - Prepare user, admin, and developer documentation  
   - Create deployment scripts with potential containerization for the future