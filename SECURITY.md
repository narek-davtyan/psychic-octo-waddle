# SafeVault security notes

This document maps each common web-application threat to the control that handles it and
to the file where you can review that control.

| Threat | Control | Where to look |
|---|---|---|
| **Password theft from a leaked store** | PBKDF2-HMAC-SHA512, 600,000 iterations, 128-bit random salt per user, self-describing hash format, transparent upgrade of old hashes at login | `Services/Pbkdf2PasswordHasher.cs`, `Services/AuthService.cs` |
| **Weak passwords** | 12-128 chars, upper/lower/digit/symbol, must not contain the username | `Security/PasswordPolicy.cs` |
| **Brute-force / credential stuffing** | Per-IP rate limit on login + register (429), per-account lockout (default 5 failures / 15 min), lockout applies even to the correct password | `Program.cs` (rate limiter), `Services/AuthService.cs` |
| **User enumeration** | One generic login error for unknown user / wrong password / locked; a dummy hash is computed for unknown users so response time does not differ | `Controllers/AccountController.cs`, `IPasswordHasher.BurnTime` |
| **SQL injection** | No SQL anywhere: users live in a JSON file accessed through typed objects. Input is also whitelist-validated and injection patterns are rejected. If you move to SQL, use EF Core or parameterised commands (never string concatenation) | `Data/JsonFileUserRepository.cs`, `Security/InputSanitizer.cs` |
| **Cross-site scripting (XSS)** | (1) whitelist validation, (2) Razor HTML-encodes all `@` output, (3) strict Content-Security-Policy (`script-src 'self'`, no inline script), (4) HttpOnly auth cookie | `Security/*`, `Views/*`, `Middleware/SecurityHeadersMiddleware.cs` |
| **Cross-site request forgery** | Global `AutoValidateAntiforgeryToken`; every state-changing action is POST; auth cookie is `SameSite=Strict` | `Program.cs`, `Views/Shared/_Layout.cshtml` |
| **Broken access control** | `[Authorize(Roles = "Admin")]` on the whole admin controller; users only ever read their OWN profile (identity from the cookie, not a URL id); role values are whitelisted | `Controllers/AdminController.cs`, `Controllers/AccountController.cs` |
| **Privilege escalation via stale cookie** | Cookie is re-validated against the store on every request: deleted, locked or re-roled users are signed out immediately; fails closed on any error | `Security/PrincipalValidator.cs` |
| **Last-admin lock-out / self-harm** | Cannot delete yourself, and cannot demote or delete the last administrator | `Controllers/AdminController.cs` |
| **Open redirect** | `returnUrl` is honoured only if `Url.IsLocalUrl` | `Controllers/AccountController.cs` |
| **Session hijacking** | HttpOnly + `Secure` (always outside Development) + SameSite=Strict cookie, 30-minute sliding expiry, session (non-persistent) cookie, HSTS in production | `Program.cs` |
| **Clickjacking / MIME sniffing / info leaks** | `frame-ancestors 'none'`, `X-Frame-Options`, `nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy` | `Middleware/SecurityHeadersMiddleware.cs` |
| **Information disclosure via errors** | Generic error pages with a trace id; details only in server logs | `Middleware/ExceptionLoggingMiddleware.cs`, `Views/Home/Error.cshtml` |
| **Log forging** | CR/LF and control characters are stripped and values truncated before writing | `Services/FileAuditLogger.cs` |
| **Data-file exposure** | Data lives outside `wwwroot`; `users.json` is created owner-read/write only on Linux/macOS | `Data/JsonFileUserRepository.cs` |

## Known limitations (read before production use)

* **Single-instance store.** The JSON file repository is for demos and small single-server use. For several
  servers or heavy load, implement `IUserRepository` on top of EF Core + PostgreSQL / SQL Server.
* **Key ring is not encrypted at rest.** ASP.NET Core data-protection keys are written to `App_Data/keys`.
  In production protect them (certificate, Azure Key Vault, DPAPI, etc.).
* **Behind a reverse proxy**, enable forwarded headers so rate limiting and the audit log see real client IPs,
  and make sure the proxy terminates TLS.
* **No e-mail confirmation or password reset / MFA.** Registration accepts any syntactically valid e-mail.
* **Registration reveals duplicates** ("username or email already in use"). That is a usability trade-off;
  a stricter design would e-mail the owner instead.
* **Pattern blacklists are a backup layer only.** Real protection comes from whitelisting and output encoding.
  Note that the SQL pattern check rejects `--` and `/* */` in text fields.
* The seeded admin password is printed to the console once. Set `SafeVault__SeedAdmin__Password`
  (environment variable or user-secrets) for automated deployments, then change it.

## Reporting a vulnerability

Please open a private security advisory on the GitHub repository rather than a public issue.
