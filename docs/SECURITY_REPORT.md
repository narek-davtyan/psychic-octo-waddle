# SafeVault security report

## 1. Scope
SafeVault is an ASP.NET Core MVC (.NET 10) app: registration, login, role-based access control (User / Admin),
profile page, admin dashboard and audit log.

## 2. Vulnerabilities addressed, fixes and evidence

| # | Vulnerability | Fix applied | Evidence (tests / checks) |
|---|---|---|---|
| 1 | **SQL injection** | No SQL string building: users are accessed as typed objects through `IUserRepository`. Usernames are whitelist-validated (`^[A-Za-z0-9_.-]{3,32}\z`) and SQL patterns (`' OR 1=1 --`, `UNION SELECT`, `; DROP`) are rejected. If you move to SQL, use EF Core or parameterised commands. | `InputSanitizerTests.Sql_Injection_Payloads_Are_Detected`, `AuthServiceTests.Sql_Injection_Style_Usernames_Never_Authenticate`, `JsonFileUserRepositoryTests.Lookup_Treats_Injection_Strings_As_Plain_Data`; live check "SQLi username rejected" |
| 2 | **Cross-site scripting (XSS)** | Whitelist input validation, `[SafeText]` rejecting `<`, `>`, script tags, `javascript:` and event handlers; Razor HTML-encodes all output; Content-Security-Policy (`script-src 'self'`); HttpOnly auth cookie. | `InputSanitizerTests.Xss_Payloads_Are_Detected`, `RegisterViewModel_Validation_Rejects_Malicious_*`; live checks "XSS payload NOT reflected raw", "CSP header present" |
| 3 | **Regex trailing-newline bypass** (`$` matches before a final `\n`) | Username pattern ends with `\z` instead of `$`. | `Username_Whitelist_Is_Enforced("alice\n")` |
| 4 | **Weak / stolen passwords** | PBKDF2-HMAC-SHA512 (600k iterations, random salt), password policy, constant-time compare, transparent hash upgrade. | `Pbkdf2PasswordHasherTests`, `PasswordPolicyTests`, `Login_Upgrades_Old_Weak_Hashes_Transparently` |
| 5 | **Brute force / credential stuffing** | Per-IP rate limit (429) and per-account lockout that also blocks the correct password. | `Account_Locks_After_Too_Many_Failures...`, `Lockout_Expires...`; live checks for lockout and 429 |
| 6 | **User enumeration** | Same generic error and same timing (dummy hash) for unknown user / wrong password / locked. | `Login_Fails_For_Wrong_Password_And_Unknown_User_With_Same_Status` |
| 7 | **Broken access control / RBAC** | `[Authorize(Roles="Admin")]` on the admin controller; role values whitelisted; profile reads identity from the cookie only; last admin cannot be demoted or deleted; cannot delete self. | Live checks: anonymous redirected, normal user gets 403 on `/Admin`, last-admin demotion refused |
| 8 | **Stale privileges after role change / deletion / lockout** | `PrincipalValidator` re-checks the user on every request and fails closed. | `PrincipalValidatorTests` (all 5); live check "locked user's existing cookie rejected" |
| 9 | **CSRF** | Global antiforgery validation, POST-only state changes, SameSite=Strict cookie. | Live check "register POST w/o antiforgery -> 400" |
| 10 | **Open redirect** | `returnUrl` honoured only when `Url.IsLocalUrl`. | Live check "open redirect blocked" |
| 11 | **Log injection** | Control characters stripped, values truncated. | `FileAuditLoggerTests.Log_Injection_Attempts_Cannot_Forge_Extra_Log_Lines` |
| 12 | **Information disclosure** | Generic error pages with a trace id; stack traces only in server logs. | Code review of `ExceptionLoggingMiddleware` / error views |
| 13 | **Auth cookie keys not persisted** (found when running the app: log warned about ephemeral key storage; restarts would invalidate sessions) | `AddDataProtection().PersistKeysToFileSystem(...)`. Protecting the key ring at rest is still a production to-do. | Live check: an old session cookie still worked after a restart |

## 3. How tests were run
* **Unit tests:** `tests/SafeVault.Tests` (xUnit, 77 cases). During authoring they were compiled against the real
  app code and executed with a minimal xUnit stand-in (77 passed, 0 failed) because NuGet was unavailable in the
  authoring environment. Run `dotnet test SafeVault.slnx` to run them under real xUnit.
* **Live HTTP checks:** the running app was exercised with curl (19 checks passed) covering headers, CSRF, input
  rejection, login, RBAC, lockout, open redirect, rate limiting and restart persistence.

## 4. AI assistance
As requested the project used **Copilot** in a chat session. It wrote small parts of the application, as well as it was used for debugging.
