# SafeVault (.NET 10)

A small, security-focused **ASP.NET Core MVC** web application on **.NET 10**: registration, login, role-based
authorization (User / Admin), profile page, admin dashboard and an audit trail.

**Differences on purpose**

* **Zero third-party NuGet packages.** Password hashing is PBKDF2-HMAC-SHA512 from the .NET base class library
  (the originals use BCrypt / Argon2 packages), and users are stored in a JSON file behind `IUserRepository`
  (the originals use SQL Server, PostgreSQL or SQLite). The app therefore restores and runs even offline.
  Swapping in EF Core or Argon2 means writing one class each; nothing else changes.
* Account lockout, last-admin protection, strict CSP, log-injection protection and transparent hash upgrades are additions.

## Requirements

* [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)

## Run it

```bash
dotnet run --project src/SafeVault.Web --launch-profile http     # http://localhost:5080
# or, with HTTPS (trust the dev certificate once with: dotnet dev-certs https --trust)
dotnet run --project src/SafeVault.Web --launch-profile https    # https://localhost:7080
```

On the **first run** an administrator is created. Unless you configure a password, a random one is printed
**once** in the console:

```
Initial administrator created. Username: admin  Password: ********************  (shown once - change it!)
```

To choose the password yourself:

```bash
dotnet user-secrets init --project src/SafeVault.Web
dotnet user-secrets set "SafeVault:SeedAdmin:Password" "A-Long-Passw0rd!" --project src/SafeVault.Web
```

Then browse to the site, register a normal user, sign in as `admin` to open **Admin**.

## Test it

```bash
dotnet test SafeVault.slnx
```

The suite (77 cases) covers hashing, password policy, XSS / SQL-injection detection, registration, login,
lockout and expiry, hash upgrade, the JSON repository (including concurrency), cookie re-validation and
log-injection protection.

## Configuration (`appsettings.json`)

| Key | Default | Meaning |
|---|---|---|
| `SafeVault:DataDirectory` | `App_Data` | Where `users.json`, `logs/audit.log` and `keys/` are stored |
| `SafeVault:Security:MaxFailedLoginAttempts` | `5` | Failures before lockout |
| `SafeVault:Security:LockoutMinutes` | `15` | Lockout duration |
| `SafeVault:Security:Pbkdf2Iterations` | `600000` | Cost of NEW password hashes |
| `SafeVault:Security:AuthRequestsPerMinute` | `10` | Per-IP limit on login/register POSTs |
| `SafeVault:SeedAdmin:*` | admin / admin@safevault.local / *(random)* | First administrator |

Any key can be overridden by an environment variable using `__`, e.g. `SafeVault__Security__LockoutMinutes=30`.

## Project layout

```
SafeVault/
├── .github/workflows/ci.yml        # build + test + vulnerability check on every push / PR
├── SafeVault.slnx                  # solution (new .slnx format used by .NET 10)
├── README.md  SECURITY.md  LICENSE
├── docs/SECURITY_REPORT.md         # vulnerabilities, fixes, evidence, AI-assistance note
├── .gitignore  .gitattributes
├── src/SafeVault.Web/              # the ASP.NET Core MVC application
│   ├── Program.cs                  # DI, cookie auth, rate limiter, pipeline order, seeding
│   ├── Controllers/                # Home, Account (register/login/logout/profile), Admin
│   ├── Data/                       # IUserRepository + JsonFileUserRepository
│   ├── Middleware/                 # SecurityHeaders, ExceptionLogging, AuditLogging
│   ├── Models/                     # User record, Roles, view models (with validation attributes)
│   ├── Security/                   # InputSanitizer, [SafeText], PasswordPolicy, PrincipalValidator
│   ├── Services/                   # AuthService, Pbkdf2PasswordHasher, FileAuditLogger, AdminSeeder
│   ├── Views/                      # Razor views (no inline scripts/styles, CSP-friendly)
│   └── wwwroot/css/site.css
└── tests/SafeVault.Tests/          # xUnit tests
```

## Request flow (login)

1. `POST /Account/Login` passes the **rate limiter**, then the **antiforgery** check.
2. Model validation: required, length, `[SafeText]` (XSS/SQLi/control characters).
3. `AuthService.LoginAsync`: lookup, lockout check, constant-time hash verify, failure counting, audit entry.
4. On success an encrypted, signed, HttpOnly, SameSite=Strict **session cookie** is issued.
5. On every later request `PrincipalValidator` confirms the user still exists, is not locked and still has the same role.

## Deploying

Run behind HTTPS (reverse proxy or Kestrel certificate), set `ASPNETCORE_ENVIRONMENT=Production`
(enables `Secure`-only cookies, HSTS and generic error pages), provide the admin password through a secret,
persist and protect `App_Data`, and read the limitations in [SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE).
