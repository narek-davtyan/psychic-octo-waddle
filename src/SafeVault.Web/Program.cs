using Microsoft.AspNetCore.DataProtection;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Web.Data;
using SafeVault.Web.Middleware;
using SafeVault.Web.Security;
using SafeVault.Web.Services;

var builder = WebApplication.CreateBuilder(args);

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
var securityOptions = builder.Configuration.GetSection("SafeVault:Security").Get<SecurityOptions>() ?? new SecurityOptions();

// Resolve the data folder relative to the content root unless an absolute path is configured.
var dataDirectory = Path.GetFullPath(
    builder.Configuration["SafeVault:DataDirectory"] ?? "App_Data", builder.Environment.ContentRootPath);

// ---------------------------------------------------------------------------
// Services (dependency injection)
// ---------------------------------------------------------------------------
builder.Services.AddSingleton(securityOptions);
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<IUserRepository>(_ => new JsonFileUserRepository(dataDirectory));
builder.Services.AddSingleton<IAuditLogger>(sp => new FileAuditLogger(dataDirectory, sp.GetRequiredService<TimeProvider>()));
builder.Services.AddSingleton<IPasswordHasher>(_ => new Pbkdf2PasswordHasher(securityOptions.Pbkdf2Iterations));
builder.Services.AddSingleton<AuthService>();
builder.Services.AddSingleton<PrincipalValidator>();

// Persist the keys that encrypt/sign the auth cookie and antiforgery tokens. Without this, keys live in
// memory/ephemeral storage and every restart (or second server) would invalidate all sessions.
// In production, also protect the key ring (certificate, Azure Key Vault, DPAPI...) - see README.
builder.Services.AddDataProtection()
    .SetApplicationName("SafeVault")
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(dataDirectory, "keys")));

builder.Services.AddControllersWithViews(options =>
{
    // CSRF: require a valid antiforgery token on every unsafe HTTP method (POST/PUT/DELETE) by default.
    options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
});

// Cookie authentication ------------------------------------------------------
builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.AccessDeniedPath = "/Account/AccessDenied";
        options.Cookie.Name = "SafeVault.Auth";
        options.Cookie.HttpOnly = true;                       // JavaScript cannot read the cookie (limits XSS damage)
        options.Cookie.SameSite = SameSiteMode.Strict;        // never sent on cross-site requests (CSRF defence)
        // Always require HTTPS in production; allow plain HTTP only for local development.
        options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
            ? CookieSecurePolicy.SameAsRequest
            : CookieSecurePolicy.Always;
        options.ExpireTimeSpan = TimeSpan.FromMinutes(30);    // short-lived session
        options.SlidingExpiration = true;

        options.Events.OnValidatePrincipal = async context =>
        {
            // Re-check the user in the data store on every request (deleted? locked? role changed?).
            var validator = context.HttpContext.RequestServices.GetRequiredService<PrincipalValidator>();
            if (!await validator.IsValidAsync(context.Principal, context.HttpContext.RequestAborted))
            {
                context.RejectPrincipal();
                await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            }
        };
    });

builder.Services.AddAuthorization();

// Rate limiting --------------------------------------------------------------
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    // "auth" policy: a fixed window per client IP, applied to login + register POSTs.
    options.AddPolicy("auth", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = securityOptions.AuthRequestsPerMinute,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0 // reject immediately instead of queueing
            }));

    options.OnRejected = async (context, token) =>
    {
        context.HttpContext.Response.ContentType = "text/plain; charset=utf-8";
        await context.HttpContext.Response.WriteAsync("Too many requests. Please wait a minute and try again.", token);
    };
});

var app = builder.Build();

// ---------------------------------------------------------------------------
// First-run seeding: make sure at least one administrator exists.
// ---------------------------------------------------------------------------
await AdminSeeder.EnsureAdminAsync(
    app.Services.GetRequiredService<IUserRepository>(),
    app.Services.GetRequiredService<IPasswordHasher>(),
    app.Configuration,
    app.Logger,
    app.Services.GetRequiredService<IAuditLogger>());

// ---------------------------------------------------------------------------
// HTTP pipeline. ORDER MATTERS.
// ---------------------------------------------------------------------------
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");   // generic page, no stack traces
    app.UseHsts();                            // tell browsers to use HTTPS only
}

app.UseMiddleware<SecurityHeadersMiddleware>();    // headers on every response, including errors
app.UseMiddleware<ExceptionLoggingMiddleware>();   // log unhandled exceptions, then let the handler render the page
app.UseStatusCodePagesWithReExecute("/Home/HttpStatus/{0}");

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.UseRateLimiter();                              // after routing so [EnableRateLimiting] metadata is visible
app.UseAuthentication();
app.UseAuthorization();
app.UseMiddleware<AuditLoggingMiddleware>();       // after auth so the user name is known

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
