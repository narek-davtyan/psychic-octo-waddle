using SafeVault.Web.Services;

namespace SafeVault.Web.Middleware;

/// <summary>
/// Records access-control related outcomes: 401 (not signed in), 403 (wrong role) and 429 (rate limited),
/// plus every request into the /Admin area. Placed AFTER authentication/authorization so the user is known.
/// </summary>
public sealed class AuditLoggingMiddleware(RequestDelegate next, IAuditLogger audit)
{
    public async Task InvokeAsync(HttpContext context)
    {
        await next(context);

        var status = context.Response.StatusCode;
        var isAdminArea = context.Request.Path.StartsWithSegments("/Admin", StringComparison.OrdinalIgnoreCase);

        if (status is 401 or 403 or 429 || (isAdminArea && context.Request.Method != HttpMethods.Get))
        {
            audit.Log("ACCESS",
                context.User.Identity?.Name,
                context.Connection.RemoteIpAddress?.ToString(),
                $"{context.Request.Method} {context.Request.Path} -> {status}");
        }
    }
}
