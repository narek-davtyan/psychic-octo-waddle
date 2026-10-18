using SafeVault.Web.Services;

namespace SafeVault.Web.Middleware;

/// <summary>
/// Logs unhandled exceptions (full detail to the application log, a short entry to the audit trail)
/// and then re-throws so the global exception handler shows the generic error page.
/// The client NEVER sees stack traces or exception messages in production.
/// </summary>
public sealed class ExceptionLoggingMiddleware(
    RequestDelegate next, ILogger<ExceptionLoggingMiddleware> logger, IAuditLogger audit)
{
    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await next(context);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // TraceIdentifier lets support staff match what the user sees to what we logged.
            logger.LogError(ex, "Unhandled exception for {Method} {Path} (trace {TraceId})",
                context.Request.Method, context.Request.Path, context.TraceIdentifier);

            audit.Log("SERVER_ERROR", context.User.Identity?.Name,
                context.Connection.RemoteIpAddress?.ToString(),
                $"{ex.GetType().Name} on {context.Request.Path} trace={context.TraceIdentifier}");

            throw;
        }
    }
}
