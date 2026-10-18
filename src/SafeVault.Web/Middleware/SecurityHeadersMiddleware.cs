namespace SafeVault.Web.Middleware;

/// <summary>
/// Adds defensive HTTP response headers to every response.
/// The Content-Security-Policy is the strongest XSS safety net: even if some markup slipped through,
/// the browser refuses to run inline scripts or load anything from other origins.
/// </summary>
public sealed class SecurityHeadersMiddleware(RequestDelegate next)
{
    public Task InvokeAsync(HttpContext context)
    {
        var headers = context.Response.Headers;

        headers["Content-Security-Policy"] =
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
            "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";
        headers["X-Content-Type-Options"] = "nosniff";            // no MIME sniffing
        headers["X-Frame-Options"] = "DENY";                       // anti-clickjacking (legacy browsers)
        headers["Referrer-Policy"] = "no-referrer";
        headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
        headers["Cross-Origin-Opener-Policy"] = "same-origin";

        return next(context);
    }
}
