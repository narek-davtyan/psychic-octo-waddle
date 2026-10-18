using System.Security.Claims;
using SafeVault.Web.Data;

namespace SafeVault.Web.Security;

/// <summary>
/// Re-checks a signed-in user against the data store on EVERY request (called from the cookie
/// "OnValidatePrincipal" event). Without this, a cookie would stay valid for its whole lifetime even
/// after the user was deleted, locked out, or demoted. It fails CLOSED: any doubt means "not valid".
/// </summary>
public sealed class PrincipalValidator(IUserRepository users, TimeProvider time)
{
    public async Task<bool> IsValidAsync(ClaimsPrincipal? principal, CancellationToken ct = default)
    {
        if (principal?.Identity?.IsAuthenticated != true) return false;

        var idText = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(idText, out var id)) return false;

        return await CheckAsync(principal, id, ct);
    }

    private async Task<bool> CheckAsync(ClaimsPrincipal principal, Guid id, CancellationToken ct)
    {
        try
        {
            var user = await users.GetByIdAsync(id, ct);

            // Deleted user -> reject.
            if (user is null) return false;

            // Locked since the cookie was issued -> reject.
            if (user.LockoutEndUtc is { } end && end > time.GetUtcNow()) return false;

            // Role changed since the cookie was issued -> reject, forcing a fresh login with the new role.
            var roleClaim = principal.FindFirstValue(ClaimTypes.Role);
            return string.Equals(user.Role, roleClaim, StringComparison.Ordinal);
        }
        catch
        {
            // Store unavailable: fail closed rather than trusting a possibly stale elevated role.
            return false;
        }
    }
}
