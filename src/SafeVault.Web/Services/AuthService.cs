using SafeVault.Web.Data;
using SafeVault.Web.Models;
using SafeVault.Web.Security;

namespace SafeVault.Web.Services;

public enum RegisterStatus { Success, InvalidInput, Duplicate }

/// <param name="Errors">Human-readable validation problems (empty on success).</param>
public sealed record RegisterResult(RegisterStatus Status, User? User, IReadOnlyList<string> Errors);

public enum LoginStatus { Success, InvalidCredentials, LockedOut }

public sealed record LoginResult(LoginStatus Status, User? User);

/// <summary>
/// All registration / authentication business rules live here (not in the controller), which keeps
/// controllers thin and makes the rules easy to unit-test with a fake repository and fake clock.
/// </summary>
public sealed class AuthService(
    IUserRepository users,
    IPasswordHasher hasher,
    SecurityOptions options,
    TimeProvider time,
    IAuditLogger audit)
{
    /// <summary>Creates a new account with the least-privileged <see cref="Roles.User"/> role.</summary>
    public async Task<RegisterResult> RegisterAsync(
        string username, string email, string password, string? ip, CancellationToken ct = default)
    {
        username = InputSanitizer.NormalizeUsername(username);
        email = (email ?? string.Empty).Trim();

        // Re-validate here as well: never trust that the caller (controller) already did.
        var errors = new List<string>();
        if (!InputSanitizer.IsValidUsername(username) || InputSanitizer.IsSuspicious(username))
            errors.Add("Username is not valid.");
        if (!IsPlausibleEmail(email) || InputSanitizer.IsSuspicious(email))
            errors.Add("Email address is not valid.");
        errors.AddRange(PasswordPolicy.Validate(password, username));

        if (errors.Count > 0)
        {
            return new RegisterResult(RegisterStatus.InvalidInput, null, errors);
        }

        var user = new User
        {
            Username = username,
            Email = email,
            PasswordHash = hasher.Hash(password),
            Role = Roles.User,              // self-registration NEVER grants elevated roles
            CreatedUtc = time.GetUtcNow()
        };

        if (!await users.AddAsync(user, ct))
        {
            audit.Log("REGISTER_DUPLICATE", username, ip);
            return new RegisterResult(RegisterStatus.Duplicate, null, ["That username or email is already in use."]);
        }

        audit.Log("REGISTER_SUCCESS", username, ip);
        return new RegisterResult(RegisterStatus.Success, user, []);
    }

    /// <summary>
    /// Verifies credentials, applying lockout rules. The caller shows ONE generic message for every
    /// failure so attackers cannot tell "no such user" from "wrong password" from "locked".
    /// </summary>
    public async Task<LoginResult> LoginAsync(string username, string password, string? ip, CancellationToken ct = default)
    {
        username = InputSanitizer.NormalizeUsername(username);
        var now = time.GetUtcNow();

        var user = await users.GetByUsernameAsync(username, ct);
        if (user is null)
        {
            hasher.BurnTime(password);      // equalise timing with the "user exists" path
            audit.Log("LOGIN_FAILED", username, ip, "unknown user");
            return new LoginResult(LoginStatus.InvalidCredentials, null);
        }

        // Locked accounts are rejected before any password check.
        if (user.LockoutEndUtc is { } lockoutEnd && lockoutEnd > now)
        {
            hasher.BurnTime(password);
            audit.Log("LOGIN_BLOCKED_LOCKED", username, ip);
            return new LoginResult(LoginStatus.LockedOut, null);
        }

        if (!hasher.Verify(password, user.PasswordHash))
        {
            var failures = user.FailedLoginCount + 1;
            var locked = failures >= options.MaxFailedLoginAttempts;

            await users.UpdateAsync(user with
            {
                FailedLoginCount = locked ? 0 : failures,
                LockoutEndUtc = locked ? now.AddMinutes(options.LockoutMinutes) : user.LockoutEndUtc
            }, ct);

            audit.Log(locked ? "ACCOUNT_LOCKED" : "LOGIN_FAILED", username, ip, $"failures={failures}");
            return new LoginResult(locked ? LoginStatus.LockedOut : LoginStatus.InvalidCredentials, null);
        }

        // Success: reset counters, and upgrade the hash if our settings became stronger.
        var updated = user with
        {
            FailedLoginCount = 0,
            LockoutEndUtc = null,
            LastLoginUtc = now,
            PasswordHash = hasher.NeedsRehash(user.PasswordHash) ? hasher.Hash(password) : user.PasswordHash
        };
        await users.UpdateAsync(updated, ct);

        audit.Log("LOGIN_SUCCESS", username, ip);
        return new LoginResult(LoginStatus.Success, updated);
    }

    /// <summary>
    /// Pragmatic e-mail shape check (exactly one '@', non-empty local part, dotted domain).
    /// Real ownership of an address can only be proven by sending a confirmation e-mail.
    /// </summary>
    private static bool IsPlausibleEmail(string email)
    {
        if (email.Length is < 5 or > 254) return false;
        var at = email.IndexOf('@');
        if (at < 1 || at != email.LastIndexOf('@')) return false;
        var domain = email[(at + 1)..];
        return domain.Contains('.') && !domain.StartsWith('.') && !domain.EndsWith('.') && !email.Contains(' ');
    }
}
