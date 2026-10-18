namespace SafeVault.Web.Models;

/// <summary>Role names used for role-based authorization.</summary>
public static class Roles
{
    public const string Admin = "Admin";
    public const string User = "User";

    /// <summary>Every role the application recognises (used to validate role changes).</summary>
    public static readonly string[] All = [Admin, User];

    /// <summary>Returns true only for an exact (case-sensitive) known role name.</summary>
    public static bool IsValid(string? role) =>
        role is not null && Array.IndexOf(All, role) >= 0;
}

/// <summary>
/// A stored user account. It is an immutable record: to change a user, create a
/// modified copy with a <c>with</c> expression and hand it to the repository.
/// </summary>
public sealed record User
{
    /// <summary>Opaque, non-guessable identifier (never an incrementing number).</summary>
    public Guid Id { get; init; } = Guid.NewGuid();

    public required string Username { get; init; }

    public required string Email { get; init; }

    /// <summary>Self-describing PBKDF2 hash string. The plain password is never stored.</summary>
    public required string PasswordHash { get; init; }

    public string Role { get; init; } = Roles.User;

    public DateTimeOffset CreatedUtc { get; init; } = DateTimeOffset.UtcNow;

    public DateTimeOffset? LastLoginUtc { get; init; }

    /// <summary>Consecutive failed logins since the last success (drives account lockout).</summary>
    public int FailedLoginCount { get; init; }

    /// <summary>When set and in the future, the account refuses all logins.</summary>
    public DateTimeOffset? LockoutEndUtc { get; init; }
}
