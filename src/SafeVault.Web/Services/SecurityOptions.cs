namespace SafeVault.Web.Services;

/// <summary>Tunable security settings, bound from the "SafeVault:Security" configuration section.</summary>
public sealed class SecurityOptions
{
    /// <summary>Consecutive failed logins before the account is locked.</summary>
    public int MaxFailedLoginAttempts { get; set; } = 5;

    /// <summary>How long a locked account stays locked.</summary>
    public int LockoutMinutes { get; set; } = 15;

    /// <summary>PBKDF2 iteration count for NEW hashes.</summary>
    public int Pbkdf2Iterations { get; set; } = 600_000;

    /// <summary>Per-IP request budget per minute for login/register endpoints.</summary>
    public int AuthRequestsPerMinute { get; set; } = 10;
}
