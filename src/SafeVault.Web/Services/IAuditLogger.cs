namespace SafeVault.Web.Services;

/// <summary>Writes security-relevant events (logins, lockouts, role changes, errors) to an audit trail.</summary>
public interface IAuditLogger
{
    /// <param name="eventType">Short event name, for example LOGIN_SUCCESS.</param>
    /// <param name="user">Username involved (may be unauthenticated input - it is sanitised before writing).</param>
    /// <param name="ip">Client IP address.</param>
    /// <param name="details">Optional extra text.</param>
    void Log(string eventType, string? user = null, string? ip = null, string? details = null);

    /// <summary>Returns the most recent <paramref name="count"/> lines (newest last) for the admin dashboard.</summary>
    IReadOnlyList<string> ReadRecent(int count);
}
