using System.Text.RegularExpressions;

namespace SafeVault.Web.Security;

/// <summary>
/// Central place for input checks. These are a DEFENCE-IN-DEPTH layer:
/// the primary protections are (1) whitelist validation of each field,
/// (2) no SQL string building at all (the store is not SQL), and
/// (3) Razor's automatic HTML encoding on output.
/// We REJECT suspicious input rather than trying to "clean" it, because
/// blacklist-style sanitising is easy to bypass.
/// </summary>
public static partial class InputSanitizer
{
    /// <summary>Allowed usernames: 3-32 chars of letters, digits, '_', '.', '-'. (\z = absolute end of string.)</summary>
    public const string UsernamePattern = @"^[A-Za-z0-9_.\-]{3,32}\z";

    [GeneratedRegex(UsernamePattern)]
    private static partial Regex UsernameRegex();

    // Common script-injection shapes: dangerous tags, javascript: URLs, inline event handlers.
    [GeneratedRegex(
        @"<\s*/?\s*(script|iframe|object|embed|svg|img|link|style|meta|body|form|input|base)\b|javascript\s*:|vbscript\s*:|data\s*:\s*text/html|\bon\w+\s*=",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex XssRegex();

    // Common SQL-injection shapes (comment markers, stacked statements, tautologies, UNION SELECT...).
    [GeneratedRegex(
        @"(--|/\*|\*/|;\s*(drop|delete|insert|update|alter|exec)\b|\bunion\s+select\b|\bor\s+1\s*=\s*1\b|\bxp_cmdshell\b|\bdrop\s+table\b)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SqlRegex();

    /// <summary>True when the username matches the strict whitelist.</summary>
    public static bool IsValidUsername(string? username) =>
        username is not null && UsernameRegex().IsMatch(username);

    /// <summary>Trims and Unicode-normalises a username so look-alike forms compare equal.</summary>
    public static string NormalizeUsername(string? username) =>
        (username ?? string.Empty).Trim().Normalize(System.Text.NormalizationForm.FormC);

    /// <summary>True if the text contains any HTML-ish angle brackets or a known script pattern.</summary>
    public static bool ContainsXss(string? text) =>
        !string.IsNullOrEmpty(text) &&
        (text.AsSpan().IndexOfAny('<', '>') >= 0 || XssRegex().IsMatch(text));

    /// <summary>True if the text contains a known SQL-injection pattern.</summary>
    public static bool ContainsSqlInjection(string? text) =>
        !string.IsNullOrEmpty(text) && SqlRegex().IsMatch(text);

    /// <summary>True if the text contains control characters (NUL, CR, LF, ...), used for log/header injection.</summary>
    public static bool ContainsControlCharacters(string? text) =>
        !string.IsNullOrEmpty(text) && text.Any(char.IsControl);

    /// <summary>Combined check used by <see cref="SafeTextAttribute"/>.</summary>
    public static bool IsSuspicious(string? text) =>
        ContainsXss(text) || ContainsSqlInjection(text) || ContainsControlCharacters(text);
}
