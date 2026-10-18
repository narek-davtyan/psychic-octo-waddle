namespace SafeVault.Web.Security;

/// <summary>
/// Password rules (aligned with the NIST/OWASP idea of "long and not trivially guessable"):
/// 12-128 characters, mixed character classes, and not containing the username.
/// </summary>
public static class PasswordPolicy
{
    public const int MinLength = 12;
    public const int MaxLength = 128;

    /// <summary>Returns a list of human-readable problems; an empty list means the password is acceptable.</summary>
    public static IReadOnlyList<string> Validate(string? password, string? username = null)
    {
        var errors = new List<string>();

        if (string.IsNullOrEmpty(password))
        {
            errors.Add("Password is required.");
            return errors;
        }

        if (password.Length < MinLength) errors.Add($"Password must be at least {MinLength} characters long.");
        if (password.Length > MaxLength) errors.Add($"Password must be at most {MaxLength} characters long.");
        if (!password.Any(char.IsUpper)) errors.Add("Password must contain an uppercase letter.");
        if (!password.Any(char.IsLower)) errors.Add("Password must contain a lowercase letter.");
        if (!password.Any(char.IsDigit)) errors.Add("Password must contain a digit.");
        if (password.All(char.IsLetterOrDigit)) errors.Add("Password must contain a symbol (for example ! # $ % ?).");

        if (!string.IsNullOrWhiteSpace(username) &&
            password.Contains(username, StringComparison.OrdinalIgnoreCase))
        {
            errors.Add("Password must not contain your username.");
        }

        return errors;
    }
}
