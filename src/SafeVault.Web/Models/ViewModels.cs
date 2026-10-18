using System.ComponentModel.DataAnnotations;
using SafeVault.Web.Security;

namespace SafeVault.Web.Models;

/// <summary>Registration form. Server-side validation is the source of truth.</summary>
public sealed class RegisterViewModel
{
    // Whitelist approach: only letters, digits, underscore, dot and hyphen are accepted.
    [Required, StringLength(32, MinimumLength = 3)]
    [RegularExpression(InputSanitizer.UsernamePattern,
        ErrorMessage = "Username may only contain letters, digits, '_', '.' and '-'.")]
    [SafeText]
    public string Username { get; set; } = string.Empty;

    [Required, EmailAddress, StringLength(254)]
    [SafeText]
    public string Email { get; set; } = string.Empty;

    // Passwords are NOT passed through SafeText: they may legitimately contain symbols like ' or <.
    // They are only ever hashed, never rendered or put into a query, so that is safe.
    [Required, DataType(DataType.Password), StringLength(128)]
    public string Password { get; set; } = string.Empty;

    [Required, DataType(DataType.Password), Display(Name = "Confirm password")]
    [Compare(nameof(Password), ErrorMessage = "The passwords do not match.")]
    public string ConfirmPassword { get; set; } = string.Empty;
}

/// <summary>Login form.</summary>
public sealed class LoginViewModel
{
    [Required, StringLength(32, MinimumLength = 3)]
    [SafeText]
    public string Username { get; set; } = string.Empty;

    [Required, DataType(DataType.Password), StringLength(128)]
    public string Password { get; set; } = string.Empty;

    /// <summary>Where to go after login. Only local URLs are honoured (open-redirect defence).</summary>
    public string? ReturnUrl { get; set; }
}

/// <summary>Data shown on the profile page.</summary>
public sealed record ProfileViewModel(
    string Username, string Email, string Role,
    DateTimeOffset CreatedUtc, DateTimeOffset? LastLoginUtc);

/// <summary>Data shown on the admin dashboard.</summary>
public sealed record AdminIndexViewModel(
    IReadOnlyList<User> Users, Guid CurrentUserId, IReadOnlyList<string> RecentAuditLines);

/// <summary>Data for the generic error page.</summary>
public sealed record ErrorViewModel(string? RequestId, int? StatusCode = null)
{
    public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);
}
