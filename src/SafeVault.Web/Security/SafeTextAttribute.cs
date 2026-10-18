using System.ComponentModel.DataAnnotations;

namespace SafeVault.Web.Security;

/// <summary>
/// Validation attribute: fails model validation when a string looks like an XSS or SQL-injection payload.
/// Apply it to free-text fields (NOT to passwords).
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public sealed class SafeTextAttribute : ValidationAttribute
{
    public SafeTextAttribute() : base("The value contains characters or patterns that are not allowed.") { }

    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        // null/non-string values are left to [Required] and type binding.
        if (value is string text && InputSanitizer.IsSuspicious(text))
        {
            return new ValidationResult(FormatErrorMessage(validationContext.DisplayName));
        }

        return ValidationResult.Success;
    }
}
