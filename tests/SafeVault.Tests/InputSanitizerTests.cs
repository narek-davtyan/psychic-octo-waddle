using System.ComponentModel.DataAnnotations;
using SafeVault.Web.Models;
using SafeVault.Web.Security;

namespace SafeVault.Tests;

/// <summary>Tests for the XSS / SQL-injection defences on user-supplied text.</summary>
public class InputSanitizerTests
{
    [Theory]
    [InlineData("<script>alert('xss')</script>")]
    [InlineData("<img src=x onerror=alert(1)>")]
    [InlineData("\"><svg/onload=alert(1)>")]
    [InlineData("javascript:alert(1)")]
    [InlineData("JaVaScRiPt :alert(1)")]
    [InlineData("<iframe src=//evil.example></iframe>")]
    [InlineData("hello <b>world</b>")]
    public void Xss_Payloads_Are_Detected(string payload)
    {
        Assert.True(InputSanitizer.ContainsXss(payload));
        Assert.True(InputSanitizer.IsSuspicious(payload));
    }

    [Theory]
    [InlineData("' OR 1=1 --")]
    [InlineData("admin'; DROP TABLE Users;--")]
    [InlineData("x' UNION SELECT username, password FROM users --")]
    [InlineData("1; DELETE FROM Users")]
    [InlineData("/* comment */ admin")]
    public void Sql_Injection_Payloads_Are_Detected(string payload)
    {
        Assert.True(InputSanitizer.ContainsSqlInjection(payload));
        Assert.True(InputSanitizer.IsSuspicious(payload));
    }

    [Theory]
    [InlineData("alice")]
    [InlineData("alice.smith-01")]
    [InlineData("alice@example.com")]
    [InlineData("Bob_The_Builder")]
    public void Ordinary_Text_Is_Not_Flagged(string text)
    {
        Assert.False(InputSanitizer.IsSuspicious(text));
    }

    [Fact]
    public void Control_Characters_Are_Flagged()
    {
        Assert.True(InputSanitizer.IsSuspicious("alice\r\nINJECTED"));
        Assert.True(InputSanitizer.IsSuspicious("al\0ice"));
    }

    [Theory]
    [InlineData("alice", true)]
    [InlineData("a.b-c_9", true)]
    [InlineData("ab", false)]                              // too short
    [InlineData("this_username_is_definitely_way_too_long_for_us", false)]
    [InlineData("has space", false)]
    [InlineData("semi;colon", false)]
    [InlineData("alice\n", false)]                         // trailing newline must NOT slip through ($ vs \z)
    [InlineData("<script>", false)]
    public void Username_Whitelist_Is_Enforced(string username, bool expected)
    {
        Assert.Equal(expected, InputSanitizer.IsValidUsername(username));
    }

    [Fact]
    public void RegisterViewModel_Validation_Rejects_Malicious_Username_And_Email()
    {
        var model = new RegisterViewModel
        {
            Username = "<script>alert(1)</script>",
            Email = "a@b.com<script>",
            Password = "Correct-Horse-9!",
            ConfirmPassword = "Correct-Horse-9!"
        };

        var results = new List<ValidationResult>();
        var valid = Validator.TryValidateObject(model, new ValidationContext(model), results, validateAllProperties: true);

        Assert.False(valid);
        Assert.NotEmpty(results);
    }

    [Fact]
    public void RegisterViewModel_Validation_Accepts_Good_Input_Including_Symbols_In_Password()
    {
        var model = new RegisterViewModel
        {
            Username = "alice",
            Email = "alice@example.com",
            Password = "It's<fine>&ok-123Z",   // symbols are fine in passwords because they are only hashed
            ConfirmPassword = "It's<fine>&ok-123Z"
        };

        var results = new List<ValidationResult>();
        Assert.True(Validator.TryValidateObject(model, new ValidationContext(model), results, true));
    }
}
