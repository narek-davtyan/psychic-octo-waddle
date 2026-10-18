using SafeVault.Web.Security;

namespace SafeVault.Tests;

public class PasswordPolicyTests
{
    [Fact]
    public void Strong_Password_Has_No_Errors()
    {
        Assert.Empty(PasswordPolicy.Validate("Correct-Horse-9!", "alice"));
    }

    [Theory]
    [InlineData("Sh0rt!a")]               // too short
    [InlineData("alllowercase-1234!!")]   // no upper case
    [InlineData("ALLUPPERCASE-1234!!")]   // no lower case
    [InlineData("NoDigitsHere-abc!!")]    // no digit
    [InlineData("NoSymbolsHere12345")]    // no symbol
    public void Weak_Passwords_Are_Rejected(string password)
    {
        Assert.NotEmpty(PasswordPolicy.Validate(password, "alice"));
    }

    [Fact]
    public void Password_Containing_Username_Is_Rejected()
    {
        Assert.NotEmpty(PasswordPolicy.Validate("My-ALICE-Passw0rd!", "alice"));
    }

    [Fact]
    public void Empty_Password_Is_Rejected()
    {
        Assert.NotEmpty(PasswordPolicy.Validate("", "alice"));
    }
}
