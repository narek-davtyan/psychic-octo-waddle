using System.Security.Claims;
using SafeVault.Web.Models;
using SafeVault.Web.Security;

namespace SafeVault.Tests;

/// <summary>The validator re-checks cookies against the store on every request.</summary>
public class PrincipalValidatorTests
{
    private readonly InMemoryUserRepository _repo = new();
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
    private readonly PrincipalValidator _validator;

    public PrincipalValidatorTests() => _validator = new PrincipalValidator(_repo, _time);

    private static ClaimsPrincipal PrincipalFor(User user, string? roleOverride = null) =>
        new(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Role, roleOverride ?? user.Role)
        ], authenticationType: "Cookies"));

    private async Task<User> StoredUserAsync(string role = Roles.User)
    {
        var user = new User { Username = "alice", Email = "alice@example.com", PasswordHash = "h", Role = role };
        await _repo.AddAsync(user);
        return user;
    }

    [Fact]
    public async Task Valid_Principal_Is_Accepted()
    {
        var user = await StoredUserAsync();
        Assert.True(await _validator.IsValidAsync(PrincipalFor(user)));
    }

    [Fact]
    public async Task Deleted_User_Is_Rejected()
    {
        var user = await StoredUserAsync();
        await _repo.DeleteAsync(user.Id);
        Assert.False(await _validator.IsValidAsync(PrincipalFor(user)));
    }

    [Fact]
    public async Task Role_Change_Invalidates_Old_Cookies()
    {
        var user = await StoredUserAsync(Roles.Admin);
        var adminCookie = PrincipalFor(user);

        await _repo.UpdateAsync(user with { Role = Roles.User });   // demoted after the cookie was issued

        Assert.False(await _validator.IsValidAsync(adminCookie));
    }

    [Fact]
    public async Task Locked_User_Is_Rejected()
    {
        var user = await StoredUserAsync();
        await _repo.UpdateAsync(user with { LockoutEndUtc = _time.GetUtcNow().AddMinutes(5) });
        Assert.False(await _validator.IsValidAsync(PrincipalFor(user)));
    }

    [Fact]
    public async Task Anonymous_Or_Malformed_Principals_Are_Rejected()
    {
        Assert.False(await _validator.IsValidAsync(null));
        Assert.False(await _validator.IsValidAsync(new ClaimsPrincipal(new ClaimsIdentity())));

        var badId = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, "not-a-guid")], "Cookies"));
        Assert.False(await _validator.IsValidAsync(badId));
    }
}
