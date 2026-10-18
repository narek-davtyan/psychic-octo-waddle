using SafeVault.Web.Models;
using SafeVault.Web.Services;

namespace SafeVault.Tests;

public class AuthServiceTests
{
    private const string GoodPassword = "Correct-Horse-9!";

    private readonly InMemoryUserRepository _repo = new();
    private readonly RecordingAuditLogger _audit = new();
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
    private readonly SecurityOptions _options = new() { MaxFailedLoginAttempts = 3, LockoutMinutes = 15 };
    private readonly AuthService _auth;

    public AuthServiceTests()
    {
        _auth = new AuthService(_repo, new Pbkdf2PasswordHasher(2_000), _options, _time, _audit);
    }

    // ------------------------------------------------------------ registration

    [Fact]
    public async Task Register_Creates_Normal_User_With_Hashed_Password()
    {
        var result = await _auth.RegisterAsync("alice", "alice@example.com", GoodPassword, "127.0.0.1");

        Assert.Equal(RegisterStatus.Success, result.Status);
        Assert.NotNull(result.User);
        Assert.Equal(Roles.User, result.User!.Role);           // never Admin
        Assert.NotEqual(GoodPassword, result.User.PasswordHash);
        Assert.DoesNotContain(GoodPassword, result.User.PasswordHash);
    }

    [Fact]
    public async Task Register_Rejects_Duplicate_Username_Case_Insensitively()
    {
        await _auth.RegisterAsync("alice", "alice@example.com", GoodPassword, null);
        var second = await _auth.RegisterAsync("ALICE", "other@example.com", GoodPassword, null);

        Assert.Equal(RegisterStatus.Duplicate, second.Status);
    }

    [Fact]
    public async Task Register_Rejects_Duplicate_Email()
    {
        await _auth.RegisterAsync("alice", "alice@example.com", GoodPassword, null);
        var second = await _auth.RegisterAsync("bob", "Alice@Example.com", GoodPassword, null);

        Assert.Equal(RegisterStatus.Duplicate, second.Status);
    }

    [Theory]
    [InlineData("<script>x</script>", "a@example.com")]
    [InlineData("alice", "not-an-email")]
    [InlineData("admin'--", "a@example.com")]
    [InlineData("alice", "a@example.com<script>")]
    public async Task Register_Rejects_Malicious_Or_Invalid_Input_Even_If_Controller_Validation_Was_Skipped(string username, string email)
    {
        var result = await _auth.RegisterAsync(username, email, GoodPassword, null);

        Assert.Equal(RegisterStatus.InvalidInput, result.Status);
        Assert.Empty(await _repo.ListAsync());
    }

    [Fact]
    public async Task Register_Rejects_Weak_Password()
    {
        var result = await _auth.RegisterAsync("alice", "alice@example.com", "weak", null);
        Assert.Equal(RegisterStatus.InvalidInput, result.Status);
    }

    // ------------------------------------------------------------------- login

    [Fact]
    public async Task Login_Succeeds_With_Correct_Credentials_And_Records_Timestamp()
    {
        await _auth.RegisterAsync("alice", "alice@example.com", GoodPassword, null);

        var result = await _auth.LoginAsync("alice", GoodPassword, "127.0.0.1");

        Assert.Equal(LoginStatus.Success, result.Status);
        Assert.Equal(_time.GetUtcNow(), result.User!.LastLoginUtc);
    }

    [Fact]
    public async Task Login_Is_Case_Insensitive_For_Username()
    {
        await _auth.RegisterAsync("alice", "alice@example.com", GoodPassword, null);
        Assert.Equal(LoginStatus.Success, (await _auth.LoginAsync("ALICE", GoodPassword, null)).Status);
    }

    [Fact]
    public async Task Login_Fails_For_Wrong_Password_And_Unknown_User_With_Same_Status()
    {
        await _auth.RegisterAsync("alice", "alice@example.com", GoodPassword, null);

        var wrongPassword = await _auth.LoginAsync("alice", "Wrong-Password-1!", null);
        var unknownUser = await _auth.LoginAsync("nobody", GoodPassword, null);

        // Same result for both, so the UI cannot reveal which usernames exist.
        Assert.Equal(LoginStatus.InvalidCredentials, wrongPassword.Status);
        Assert.Equal(LoginStatus.InvalidCredentials, unknownUser.Status);
    }

    [Theory]
    [InlineData("' OR '1'='1")]
    [InlineData("alice' --")]
    [InlineData("admin'; DROP TABLE Users; --")]
    public async Task Sql_Injection_Style_Usernames_Never_Authenticate(string username)
    {
        await _auth.RegisterAsync("alice", "alice@example.com", GoodPassword, null);

        var result = await _auth.LoginAsync(username, GoodPassword, null);

        Assert.Equal(LoginStatus.InvalidCredentials, result.Status);
        Assert.Single(await _repo.ListAsync()); // and the "table" is still intact
    }

    // ----------------------------------------------------------------- lockout

    [Fact]
    public async Task Account_Locks_After_Too_Many_Failures_Even_For_Correct_Password()
    {
        await _auth.RegisterAsync("alice", "alice@example.com", GoodPassword, null);

        await _auth.LoginAsync("alice", "bad-1", null);
        await _auth.LoginAsync("alice", "bad-2", null);
        var third = await _auth.LoginAsync("alice", "bad-3", null);
        Assert.Equal(LoginStatus.LockedOut, third.Status);

        var correct = await _auth.LoginAsync("alice", GoodPassword, null);
        Assert.Equal(LoginStatus.LockedOut, correct.Status);
        Assert.Contains("ACCOUNT_LOCKED", _audit.Events);
    }

    [Fact]
    public async Task Lockout_Expires_After_The_Configured_Time()
    {
        await _auth.RegisterAsync("alice", "alice@example.com", GoodPassword, null);
        for (var i = 0; i < 3; i++) await _auth.LoginAsync("alice", "bad", null);

        _time.Advance(TimeSpan.FromMinutes(16));

        Assert.Equal(LoginStatus.Success, (await _auth.LoginAsync("alice", GoodPassword, null)).Status);
    }

    [Fact]
    public async Task Successful_Login_Resets_The_Failure_Counter()
    {
        await _auth.RegisterAsync("alice", "alice@example.com", GoodPassword, null);

        await _auth.LoginAsync("alice", "bad-1", null);
        await _auth.LoginAsync("alice", "bad-2", null);
        await _auth.LoginAsync("alice", GoodPassword, null);   // resets to 0
        await _auth.LoginAsync("alice", "bad-3", null);
        await _auth.LoginAsync("alice", "bad-4", null);

        // Only 2 failures since the reset, below the limit of 3, so the account is NOT locked.
        Assert.Equal(LoginStatus.Success, (await _auth.LoginAsync("alice", GoodPassword, null)).Status);
    }

    [Fact]
    public async Task Login_Upgrades_Old_Weak_Hashes_Transparently()
    {
        var weak = new Pbkdf2PasswordHasher(1_000);
        var strong = new Pbkdf2PasswordHasher(3_000);
        var oldHash = weak.Hash(GoodPassword);
        await _repo.AddAsync(new User { Username = "alice", Email = "alice@example.com", PasswordHash = oldHash });

        var auth = new AuthService(_repo, strong, _options, _time, _audit);
        var result = await auth.LoginAsync("alice", GoodPassword, null);

        Assert.Equal(LoginStatus.Success, result.Status);
        Assert.NotEqual(oldHash, result.User!.PasswordHash);
        Assert.False(strong.NeedsRehash(result.User.PasswordHash));
    }
}
