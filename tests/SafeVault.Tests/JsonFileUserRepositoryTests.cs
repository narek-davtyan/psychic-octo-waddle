using SafeVault.Web.Data;
using SafeVault.Web.Models;

namespace SafeVault.Tests;

public sealed class JsonFileUserRepositoryTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "safevault-tests-" + Guid.NewGuid().ToString("N"));

    private static User NewUser(string name, string role = Roles.User) =>
        new() { Username = name, Email = $"{name}@example.com", PasswordHash = "hash", Role = role };

    [Fact]
    public async Task Added_Users_Are_Persisted_And_Survive_A_New_Repository_Instance()
    {
        using (var repo = new JsonFileUserRepository(_dir))
        {
            Assert.True(await repo.AddAsync(NewUser("alice")));
        }

        using var reopened = new JsonFileUserRepository(_dir);   // simulates an app restart
        var loaded = await reopened.GetByUsernameAsync("ALICE");

        Assert.NotNull(loaded);
        Assert.Equal("alice@example.com", loaded!.Email);
    }

    [Fact]
    public async Task Duplicate_Username_Or_Email_Is_Refused()
    {
        using var repo = new JsonFileUserRepository(_dir);
        Assert.True(await repo.AddAsync(NewUser("alice")));

        Assert.False(await repo.AddAsync(NewUser("ALICE")));
        Assert.False(await repo.AddAsync(NewUser("other") with { Email = "ALICE@example.com" }));
        Assert.Single(await repo.ListAsync());
    }

    [Fact]
    public async Task Update_And_Delete_Work()
    {
        using var repo = new JsonFileUserRepository(_dir);
        var alice = NewUser("alice");
        await repo.AddAsync(alice);

        Assert.True(await repo.UpdateAsync(alice with { Role = Roles.Admin }));
        Assert.Equal(Roles.Admin, (await repo.GetByIdAsync(alice.Id))!.Role);

        Assert.True(await repo.DeleteAsync(alice.Id));
        Assert.Null(await repo.GetByIdAsync(alice.Id));
        Assert.False(await repo.DeleteAsync(alice.Id));
    }

    [Fact]
    public async Task Lookup_Treats_Injection_Strings_As_Plain_Data()
    {
        using var repo = new JsonFileUserRepository(_dir);
        await repo.AddAsync(NewUser("alice"));

        Assert.Null(await repo.GetByUsernameAsync("' OR 1=1 --"));
        Assert.Null(await repo.GetByUsernameAsync("alice' --"));
    }

    [Fact]
    public async Task Concurrent_Adds_Do_Not_Lose_Or_Corrupt_Data()
    {
        using var repo = new JsonFileUserRepository(_dir);

        await Task.WhenAll(Enumerable.Range(0, 25).Select(i => repo.AddAsync(NewUser($"user{i}"))));

        Assert.Equal(25, (await repo.ListAsync()).Count);

        using var reopened = new JsonFileUserRepository(_dir);
        Assert.Equal(25, (await reopened.ListAsync()).Count);   // the file on disk is intact and complete
    }

    public void Dispose()
    {
        if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true);
    }
}
