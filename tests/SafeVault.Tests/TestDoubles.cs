using SafeVault.Web.Data;
using SafeVault.Web.Models;
using SafeVault.Web.Services;

namespace SafeVault.Tests;

/// <summary>A clock tests can move forward, so lockout expiry is testable without sleeping.</summary>
public sealed class FakeTimeProvider(DateTimeOffset start) : TimeProvider
{
    private DateTimeOffset _now = start;

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;
}

/// <summary>Collects audit events in memory so tests can assert on them.</summary>
public sealed class RecordingAuditLogger : IAuditLogger
{
    public List<string> Events { get; } = [];

    public void Log(string eventType, string? user = null, string? ip = null, string? details = null) =>
        Events.Add(eventType);

    public IReadOnlyList<string> ReadRecent(int count) => Events.TakeLast(count).ToList();
}

/// <summary>Minimal in-memory repository used to test services without touching the disk.</summary>
public sealed class InMemoryUserRepository : IUserRepository
{
    private readonly List<User> _users = [];

    public Task<User?> GetByIdAsync(Guid id, CancellationToken ct = default) =>
        Task.FromResult(_users.FirstOrDefault(u => u.Id == id));

    public Task<User?> GetByUsernameAsync(string username, CancellationToken ct = default) =>
        Task.FromResult(_users.FirstOrDefault(u => string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase)));

    public Task<IReadOnlyList<User>> ListAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<User>>(_users.ToList());

    public Task<bool> AddAsync(User user, CancellationToken ct = default)
    {
        if (_users.Any(u => string.Equals(u.Username, user.Username, StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(u.Email, user.Email, StringComparison.OrdinalIgnoreCase)))
            return Task.FromResult(false);

        _users.Add(user);
        return Task.FromResult(true);
    }

    public Task<bool> UpdateAsync(User user, CancellationToken ct = default)
    {
        var i = _users.FindIndex(u => u.Id == user.Id);
        if (i < 0) return Task.FromResult(false);
        _users[i] = user;
        return Task.FromResult(true);
    }

    public Task<bool> DeleteAsync(Guid id, CancellationToken ct = default) =>
        Task.FromResult(_users.RemoveAll(u => u.Id == id) > 0);
}
