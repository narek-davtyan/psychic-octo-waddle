using System.Text.Json;
using SafeVault.Web.Models;

namespace SafeVault.Web.Data;

/// <summary>
/// Small, dependency-free user store that keeps all users in one JSON file (users.json).
/// - A <see cref="SemaphoreSlim"/> serialises access so concurrent requests cannot corrupt the file.
/// - Writes go to a temp file first and are then moved into place, so a crash never leaves half a file.
/// - Mutations are applied to a COPY of the list and only committed after the save succeeds.
/// Suitable for demos, tests and small single-instance deployments, not for multi-server setups.
/// </summary>
public sealed class JsonFileUserRepository : IUserRepository, IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly string _filePath;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private List<User>? _cache; // loaded lazily on first use

    public JsonFileUserRepository(string dataDirectory)
    {
        Directory.CreateDirectory(dataDirectory);
        _filePath = Path.Combine(dataDirectory, "users.json");
    }

    public async Task<User?> GetByIdAsync(Guid id, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var users = await LoadAsync(ct);
            return users.FirstOrDefault(u => u.Id == id);
        }
        finally { _gate.Release(); }
    }

    public async Task<User?> GetByUsernameAsync(string username, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var users = await LoadAsync(ct);
            return users.FirstOrDefault(u => string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase));
        }
        finally { _gate.Release(); }
    }

    public async Task<IReadOnlyList<User>> ListAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var users = await LoadAsync(ct);
            // Return a copy so callers can never mutate our cache.
            return users.OrderBy(u => u.Username, StringComparer.OrdinalIgnoreCase).ToList();
        }
        finally { _gate.Release(); }
    }

    public async Task<bool> AddAsync(User user, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var users = await LoadAsync(ct);

            // Usernames and e-mails must both be unique (case-insensitive).
            if (users.Any(u =>
                    string.Equals(u.Username, user.Username, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(u.Email, user.Email, StringComparison.OrdinalIgnoreCase)))
            {
                return false;
            }

            var next = new List<User>(users) { user };
            await SaveAsync(next, ct);
            _cache = next; // commit only after a successful save
            return true;
        }
        finally { _gate.Release(); }
    }

    public async Task<bool> UpdateAsync(User user, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var users = await LoadAsync(ct);
            var index = users.FindIndex(u => u.Id == user.Id);
            if (index < 0) return false;

            var next = new List<User>(users) { [index] = user };
            await SaveAsync(next, ct);
            _cache = next;
            return true;
        }
        finally { _gate.Release(); }
    }

    public async Task<bool> DeleteAsync(Guid id, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var users = await LoadAsync(ct);
            var next = users.Where(u => u.Id != id).ToList();
            if (next.Count == users.Count) return false;

            await SaveAsync(next, ct);
            _cache = next;
            return true;
        }
        finally { _gate.Release(); }
    }

    /// <summary>Reads the file once and caches it. Must be called while holding <c>_gate</c>.</summary>
    private async Task<List<User>> LoadAsync(CancellationToken ct)
    {
        if (_cache is not null) return _cache;

        if (!File.Exists(_filePath))
        {
            _cache = [];
            return _cache;
        }

        await using var stream = File.OpenRead(_filePath);
        _cache = await JsonSerializer.DeserializeAsync<List<User>>(stream, JsonOptions, ct) ?? [];
        return _cache;
    }

    /// <summary>Atomically writes the list to disk. Must be called while holding <c>_gate</c>.</summary>
    private async Task SaveAsync(List<User> users, CancellationToken ct)
    {
        var tempPath = _filePath + ".tmp";

        await using (var stream = File.Create(tempPath))
        {
            await JsonSerializer.SerializeAsync(stream, users, JsonOptions, ct);
        }

        // The file holds password hashes: on Linux/macOS make it readable by the owner only.
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(tempPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        File.Move(tempPath, _filePath, overwrite: true);
    }

    public void Dispose() => _gate.Dispose();
}
