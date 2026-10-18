using SafeVault.Web.Models;

namespace SafeVault.Web.Data;

/// <summary>
/// Persistence contract for users. Controllers and services depend on this interface only,
/// so the file-backed store can be swapped for EF Core / SQL Server / PostgreSQL later
/// without touching any other code. (If you do move to SQL, use parameterised queries or EF Core.)
/// </summary>
public interface IUserRepository
{
    Task<User?> GetByIdAsync(Guid id, CancellationToken ct = default);

    /// <summary>Case-insensitive username lookup.</summary>
    Task<User?> GetByUsernameAsync(string username, CancellationToken ct = default);

    Task<IReadOnlyList<User>> ListAsync(CancellationToken ct = default);

    /// <summary>Adds a user. Returns false (and stores nothing) if the username or email already exists.</summary>
    Task<bool> AddAsync(User user, CancellationToken ct = default);

    /// <summary>Replaces the stored user with the same Id. Returns false if it does not exist.</summary>
    Task<bool> UpdateAsync(User user, CancellationToken ct = default);

    /// <summary>Deletes a user. Returns false if it does not exist.</summary>
    Task<bool> DeleteAsync(Guid id, CancellationToken ct = default);
}
