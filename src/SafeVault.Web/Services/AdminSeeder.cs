using System.Security.Cryptography;
using SafeVault.Web.Data;
using SafeVault.Web.Models;

namespace SafeVault.Web.Services;

/// <summary>
/// Makes sure a first administrator exists on a fresh install, otherwise nobody could ever
/// reach the admin dashboard (self-registration only creates normal users).
/// </summary>
public static class AdminSeeder
{
    public static async Task EnsureAdminAsync(
        IUserRepository users, IPasswordHasher hasher, IConfiguration config, ILogger logger, IAuditLogger audit)
    {
        // If any admin already exists there is nothing to do.
        if ((await users.ListAsync()).Any(u => u.Role == Roles.Admin)) return;

        var username = config["SafeVault:SeedAdmin:Username"] is { Length: > 0 } u ? u : "admin";
        var email = config["SafeVault:SeedAdmin:Email"] is { Length: > 0 } e ? e : "admin@safevault.local";
        var password = config["SafeVault:SeedAdmin:Password"];

        var generated = string.IsNullOrWhiteSpace(password);
        if (generated) password = GeneratePassword();

        var created = await users.AddAsync(new User
        {
            Username = username,
            Email = email,
            PasswordHash = hasher.Hash(password!),
            Role = Roles.Admin
        });

        if (!created)
        {
            logger.LogWarning("Seed admin '{Username}' could not be created (name or e-mail already used).", username);
            return;
        }

        audit.Log("ADMIN_SEEDED", username, details: "initial administrator created");

        if (generated)
        {
            // Shown once, only on the console. It is never written to the audit log or any file.
            logger.LogWarning("Initial administrator created. Username: {Username}  Password: {Password}  (shown once - change it!)",
                username, password);
        }
        else
        {
            logger.LogInformation("Initial administrator '{Username}' created from configuration.", username);
        }
    }

    /// <summary>Generates a random 20-character password that satisfies the password policy.</summary>
    private static string GeneratePassword()
    {
        const string upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
        const string lower = "abcdefghijkmnopqrstuvwxyz";
        const string digits = "23456789";
        const string symbols = "!#$%?*+-=";
        const string all = upper + lower + digits + symbols;

        // One of each class guaranteed, the rest random; then shuffle so the pattern is not predictable.
        var chars = new List<char>
        {
            upper[RandomNumberGenerator.GetInt32(upper.Length)],
            lower[RandomNumberGenerator.GetInt32(lower.Length)],
            digits[RandomNumberGenerator.GetInt32(digits.Length)],
            symbols[RandomNumberGenerator.GetInt32(symbols.Length)]
        };
        while (chars.Count < 20) chars.Add(all[RandomNumberGenerator.GetInt32(all.Length)]);

        var result = chars.ToArray();
        RandomNumberGenerator.Shuffle<char>(result);
        return new string(result);
    }
}
