using System.Security.Cryptography;

namespace SafeVault.Web.Services;

/// <summary>
/// PBKDF2-HMAC-SHA512 password hasher built on the .NET base class library (no extra packages).
/// Stored format:  $pbkdf2-sha512$&lt;iterations&gt;$&lt;base64 salt&gt;$&lt;base64 hash&gt;
/// Because the iteration count is stored with every hash, it can be raised later and old hashes
/// are upgraded transparently at next login (see <see cref="NeedsRehash"/>).
/// </summary>
public sealed class Pbkdf2PasswordHasher : IPasswordHasher
{
    private const string Prefix = "pbkdf2-sha512";
    private const int SaltSize = 16;   // 128-bit random salt per password
    private const int KeySize = 32;    // 256-bit derived key
    private const int MaxAcceptedIterations = 5_000_000; // guards against a tampered store forcing huge CPU use

    private readonly int _iterations;
    private readonly string _dummyHash;

    /// <param name="iterations">OWASP (2023) recommends at least 210,000 for PBKDF2-SHA512; we default to 600,000.</param>
    public Pbkdf2PasswordHasher(int iterations = 600_000)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(iterations, 1_000);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(iterations, MaxAcceptedIterations);
        _iterations = iterations;
        _dummyHash = Hash("timing-equalisation-password");
    }

    public string Hash(string password)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);

        // A fresh cryptographically random salt makes identical passwords hash differently.
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var key = Rfc2898DeriveBytes.Pbkdf2(password, salt, _iterations, HashAlgorithmName.SHA512, KeySize);

        return $"${Prefix}${_iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(key)}";
    }

    public bool Verify(string password, string storedHash)
    {
        if (string.IsNullOrEmpty(password) || !TryParse(storedHash, out var iterations, out var salt, out var expected))
        {
            return false;
        }

        var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA512, expected.Length);

        // FixedTimeEquals avoids leaking how many leading bytes matched.
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    public bool NeedsRehash(string storedHash) =>
        !TryParse(storedHash, out var iterations, out _, out _) || iterations < _iterations;

    public void BurnTime(string password) => _ = Verify(password ?? string.Empty, _dummyHash);

    /// <summary>Parses the stored string defensively; returns false for anything malformed.</summary>
    private static bool TryParse(string? stored, out int iterations, out byte[] salt, out byte[] key)
    {
        iterations = 0;
        salt = [];
        key = [];

        if (string.IsNullOrEmpty(stored)) return false;

        // "$a$b$c$d".Split('$') => ["", a, b, c, d]
        var parts = stored.Split('$');
        if (parts.Length != 5 || parts[0].Length != 0 || parts[1] != Prefix) return false;

        if (!int.TryParse(parts[2], out iterations) || iterations < 1_000 || iterations > MaxAcceptedIterations)
        {
            return false;
        }

        try
        {
            salt = Convert.FromBase64String(parts[3]);
            key = Convert.FromBase64String(parts[4]);
        }
        catch (FormatException)
        {
            return false;
        }

        return salt.Length >= 8 && key.Length >= 16;
    }
}
