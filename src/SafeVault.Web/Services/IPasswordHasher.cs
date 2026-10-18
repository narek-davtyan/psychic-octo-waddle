namespace SafeVault.Web.Services;

/// <summary>Abstraction over password hashing so the algorithm can be upgraded later.</summary>
public interface IPasswordHasher
{
    /// <summary>Creates a salted, self-describing hash string for storage.</summary>
    string Hash(string password);

    /// <summary>Checks a password against a stored hash in constant time. Never throws for bad input.</summary>
    bool Verify(string password, string storedHash);

    /// <summary>True if the stored hash uses weaker parameters than the current settings and should be re-hashed.</summary>
    bool NeedsRehash(string storedHash);

    /// <summary>
    /// Spends the same CPU time as a real verification. Called when the username does not exist so
    /// response timing does not reveal which usernames are registered.
    /// </summary>
    void BurnTime(string password);
}
