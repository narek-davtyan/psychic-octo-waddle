using SafeVault.Web.Services;

namespace SafeVault.Tests;

public class Pbkdf2PasswordHasherTests
{
    // Low iteration count keeps the test suite fast; production uses the configured (much higher) value.
    private readonly Pbkdf2PasswordHasher _hasher = new(iterations: 2_000);

    [Fact]
    public void Hash_Then_Verify_Succeeds_For_Correct_Password()
    {
        var hash = _hasher.Hash("Correct-Horse-9!");
        Assert.True(_hasher.Verify("Correct-Horse-9!", hash));
    }

    [Fact]
    public void Verify_Fails_For_Wrong_Password()
    {
        var hash = _hasher.Hash("Correct-Horse-9!");
        Assert.False(_hasher.Verify("correct-horse-9!", hash)); // case differs
    }

    [Fact]
    public void Same_Password_Produces_Different_Hashes_Because_Of_Random_Salt()
    {
        Assert.NotEqual(_hasher.Hash("Correct-Horse-9!"), _hasher.Hash("Correct-Horse-9!"));
    }

    [Fact]
    public void Hash_Never_Contains_The_Plain_Password()
    {
        Assert.DoesNotContain("Correct-Horse-9!", _hasher.Hash("Correct-Horse-9!"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-hash")]
    [InlineData("$pbkdf2-sha512$abc$AAAA$AAAA")]
    [InlineData("$pbkdf2-sha512$2000$!!!$!!!")]
    [InlineData("$other-algo$2000$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")]
    public void Verify_Returns_False_For_Malformed_Stored_Hash_Instead_Of_Throwing(string stored)
    {
        Assert.False(_hasher.Verify("whatever", stored));
    }

    [Fact]
    public void NeedsRehash_Is_True_When_Stored_Hash_Uses_Fewer_Iterations()
    {
        var weakHash = new Pbkdf2PasswordHasher(1_000).Hash("Correct-Horse-9!");
        Assert.True(_hasher.NeedsRehash(weakHash));
        Assert.False(_hasher.NeedsRehash(_hasher.Hash("Correct-Horse-9!")));
    }

    [Fact]
    public void Constructor_Rejects_Dangerously_Low_Iteration_Counts()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new Pbkdf2PasswordHasher(10));
    }
}
