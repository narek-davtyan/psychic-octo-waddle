using SafeVault.Web.Services;

namespace SafeVault.Tests;

public sealed class FileAuditLoggerTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "safevault-audit-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public void Log_Injection_Attempts_Cannot_Forge_Extra_Log_Lines()
    {
        var logger = new FileAuditLogger(_dir);

        // An attacker submits a "username" containing a newline and a fake success entry.
        logger.Log("LOGIN_FAILED", "evil\r\n2026-01-01T00:00:00Z | LOGIN_SUCCESS | user=admin", "10.0.0.1");

        var lines = logger.ReadRecent(10);
        Assert.Single(lines);                         // still exactly ONE line
        Assert.DoesNotContain("\n", lines[0]);
    }

    [Fact]
    public void Very_Long_Values_Are_Truncated()
    {
        var logger = new FileAuditLogger(_dir);
        logger.Log("X", new string('a', 10_000));

        Assert.True(logger.ReadRecent(1)[0].Length < 600);
    }

    [Fact]
    public void ReadRecent_Returns_Only_The_Newest_Lines()
    {
        var logger = new FileAuditLogger(_dir);
        for (var i = 0; i < 10; i++) logger.Log("EVENT" + i);

        var recent = logger.ReadRecent(3);
        Assert.Equal(3, recent.Count);
        Assert.Contains("EVENT9", recent[2]);
    }

    public void Dispose()
    {
        if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true);
    }
}
