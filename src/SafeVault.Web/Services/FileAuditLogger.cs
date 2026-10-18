using System.Text;

namespace SafeVault.Web.Services;

/// <summary>
/// Appends one line per event to logs/audit.log inside the data directory.
/// User-controlled text is sanitised first so an attacker cannot forge extra log lines
/// by sending CR/LF characters ("log injection").
/// </summary>
public sealed class FileAuditLogger : IAuditLogger
{
    private const int MaxFieldLength = 200;

    private readonly string _filePath;
    private readonly TimeProvider _time;
    private readonly object _lock = new();

    public FileAuditLogger(string dataDirectory, TimeProvider? time = null)
    {
        var logDirectory = Path.Combine(dataDirectory, "logs");
        Directory.CreateDirectory(logDirectory);
        _filePath = Path.Combine(logDirectory, "audit.log");
        _time = time ?? TimeProvider.System;
    }

    public void Log(string eventType, string? user = null, string? ip = null, string? details = null)
    {
        var line = $"{_time.GetUtcNow():yyyy-MM-ddTHH:mm:ssZ} | {Clean(eventType)} | user={Clean(user)} | ip={Clean(ip)} | {Clean(details)}";

        // A simple lock is plenty for an audit file written by a single process.
        lock (_lock)
        {
            File.AppendAllText(_filePath, line + Environment.NewLine, Encoding.UTF8);
        }
    }

    public IReadOnlyList<string> ReadRecent(int count)
    {
        lock (_lock)
        {
            if (!File.Exists(_filePath) || count <= 0) return [];
            return File.ReadAllLines(_filePath).TakeLast(count).ToList();
        }
    }

    /// <summary>Replaces control characters with spaces and truncates, so one event is always one line.</summary>
    internal static string Clean(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "-";

        var sb = new StringBuilder(Math.Min(value.Length, MaxFieldLength));
        foreach (var ch in value)
        {
            if (sb.Length >= MaxFieldLength) break;
            sb.Append(char.IsControl(ch) ? ' ' : ch);
        }

        return sb.ToString();
    }
}
