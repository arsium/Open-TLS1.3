namespace TLS;

/// <summary>
/// SSLKEYLOGFILE key logger for TLS 1.3 traffic decryption (Wireshark compatible).
/// Set the SSLKEYLOGFILE environment variable to a file path to enable logging.
/// Format: NSS Key Log Format (https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format)
/// </summary>
public static class KeyLogger
{
    private static readonly string? _logFile;
    private static readonly object _lock = new();

    static KeyLogger()
    {
        _logFile = Environment.GetEnvironmentVariable("SSLKEYLOGFILE");
    }

    public static bool IsEnabled => _logFile != null;

    public static void LogHandshakeTrafficSecrets(byte[] clientRandom, byte[] clientSecret, byte[] serverSecret)
    {
        if (_logFile == null) return;
        string cr = ToHex(clientRandom);
        WriteLines(
            $"CLIENT_HANDSHAKE_TRAFFIC_SECRET {cr} {ToHex(clientSecret)}",
            $"SERVER_HANDSHAKE_TRAFFIC_SECRET {cr} {ToHex(serverSecret)}"
        );
    }

    public static void LogAppTrafficSecrets(byte[] clientRandom, byte[] clientSecret, byte[] serverSecret)
    {
        if (_logFile == null) return;
        string cr = ToHex(clientRandom);
        WriteLines(
            $"CLIENT_TRAFFIC_SECRET_0 {cr} {ToHex(clientSecret)}",
            $"SERVER_TRAFFIC_SECRET_0 {cr} {ToHex(serverSecret)}"
        );
    }

    public static void LogEarlyTrafficSecret(byte[] clientRandom, byte[] earlySecret)
    {
        if (_logFile == null) return;
        WriteLines($"CLIENT_EARLY_TRAFFIC_SECRET {ToHex(clientRandom)} {ToHex(earlySecret)}");
    }

    public static void LogExporterSecret(byte[] clientRandom, byte[] exporterSecret)
    {
        if (_logFile == null) return;
        WriteLines($"EXPORTER_SECRET {ToHex(clientRandom)} {ToHex(exporterSecret)}");
    }

    private static string ToHex(byte[] data) => Convert.ToHexString(data).ToLowerInvariant();

    private static void WriteLines(params string[] lines)
    {
        lock (_lock)
        {
            File.AppendAllLines(_logFile!, lines);
        }
    }
}
