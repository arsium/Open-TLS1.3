namespace TLS;

using System.Net.Sockets;

/// <summary>Encrypted TLS 1.3 stream — Read() and Write() application data.</summary>
public sealed class TlsStream : IDisposable
{
    private readonly TlsConnection _conn;
    private readonly TcpClient _tcp;
    private bool _disposed;

    internal TlsStream(TlsConnection conn, TcpClient tcp)
    {
        _conn = conn;
        _tcp = tcp;
    }

    /// <summary>DER-encoded peer certificate, or null if no peer cert was provided.</summary>
    public byte[]? PeerCertificate => _conn.PeerCertificateData;

    /// <summary>Warnings from optional X.509 validation (expiration, hostname mismatch). Empty = all checks passed.</summary>
    public IReadOnlyList<string> CertificateWarnings => _conn.CertificateWarnings;

    /// <summary>True if this connection was established via PSK session resumption.</summary>
    public bool IsResumed => _conn.IsResumed;

    /// <summary>True if 0-RTT early data was accepted by the server.</summary>
    public bool EarlyDataAccepted => _conn.EarlyDataAccepted;

    /// <summary>Early data received from the client (server-side). Null if none.</summary>
    public byte[]? ReceivedEarlyData => _conn.ReceivedEarlyData;

    /// <summary>Negotiated ALPN protocol, or null if ALPN was not used.</summary>
    public string? NegotiatedAlpn => _conn.NegotiatedAlpn;

    /// <summary>Read decrypted data into buffer. Returns number of bytes read (0 = EOF from close_notify).</summary>
    public int Read(byte[] buffer, int offset = 0, int count = -1)
    {
        if (count < 0) count = buffer.Length - offset;
        return _conn.Read(buffer, offset, count);
    }

    /// <summary>Read one complete TLS record worth of decrypted data.</summary>
    public byte[] ReadAll()
    {
        return _conn.ReadAll();
    }

    /// <summary>Write data over the encrypted connection.</summary>
    public void Write(byte[] data, int offset = 0, int count = -1)
    {
        if (count < 0) count = data.Length - offset;
        _conn.Write(data, offset, count);
    }

    /// <summary>Export keying material per RFC 8446 §7.5.</summary>
    public byte[] ExportKeyingMaterial(string label, byte[] context, int length)
    {
        return _conn.ExportKeyingMaterial(label, context, length);
    }

    /// <summary>Request post-handshake client authentication (server-side only).</summary>
    public void RequestClientAuthentication()
    {
        _conn.RequestPostHandshakeAuth();
    }

    /// <summary>Request a key rotation (RFC 8446 §4.6.3). If requestPeerUpdate is true, the peer will also rotate.</summary>
    public void RequestKeyUpdate(bool requestPeerUpdate = true)
    {
        _conn.SendKeyUpdate(requestPeerUpdate);
    }

    /// <summary>Send close_notify alert and close the underlying TCP connection.</summary>
    public void Close()
    {
        if (_disposed) return;
        _disposed = true;
        try { _conn.SendAlert(AlertLevel.Warning, AlertDescription.CloseNotify); } catch { }
        _tcp.Close();
    }

    public void Dispose() => Close();

    // ================================================================
    //  Async methods
    // ================================================================

    /// <summary>Read decrypted data asynchronously. Returns number of bytes read (0 = EOF from close_notify).</summary>
    public async Task<int> ReadAsync(byte[] buffer, int offset = 0, int count = -1, CancellationToken ct = default)
    {
        if (count < 0) count = buffer.Length - offset;
        return await _conn.ReadAsync(buffer, offset, count, ct).ConfigureAwait(false);
    }

    /// <summary>Read one complete TLS record worth of decrypted data asynchronously.</summary>
    public async Task<byte[]> ReadAllAsync(CancellationToken ct = default)
    {
        return await _conn.ReadAllAsync(ct).ConfigureAwait(false);
    }

    /// <summary>Write data over the encrypted connection asynchronously.</summary>
    public async Task WriteAsync(byte[] data, int offset = 0, int count = -1, CancellationToken ct = default)
    {
        if (count < 0) count = data.Length - offset;
        await _conn.WriteAsync(data, offset, count, ct).ConfigureAwait(false);
    }

    /// <summary>Request a key rotation asynchronously (RFC 8446 §4.6.3).</summary>
    public async Task RequestKeyUpdateAsync(bool requestPeerUpdate = true, CancellationToken ct = default)
    {
        await _conn.SendKeyUpdateAsync(requestPeerUpdate, ct).ConfigureAwait(false);
    }

    /// <summary>Request post-handshake client authentication asynchronously (server-side only).</summary>
    public async Task RequestClientAuthenticationAsync(CancellationToken ct = default)
    {
        await _conn.RequestPostHandshakeAuthAsync(ct).ConfigureAwait(false);
    }

    /// <summary>Send close_notify alert and close the underlying TCP connection asynchronously.</summary>
    public async Task CloseAsync(CancellationToken ct = default)
    {
        if (_disposed) return;
        _disposed = true;
        try { await _conn.SendAlertAsync(AlertLevel.Warning, AlertDescription.CloseNotify, ct).ConfigureAwait(false); } catch { }
        _tcp.Close();
    }
}
