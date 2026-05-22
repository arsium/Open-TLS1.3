namespace TLS;

using System.Net.Sockets;

/// <summary>TLS 1.3 client — Connect() to a TLS server and get a TlsStream.</summary>
public sealed class TlsClient
{
    /// <summary>Handshake timeout in milliseconds. 0 = no timeout (default).</summary>
    public int HandshakeTimeoutMs { get; set; }

    /// <summary>Session ticket store for PSK resumption. Set this to enable automatic ticket storage and resumption.</summary>
    public SessionTicketStore? TicketStore { get; set; }

    /// <summary>ALPN protocols to offer during handshake (e.g., "h2", "http/1.1").</summary>
    public string[]? AlpnProtocols { get; set; }

    /// <summary>Record padding block size for traffic analysis resistance. 0 = no padding (default).</summary>
    public int PaddingBlockSize { get; set; }

    /// <summary>Request OCSP stapling from the server via the status_request extension.</summary>
    public bool RequestOcspStapling { get; set; }

    /// <summary>Override the cipher suites offered in ClientHello (in preference order). Null = stack default.</summary>
    public CipherSuite[]? CipherSuites { get; set; }

    /// <summary>Override the key-share groups offered in ClientHello (in preference order). Null = stack default.</summary>
    public NamedGroup[]? NamedGroups { get; set; }

    /// <summary>
    /// Connect to a TLS 1.3 server.
    /// Performs the full handshake and returns an encrypted stream.
    /// </summary>
    /// <param name="earlyData">Optional 0-RTT early data to send before the handshake completes. Check EarlyDataAccepted on the returned stream.</param>
    public TlsStream Connect(string host, int port, byte[]? earlyData = null)
    {
        var tcp = new TcpClient { NoDelay = true };
        try
        {
            tcp.Connect(host, port);

            var stream = tcp.GetStream();
            int origTimeout = stream.ReadTimeout;
            if (HandshakeTimeoutMs > 0) stream.ReadTimeout = HandshakeTimeoutMs;

            var conn = new TlsConnection(stream, isServer: false);
            ConfigureConnection(conn, host);
            if (earlyData != null) conn.SetEarlyData(earlyData);
            conn.HandshakeAsClient(host);

            if (HandshakeTimeoutMs > 0) stream.ReadTimeout = origTimeout;
            return new TlsStream(conn, tcp);
        }
        catch { tcp.Dispose(); throw; }
    }

    /// <summary>
    /// Connect to a TLS 1.3 server with a client certificate (mTLS).
    /// </summary>
    /// <param name="earlyData">Optional 0-RTT early data to send before the handshake completes. Check EarlyDataAccepted on the returned stream.</param>
    public TlsStream Connect(string host, int port, TlsCertificate clientCertificate, byte[]? earlyData = null)
    {
        var tcp = new TcpClient { NoDelay = true };
        try
        {
            tcp.Connect(host, port);

            var stream = tcp.GetStream();
            int origTimeout = stream.ReadTimeout;
            if (HandshakeTimeoutMs > 0) stream.ReadTimeout = HandshakeTimeoutMs;

            var conn = new TlsConnection(stream, isServer: false, certificate: clientCertificate);
            ConfigureConnection(conn, host);
            if (earlyData != null) conn.SetEarlyData(earlyData);
            conn.HandshakeAsClient(host);

            if (HandshakeTimeoutMs > 0) stream.ReadTimeout = origTimeout;
            return new TlsStream(conn, tcp);
        }
        catch { tcp.Dispose(); throw; }
    }

    // ================================================================
    //  Async methods
    // ================================================================

    /// <summary>
    /// Connect to a TLS 1.3 server asynchronously.
    /// Performs the full handshake and returns an encrypted stream.
    /// </summary>
    public async Task<TlsStream> ConnectAsync(string host, int port, byte[]? earlyData = null, CancellationToken ct = default)
    {
        var tcp = new TcpClient { NoDelay = true };
        try
        {
            await tcp.ConnectAsync(host, port, ct).ConfigureAwait(false);

            var stream = tcp.GetStream();
            int origTimeout = stream.ReadTimeout;
            if (HandshakeTimeoutMs > 0) stream.ReadTimeout = HandshakeTimeoutMs;

            var conn = new TlsConnection(stream, isServer: false);
            ConfigureConnection(conn, host);
            if (earlyData != null) conn.SetEarlyData(earlyData);
            await conn.HandshakeAsClientAsync(host, ct).ConfigureAwait(false);

            if (HandshakeTimeoutMs > 0) stream.ReadTimeout = origTimeout;
            return new TlsStream(conn, tcp);
        }
        catch { tcp.Dispose(); throw; }
    }

    /// <summary>
    /// Connect to a TLS 1.3 server with a client certificate (mTLS) asynchronously.
    /// </summary>
    public async Task<TlsStream> ConnectAsync(string host, int port, TlsCertificate clientCertificate, byte[]? earlyData = null, CancellationToken ct = default)
    {
        var tcp = new TcpClient { NoDelay = true };
        try
        {
            await tcp.ConnectAsync(host, port, ct).ConfigureAwait(false);

            var stream = tcp.GetStream();
            int origTimeout = stream.ReadTimeout;
            if (HandshakeTimeoutMs > 0) stream.ReadTimeout = HandshakeTimeoutMs;

            var conn = new TlsConnection(stream, isServer: false, certificate: clientCertificate);
            ConfigureConnection(conn, host);
            if (earlyData != null) conn.SetEarlyData(earlyData);
            await conn.HandshakeAsClientAsync(host, ct).ConfigureAwait(false);

            if (HandshakeTimeoutMs > 0) stream.ReadTimeout = origTimeout;
            return new TlsStream(conn, tcp);
        }
        catch { tcp.Dispose(); throw; }
    }

    private void ConfigureConnection(TlsConnection conn, string host)
    {
        if (AlpnProtocols != null)
            conn.SetAlpnProtocols(AlpnProtocols);

        if (PaddingBlockSize > 0)
            conn.PaddingBlockSize = PaddingBlockSize;

        if (RequestOcspStapling)
            conn.RequestOcspStapling();

        if (CipherSuites != null)
            conn.SetOfferedCipherSuites(CipherSuites);

        if (NamedGroups != null)
            conn.SetOfferedGroups(NamedGroups);

        if (TicketStore == null) return;

        var ticket = TicketStore.Get(host);
        if (ticket != null)
            conn.SetClientTicket(ticket);

        conn.SetNewTicketCallback(t =>
        {
            TicketStore.Add(host, t);
        });
    }
}
