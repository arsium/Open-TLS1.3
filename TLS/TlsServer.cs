namespace TLS;

using System.Net;
using System.Net.Sockets;

/// <summary>TLS 1.3 server — Listen() then Accept() connections as TlsStream.</summary>
public sealed class TlsServer : IDisposable
{
    private TcpListener? _listener;
    private readonly TlsCertificate _certificate;

    /// <summary>If true, the server sends CertificateRequest and requires a client certificate (mTLS).</summary>
    public bool RequireClientCertificate { get; set; }

    /// <summary>CA certificate used to verify client certificates during mTLS.</summary>
    public TlsCertificate? CaCertificate { get; set; }

    /// <summary>Handshake timeout in milliseconds. 0 = no timeout (default).</summary>
    public int HandshakeTimeoutMs { get; set; }

    /// <summary>Ticket encryption instance. Set to enable session ticket issuance for PSK resumption.</summary>
    public TicketEncryption? TicketEncryption { get; set; }

    /// <summary>Whether to accept 0-RTT early data from resuming clients.</summary>
    public bool Accept0Rtt { get; set; }

    /// <summary>Maximum early data size in bytes (default 16384).</summary>
    public uint MaxEarlyDataSize { get; set; } = 16384;

    /// <summary>ALPN protocols the server accepts, in preference order.</summary>
    public string[]? AlpnProtocols { get; set; }

    /// <summary>Enable certificate compression (RFC 8879, brotli).</summary>
    public bool UseCertificateCompression { get; set; }

    /// <summary>Record padding block size for traffic analysis resistance. 0 = no padding (default).</summary>
    public int PaddingBlockSize { get; set; }

    public TlsServer(TlsCertificate certificate)
    {
        _certificate = certificate;
    }

    /// <summary>Start listening for TCP connections on the given port.</summary>
    public void Listen(int port, IPAddress? address = null)
    {
        _listener = new TcpListener(address ?? IPAddress.Any, port);
        _listener.Start();
    }

    /// <summary>Accept one TCP connection, perform the TLS handshake, return an encrypted stream.</summary>
    public TlsStream Accept()
    {
        if (_listener == null)
            throw new InvalidOperationException("Call Listen() first");

        var tcp = _listener.AcceptTcpClient();
        try
        {
            var stream = tcp.GetStream();
            int origTimeout = stream.ReadTimeout;
            if (HandshakeTimeoutMs > 0) stream.ReadTimeout = HandshakeTimeoutMs;

            var conn = new TlsConnection(stream, isServer: true, _certificate,
                requireClientCert: RequireClientCertificate, caCertificate: CaCertificate);

            if (TicketEncryption != null)
                conn.EnableServerTickets(TicketEncryption, Accept0Rtt, MaxEarlyDataSize);
            if (AlpnProtocols != null)
                conn.SetAlpnProtocols(AlpnProtocols);
            if (UseCertificateCompression)
                conn.EnableCertificateCompression();
            if (PaddingBlockSize > 0)
                conn.PaddingBlockSize = PaddingBlockSize;

            conn.HandshakeAsServer();

            if (HandshakeTimeoutMs > 0) stream.ReadTimeout = origTimeout;
            return new TlsStream(conn, tcp);
        }
        catch { tcp.Dispose(); throw; }
    }

    /// <summary>Accept one TCP connection asynchronously, perform the TLS handshake, return an encrypted stream.</summary>
    public async Task<TlsStream> AcceptAsync(CancellationToken ct = default)
    {
        if (_listener == null)
            throw new InvalidOperationException("Call Listen() first");

        var tcp = await _listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
        try
        {
            var stream = tcp.GetStream();
            int origTimeout = stream.ReadTimeout;
            if (HandshakeTimeoutMs > 0) stream.ReadTimeout = HandshakeTimeoutMs;

            var conn = new TlsConnection(stream, isServer: true, _certificate,
                requireClientCert: RequireClientCertificate, caCertificate: CaCertificate);

            if (TicketEncryption != null)
                conn.EnableServerTickets(TicketEncryption, Accept0Rtt, MaxEarlyDataSize);
            if (AlpnProtocols != null)
                conn.SetAlpnProtocols(AlpnProtocols);
            if (UseCertificateCompression)
                conn.EnableCertificateCompression();
            if (PaddingBlockSize > 0)
                conn.PaddingBlockSize = PaddingBlockSize;

            await conn.HandshakeAsServerAsync(ct).ConfigureAwait(false);

            if (HandshakeTimeoutMs > 0) stream.ReadTimeout = origTimeout;
            return new TlsStream(conn, tcp);
        }
        catch { tcp.Dispose(); throw; }
    }

    public void Stop() => _listener?.Stop();
    public void Dispose() => Stop();
}
