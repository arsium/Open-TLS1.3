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

    /// <summary>Handshake timeout in milliseconds. 0 = no timeout.</summary>
    public int HandshakeTimeoutMs { get; set; } = 10000;

    /// <summary>Ticket encryption instance. Set to enable session ticket issuance for PSK resumption.</summary>
    public TicketEncryption? TicketEncryption { get; set; }

    /// <summary>Whether to accept 0-RTT early data from resuming clients.</summary>
    public bool Accept0Rtt { get; set; }

    /// <summary>Maximum early data size in bytes (default 16384).</summary>
    public uint MaxEarlyDataSize { get; set; } = 16384;

    /// <summary>How many NewSessionTickets to send unsolicited after each handshake (RFC 8446 §4.6.1)
    /// when the client signals resumption support. Only effective when <see cref="TicketEncryption"/>
    /// is set. Default 2; set 0 to issue tickets only when a client explicitly requests them.</summary>
    public int DefaultNewSessionTicketCount { get; set; } = 2;

    /// <summary>ALPN protocols the server accepts, in preference order.</summary>
    public string[]? AlpnProtocols { get; set; }

    /// <summary>Restrict which cipher suites the server will select — an allow-list, intersected with the
    /// client's offer in the server's preference order. Null = accept any suite the stack supports (default).
    /// Use this to refuse, e.g., the AEGIS (draft) or the GOST/SM national suites.</summary>
    public CipherSuite[]? AllowedCipherSuites { get; set; }

    /// <summary>Restrict which key-exchange groups the server will select — an allow-list. Null = accept any
    /// supported group the client offers (default). Use this to require — or forbid — the hybrid PQ groups.</summary>
    public NamedGroup[]? AllowedGroups { get; set; }

    /// <summary>mTLS: override the signature schemes advertised in CertificateRequest — what the server accepts
    /// for the client's CertificateVerify. Null = stack default.</summary>
    public SignatureScheme[]? AcceptedClientSignatureSchemes { get; set; }

    /// <summary>Enable certificate compression (RFC 8879, brotli).</summary>
    public bool UseCertificateCompression { get; set; }

    /// <summary>Record padding block size for traffic analysis resistance. 0 = no padding (default).</summary>
    public int PaddingBlockSize { get; set; }

    /// <summary>DER-encoded OCSP response to staple in the Certificate message when the client requests it.</summary>
    public byte[]? OcspResponse { get; set; }

    /// <summary>Encrypted Client Hello: the X25519 private key (32 bytes) matching the published
    /// ECHConfig's public_key. Set together with <see cref="EchConfigList"/> to accept ECH.</summary>
    public byte[]? EchPrivateKey { get; set; }

    /// <summary>Encrypted Client Hello: the ECHConfigList (wire bytes) this server publishes — its
    /// public_key must correspond to <see cref="EchPrivateKey"/>.</summary>
    public byte[]? EchConfigList { get; set; }

    /// <summary>Enforce RFC 8446 §4.1.4: the client's second ClientHello (after a HelloRetryRequest)
    /// must be identical to the first except for the permitted changes (key_share, early_data, cookie,
    /// pre_shared_key, padding). A mismatch aborts the handshake with <c>illegal_parameter</c>. Default
    /// <c>true</c> (recommended); set <c>false</c> only to interoperate with a non-conformant client
    /// that mutates other ClientHello fields across the retry.</summary>
    public bool EnforceHelloRetryConsistency { get; set; } = true;

    /// <summary>Testing: force a single HelloRetryRequest on every connection (exercises the HRR path,
    /// including the ECH HRR accept-confirmation, in a loopback where it otherwise never triggers).</summary>
    internal bool ForceHelloRetryRequest { get; set; }

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

    /// <summary>The local port the listener is bound to (set after <see cref="Listen"/>).
    /// Use this after binding to port 0 to read back the OS-assigned port.</summary>
    public int? LocalPort => (_listener?.LocalEndpoint as IPEndPoint)?.Port;

    /// <summary>Accept one TCP connection, perform the TLS handshake, return an encrypted stream.</summary>
    public TlsStream Accept()
    {
        if (_listener == null)
            throw new InvalidOperationException("Call Listen() first");

        var tcp = _listener.AcceptTcpClient();
        tcp.NoDelay = true;
        try
        {
            var stream = tcp.GetStream();
            int origTimeout = stream.ReadTimeout;
            if (HandshakeTimeoutMs > 0) stream.ReadTimeout = HandshakeTimeoutMs;

            var conn = new TlsConnection(stream, isServer: true, _certificate,
                requireClientCert: RequireClientCertificate, caCertificate: CaCertificate);

            if (TicketEncryption != null)
                conn.EnableServerTickets(TicketEncryption, Accept0Rtt, MaxEarlyDataSize, DefaultNewSessionTicketCount);
            if (AlpnProtocols != null)
                conn.SetAlpnProtocols(AlpnProtocols);
            if (UseCertificateCompression)
                conn.EnableCertificateCompression();
            if (PaddingBlockSize > 0)
                conn.PaddingBlockSize = PaddingBlockSize;
            if (OcspResponse != null)
                conn.SetOcspResponse(OcspResponse);
            if (EchPrivateKey != null && EchConfigList != null)
            {
                conn.SetEchPrivateKey(EchPrivateKey);
                conn.SetEchConfigs(EncryptedClientHello.ParseEchConfigList(EchConfigList));
            }
            if (AllowedCipherSuites != null)
                conn.SetAllowedCipherSuites(AllowedCipherSuites);
            if (AllowedGroups != null)
                conn.SetAllowedGroups(AllowedGroups);
            if (AcceptedClientSignatureSchemes != null)
                conn.SetOfferedSignatureSchemes(AcceptedClientSignatureSchemes);
            conn.SetEnforceHelloRetryConsistency(EnforceHelloRetryConsistency);
            if (ForceHelloRetryRequest)
                conn.ForceHelloRetryRequest();

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
        tcp.NoDelay = true;
        try
        {
            var stream = tcp.GetStream();
            int origTimeout = stream.ReadTimeout;
            if (HandshakeTimeoutMs > 0) stream.ReadTimeout = HandshakeTimeoutMs;

            var conn = new TlsConnection(stream, isServer: true, _certificate,
                requireClientCert: RequireClientCertificate, caCertificate: CaCertificate);

            if (TicketEncryption != null)
                conn.EnableServerTickets(TicketEncryption, Accept0Rtt, MaxEarlyDataSize, DefaultNewSessionTicketCount);
            if (AlpnProtocols != null)
                conn.SetAlpnProtocols(AlpnProtocols);
            if (UseCertificateCompression)
                conn.EnableCertificateCompression();
            if (PaddingBlockSize > 0)
                conn.PaddingBlockSize = PaddingBlockSize;
            if (OcspResponse != null)
                conn.SetOcspResponse(OcspResponse);
            if (EchPrivateKey != null && EchConfigList != null)
            {
                conn.SetEchPrivateKey(EchPrivateKey);
                conn.SetEchConfigs(EncryptedClientHello.ParseEchConfigList(EchConfigList));
            }
            if (AllowedCipherSuites != null)
                conn.SetAllowedCipherSuites(AllowedCipherSuites);
            if (AllowedGroups != null)
                conn.SetAllowedGroups(AllowedGroups);
            if (AcceptedClientSignatureSchemes != null)
                conn.SetOfferedSignatureSchemes(AcceptedClientSignatureSchemes);
            conn.SetEnforceHelloRetryConsistency(EnforceHelloRetryConsistency);
            if (ForceHelloRetryRequest)
                conn.ForceHelloRetryRequest();

            await conn.HandshakeAsServerAsync(ct).ConfigureAwait(false);

            if (HandshakeTimeoutMs > 0) stream.ReadTimeout = origTimeout;
            return new TlsStream(conn, tcp);
        }
        catch { tcp.Dispose(); throw; }
    }

    public void Stop() => _listener?.Stop();
    public void Dispose() => Stop();
}
