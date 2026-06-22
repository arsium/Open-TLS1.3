namespace TLS;

using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

/// <summary>
/// Core TLS 1.3 connection — performs the full handshake (client or server)
/// and provides encrypted Read/Write for application data.
/// Supports X25519, X448, P-256, P-384, X25519+ML-KEM-768 key exchange,
/// HelloRetryRequest, Ed25519/ECDSA/RSA-PSS signatures,
/// ALPN, certificate compression (RFC 8879), record padding,
/// certificate chains, RSA certificate verification, KeyUpdate,
/// PSK/session resumption, 0-RTT early data, post-handshake client auth,
/// exporter interface, SSLKEYLOGFILE, and proper close_notify / alert handling.
/// </summary>
/// <summary>
/// Diagnostic phase hook fired at well-known points during the handshake. Set <see cref="Hook"/>
/// to a non-null delegate to capture phase markers (e.g. for allocation profiling).
/// Cost when null: a single null-check + indirect invoke skip; safe to leave wired in release.
/// Cost when non-null: one delegate invocation per mark. Both client and server fire to the same
/// hook — they may interleave when the handshake runs in-process.
/// </summary>
public static class HandshakePhaseHook
{
    public static Action<string>? Hook;
    internal static void Mark(string phase) => Hook?.Invoke(phase);
}

public sealed class TlsConnection : IDisposable
{
    private readonly RecordLayer _record;
    private readonly bool _isServer;
    private readonly TlsCertificate? _certificate;
    private readonly bool _requireClientCert;
    private readonly TlsCertificate? _caCertificate;
    private readonly TranscriptHash _transcript;
    private KeySchedule? _keySchedule;

    // Handshake message buffer (a single record can carry multiple messages)
    private readonly Queue<byte[]> _hsBuffer = new();
    // Bytes of a handshake message that arrived split across record boundaries (RFC 8446 §5.1);
    // held until the remainder arrives in a later record.
    private byte[] _hsPartial = Array.Empty<byte>();
    // Upper bound on a single reassembled handshake message — guards against an unbounded
    // buffering DoS from a peer streaming records that claim an enormous message length.
    private const int MaxHandshakeMessageLength = 1 << 20; // 1 MiB

    // Application-data read buffer
    private byte[] _readBuf = Array.Empty<byte>();
    private int _readOff;

    // State flags
    private bool _sentCcs;
    private bool _closed;

    // Write-side thread safety (protects all record writes post-handshake)
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    public bool IsHandshakeComplete { get; private set; }

    /// <summary>DER-encoded peer certificate (server cert on client side, client cert on server side).</summary>
    public byte[]? PeerCertificateData { get; private set; }

    /// <summary>Warnings from optional X.509 validation (expiration, hostname mismatch). Empty = no warnings.</summary>
    public List<string> CertificateWarnings { get; } = new();

    /// <summary>True if the connection was resumed via PSK.</summary>
    public bool IsResumed { get; private set; }

    /// <summary>True if this connection authenticated with a certificate AND mixed an external PSK
    /// into the key schedule (draft-ietf-tls-8773bis, Internet-Draft). Distinct from <see cref="IsResumed"/>:
    /// a full certificate handshake ran; the PSK only hardened the key schedule.</summary>
    public bool UsedCertWithExternalPsk { get; private set; }

    /// <summary>The key-exchange group negotiated for this connection (e.g. X25519MLKEM768, X25519),
    /// reflecting any HelloRetryRequest. Valid once the handshake has completed.</summary>
    public NamedGroup NegotiatedGroup => _negotiatedGroup;

    /// <summary>The cipher suite negotiated for this connection. Valid once the handshake has completed.</summary>
    public CipherSuite NegotiatedCipherSuite => _keySchedule?.Suite ?? default;

    /// <summary>True if 0-RTT early data was accepted by the server.</summary>
    public bool EarlyDataAccepted { get; private set; }

    /// <summary>Early data received by the server (0-RTT), or null.</summary>
    public byte[]? ReceivedEarlyData { get; private set; }

    // Signature schemes we advertise and accept
    private static readonly SignatureScheme[] AdvertisedSigAlgs =
    {
        SignatureScheme.EcdsaSecp256r1Sha256,
        // EcdsaSecp384r1Sha384 (0x0503) is intentionally NOT advertised: this stack's ECDSA verify/sign is
        // P-256-only, and RFC 8446 §4.2.3 requires being able to process any scheme you offer — advertising
        // P-384 made a handshake with a P-384 peer fail mid-flight. Re-add here once P-384 verify/sign exists.
        SignatureScheme.Ed25519,
        SignatureScheme.RsaPssRsaeSha256,
        SignatureScheme.RsaPssRsaeSha384,
        // FIPS 204 ML-DSA post-quantum signatures (draft-ietf-tls-mldsa)
        SignatureScheme.MlDsa44,
        SignatureScheme.MlDsa65,
        SignatureScheme.MlDsa87,
        // RFC 9367 GOST R 34.10-2012 signature schemes
        SignatureScheme.Gostr34102012_256a,
        SignatureScheme.Gostr34102012_256b,
        SignatureScheme.Gostr34102012_256c,
        SignatureScheme.Gostr34102012_256d,
        SignatureScheme.Gostr34102012_512a,
        SignatureScheme.Gostr34102012_512b,
        SignatureScheme.Gostr34102012_512c,
        // RFC 8998 SM2 signature scheme
        SignatureScheme.Sm2Sm3
    };

    // Supported named groups in preference order
    private static readonly NamedGroup[] ServerGroupPreference =
    {
        NamedGroup.X25519MLKEM768,
        NamedGroup.SecP256r1MLKEM768,
        NamedGroup.SecP384r1MLKEM1024,
        NamedGroup.X25519,
        NamedGroup.X448,
        NamedGroup.Secp256r1,
        NamedGroup.Secp384r1,
        // RFC 9367 GOST curves (lower preference; selected when a client offers only these)
        NamedGroup.GC256A,
        NamedGroup.GC256B,
        NamedGroup.GC256C,
        NamedGroup.GC256D,
        NamedGroup.GC512A,
        NamedGroup.GC512B,
        NamedGroup.GC512C,
        // RFC 8998 Chinese SM2 curve
        NamedGroup.Curvesm2
    };

    // ALPN
    private string[]? _alpnProtocols;      // offered protocols (client) or accepted protocols (server)
    private CipherSuite[]? _offeredSuites;  // client: override the default offered cipher suite list
    private NamedGroup[]? _offeredGroups;   // client: override the default offered key-share groups
    private SignatureScheme[]? _offeredSigAlgs; // override advertised signature_algorithms (CH / CertificateRequest)
    private CipherSuite[]? _allowedSuites;  // server: allow-list restricting which offered suites may be selected
    private NamedGroup[]? _allowedGroups;   // server: allow-list restricting which offered groups may be selected
    private NamedGroup _negotiatedGroup;    // the key-exchange group selected for this connection
    private byte[]? _gostKexPriv;           // client: ephemeral GOST ECDH private key (if a GOST group offered)
    private string? _gostKexCurveOid;       // client: curve OID for _gostKexPriv
    private byte[]? _sm2KexPriv;            // client: ephemeral SM2 ECDH private key (if curveSM2 offered)
    private byte[] _mlkemDkSecp256 = Array.Empty<byte>(); // client: ML-KEM-768 decaps key for SecP256r1MLKEM768
    private byte[] _mlkemDkSecp384 = Array.Empty<byte>(); // client: ML-KEM-1024 decaps key for SecP384r1MLKEM1024
    private string? _negotiatedAlpn;       // result of negotiation

    /// <summary>Negotiated ALPN protocol, or null if ALPN was not used.</summary>
    public string? NegotiatedAlpn => _negotiatedAlpn;

    // Certificate compression
    private bool _useCertCompression;      // server: use compressed cert if client supports
    private ushort _peerCertCompAlgorithm; // negotiated algorithm (0 = none)

    // Record padding
    private int _paddingBlockSize;

    /// <summary>Record padding block size for traffic analysis resistance. 0 = no padding.</summary>
    public int PaddingBlockSize
    {
        get => _paddingBlockSize;
        set { _paddingBlockSize = value; _record.PaddingBlockSize = value; }
    }

    // Key logging
    private byte[]? _clientRandom; // saved for SSLKEYLOGFILE

    // PSK / Resumption
    private SessionTicket? _pskTicket;       // client: ticket to offer
    private ExternalPsk? _externalPsk;       // RFC 9258: external PSK for import
    private bool _certWithExternPsk;         // client: cert + external PSK mode (draft-ietf-tls-8773bis)
    private byte[]? _earlyData;              // client: data to send as 0-RTT
    private TicketEncryption? _ticketEncryption; // server: ticket sealing key
    private bool _enableTickets;
    private bool _accept0Rtt;
    private uint _maxEarlyDataSize;
    private ushort _ticketRequestCount;      // RFC 9149: client-requested ticket count
    private int _defaultTicketCount = 2;     // NSTs to issue unsolicited (RFC 8446 §4.6.1) when client supports resumption

    // Post-handshake auth
    private PostHsAuthState _postHsAuthState = PostHsAuthState.None;
    private byte[]? _pendingPostHsContext;
    private bool _offerPostHandshakeAuth;                    // client: advertise post_handshake_auth
    private bool _peerAllowsPostHandshakeAuth;                // server: client advertised post_handshake_auth
    private byte[]? _serverFinishedHash; // Transcript-Hash(CH..SF), used for DeriveAppSecrets

    // OCSP stapling
    private bool _requestOcspStapling;  // client: request status_request extension
    private byte[]? _ocspResponse;      // server: OCSP response to staple

    // RFC 8879 mTLS client-cert compression
    private ushort[]? _serverCertReqCompAlgs;  // client: compress_certificate algs advertised in CertificateRequest
    private static readonly ushort[] CertCompAdvertise = { 0x0002, 0x0003, 0x0001 }; // brotli, zstd, zlib

    // ECH (Encrypted Client Hello)
    private EncryptedClientHello.EchConfig[]? _echConfigs;    // client: ECH configurations
    private byte[]? _echPrivateKey;                           // server: ECH decryption key
    private EncryptedClientHello.EchClientContext? _echContext; // client: ECH encryption context
    private byte[]? _echTranscriptOverride;                   // client: inner CH to transcript (ECH accept path)
    private byte[]? _echInnerChMsg;                           // server: reconstructed inner CH (for accept-confirmation)
    private byte[]? _echInnerRandom;                          // both: ClientHelloInner.random
    private byte[]? _echOuterChMsg;                           // client: the outer CH sent (transcript on ECH reject)
    private bool _greaseEch;                                  // client: send a GREASE ECH ext when no real config
    private bool _echServerRejected;                          // server: saw an outer CH it couldn't decrypt → send retry_configs
    private bool _forceHrr;                                   // server (test): always send one HelloRetryRequest
    private bool _enforceHrrConsistency = true;               // server: RFC 8446 §4.1.4 CH1↔CH2 invariant check (default on)
    private byte[]? _echRetryConfigs;                         // client: ECHConfigList from a rejecting server (retry_configs)
    /// <summary>True once ECH was confirmed accepted (server: decrypted; client: confirmation verified).</summary>
    public bool EchAccepted { get; private set; }

    public TlsConnection(Stream stream, bool isServer, TlsCertificate? certificate = null,
        bool requireClientCert = false, TlsCertificate? caCertificate = null)
    {
        _record = new RecordLayer(stream);
        _isServer = isServer;
        _certificate = certificate;
        _requireClientCert = requireClientCert;
        _caCertificate = caCertificate;
        _transcript = new TranscriptHash(HashAlgorithmName.SHA256);
    }

    /// <summary>Configure PSK resumption for client (ticket to offer).</summary>
    public void SetClientTicket(SessionTicket ticket) => _pskTicket = ticket;

    /// <summary>Import external PSK for client/server use (RFC 9258).</summary>
    public void ImportExternalPsk(ExternalPsk psk) => _externalPsk = psk;

    /// <summary>Client: combine an external PSK with certificate authentication
    /// (draft-ietf-tls-8773bis, Internet-Draft). A full certificate handshake runs, but the external
    /// PSK is also mixed into the key schedule, so the session stays confidential even if the
    /// certificate's signature algorithm is later broken. Must be set before the handshake; not
    /// compatible with 0-RTT.</summary>
    public void EnableCertWithExternalPsk(ExternalPsk psk)
    {
        _externalPsk = psk;
        _certWithExternPsk = true;
    }

    /// <summary>Set early data to send as 0-RTT (client only). Must be called before handshake.</summary>
    public void SetEarlyData(byte[] data) => _earlyData = data;

    /// <summary>Configure server ticket issuance. <paramref name="defaultTicketCount"/> is how many
    /// NewSessionTickets to send unsolicited (RFC 8446 §4.6.1) when the client signals resumption
    /// support via psk_key_exchange_modes; 0 disables unsolicited issuance (the server then only
    /// issues tickets when the client explicitly asks via RFC 9149 ticket_request).</summary>
    public void EnableServerTickets(TicketEncryption encryption, bool accept0Rtt = false,
        uint maxEarlyDataSize = 16384, int defaultTicketCount = 2)
    {
        _ticketEncryption = encryption;
        _enableTickets = true;
        _accept0Rtt = accept0Rtt;
        _maxEarlyDataSize = maxEarlyDataSize;
        _defaultTicketCount = defaultTicketCount;
    }

    /// <summary>How many NewSessionTickets to send after this handshake. Honors an explicit RFC 9149
    /// ticket_request count if present, else the server default — but only when ticket issuance is
    /// enabled AND the client advertised psk_dhe_ke (RFC 8446 §4.2.9), since a client that can't do
    /// PSK-with-(EC)DHE resumption has no use for a ticket. Capped to bound a malicious request.</summary>
    private int EffectiveTicketCount(ParsedClientHello ch)
    {
        if (!_enableTickets || !ch.OffersPskDheKe) return 0;
        int count = ch.TicketRequestCount > 0 ? ch.TicketRequestCount : _defaultTicketCount;
        return Math.Min(count, 10);
    }

    /// <summary>Set ALPN protocols to offer (client) or accept (server).</summary>
    public void SetAlpnProtocols(string[] protocols) => _alpnProtocols = protocols;

    /// <summary>Client: advertise RFC 8446 post_handshake_auth and accept post-handshake CertificateRequest.</summary>
    public void EnablePostHandshakeAuth() => _offerPostHandshakeAuth = true;

    /// <summary>Client: override the cipher suites offered in ClientHello (in preference order).</summary>
    public void SetOfferedCipherSuites(CipherSuite[] suites) => _offeredSuites = suites;

    /// <summary>Client: override the key-share groups offered in ClientHello (in preference order).</summary>
    public void SetOfferedGroups(NamedGroup[] groups) => _offeredGroups = groups;

    /// <summary>Override the signature schemes this endpoint accepts from its peer — advertised in the
    /// ClientHello signature_algorithms (client) and in CertificateRequest (server, mTLS), and enforced
    /// against the peer's CertificateVerify. Null = stack default. Use this to, e.g., drop the ML-DSA
    /// (draft-ietf-tls-mldsa) schemes from the advertisement.</summary>
    public void SetOfferedSignatureSchemes(SignatureScheme[] schemes) => _offeredSigAlgs = schemes;

    /// <summary>Server: restrict which cipher suites may be selected, even if the client offers others the
    /// stack supports (an allow-list, intersected with the client's offer in the server's preference order).
    /// Null = accept any supported suite (default). Use this to refuse, e.g., the AEGIS (draft) or the
    /// GOST/SM national suites.</summary>
    public void SetAllowedCipherSuites(CipherSuite[] suites) => _allowedSuites = suites;

    /// <summary>Server: restrict which key-exchange groups may be selected (an allow-list). Null = accept any
    /// supported group the client offers (default). Use this to require — or forbid — the hybrid PQ groups.</summary>
    public void SetAllowedGroups(NamedGroup[] groups) => _allowedGroups = groups;

    // Client-side server-certificate trust (RFC 8446 leaves trust policy to the application).
    // Permissive by default; enforced only when one of these is configured via TlsClient.
    private TlsCertificate? _serverCaCertificate;
    private Func<byte[], IReadOnlyList<string>, bool>? _serverCertValidator;

    /// <summary>Client: configure server-certificate trust enforcement. When <paramref name="ca"/> is
    /// non-null the server certificate is verified (signed by the trust anchor, in its validity window,
    /// and — when a host was supplied — matching a SAN) and the handshake fails closed otherwise. When
    /// <paramref name="validator"/> is non-null it is authoritative (receives the leaf DER + advisory
    /// warnings). With neither set the client does NOT authenticate the server. Server/mTLS uses the
    /// constructor's caCertificate instead.</summary>
    public void SetServerCertificateValidation(TlsCertificate? ca, Func<byte[], IReadOnlyList<string>, bool>? validator)
    {
        _serverCaCertificate = ca;
        _serverCertValidator = validator;
    }

    // Build the ClientHello key_share list, honoring an optional offered-groups override.
    // GOST groups generate a fresh ephemeral (stored for the later shared-secret computation).
    private (NamedGroup, byte[])[] BuildClientKeyShares(
        byte[] hybridPub, byte[] x25519Pub, byte[] x448Pub, byte[] p256Pub, byte[] p384Pub,
        byte[] secp256HybridPub, byte[] secp384HybridPub)
    {
        var offered = _offeredGroups ?? new[]
        {
            NamedGroup.X25519MLKEM768, NamedGroup.X25519, NamedGroup.X448,
            NamedGroup.Secp256r1, NamedGroup.Secp384r1
        };
        var list = new List<(NamedGroup, byte[])>();
        foreach (var g in offered)
        {
            switch (g)
            {
                case NamedGroup.X25519MLKEM768: list.Add((g, hybridPub)); break;
                case NamedGroup.SecP256r1MLKEM768: list.Add((g, secp256HybridPub)); break;
                case NamedGroup.SecP384r1MLKEM1024: list.Add((g, secp384HybridPub)); break;
                case NamedGroup.X25519: list.Add((g, x25519Pub)); break;
                case NamedGroup.X448: list.Add((g, x448Pub)); break;
                case NamedGroup.Secp256r1: list.Add((g, p256Pub)); break;
                case NamedGroup.Secp384r1: list.Add((g, p384Pub)); break;
                case NamedGroup.Curvesm2:
                {
                    var (priv, pub) = ChineseCrypto.SM2.EcdhGenerateKeyPair();
                    _sm2KexPriv = priv;
                    list.Add((g, pub));
                    break;
                }
                default:
                    string? oid = GostGroupCurveOid(g);
                    if (oid != null)
                    {
                        var (priv, pub) = GostEcdh.GenerateKeyPair(oid);
                        _gostKexPriv = priv;
                        _gostKexCurveOid = oid;
                        list.Add((g, pub));
                    }
                    break;
            }
        }
        return list.ToArray();
    }

    // RFC 8446 §4.1.3: abort if ServerHello.random carries a version-downgrade sentinel.
    private static readonly byte[] DowngradeSentinel12 = { 0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01 };
    private static readonly byte[] DowngradeSentinel11 = { 0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00 };
    private void CheckDowngradeSentinel(byte[] serverRandom)
    {
        if (serverRandom.Length < 8) return;
        var tail = serverRandom.AsSpan(serverRandom.Length - 8);
        if (CryptographicOperations.FixedTimeEquals(tail, DowngradeSentinel12) ||
            CryptographicOperations.FixedTimeEquals(tail, DowngradeSentinel11))
            AlertAndThrow(AlertDescription.IllegalParameter,
                "TLS version-downgrade sentinel detected (RFC 8446 §4.1.3)");
    }

    // RFC 8446 §4.1.3: the server MUST echo the client's legacy_session_id in ServerHello/HRR;
    // a mismatch is fatal (also catches a server that ignored middlebox-compat session_id).
    private void CheckSessionIdEcho(byte[] sent, byte[] echoed)
    {
        if (!sent.AsSpan().SequenceEqual(echoed))
            AlertAndThrow(AlertDescription.IllegalParameter,
                "ServerHello legacy_session_id_echo does not match the ClientHello session_id");
    }

    private void ValidateServerCipherSuiteOffered(CipherSuite suite, CipherSuite[] offeredSuites)
    {
        if (Array.IndexOf(offeredSuites, suite) < 0)
            AlertAndThrow(AlertDescription.IllegalParameter,
                $"Server selected a cipher suite the client did not offer: {suite}");
    }

    private void ValidateServerPskSelection(ParsedServerHello sh, byte[]? offeredPsk, bool offeredCertWithExternPsk, CipherSuite? offeredPskSuite)
    {
        if (sh.CertWithExternPsk && !offeredCertWithExternPsk)
            AlertAndThrow(AlertDescription.IllegalParameter,
                "Server selected tls_cert_with_extern_psk without a matching client offer");

        if (sh.CertWithExternPsk && sh.SelectedPskIndex < 0)
            AlertAndThrow(AlertDescription.MissingExtension,
                "Server selected tls_cert_with_extern_psk without selecting a PSK identity");

        if (sh.SelectedPskIndex < 0) return;

        if (offeredPsk == null)
            AlertAndThrow(AlertDescription.IllegalParameter,
                "Server selected a PSK identity the client did not offer");

        if (sh.SelectedPskIndex != 0)
            AlertAndThrow(AlertDescription.IllegalParameter,
                $"Server selected PSK identity {sh.SelectedPskIndex}, but this client offered only identity 0");

        if (offeredPskSuite.HasValue && sh.CipherSuite != offeredPskSuite.Value)
            AlertAndThrow(AlertDescription.IllegalParameter,
                "Server selected a cipher suite incompatible with the offered PSK");
    }

    private void ValidateCertificateContext(byte[] actual, byte[] expected, string message)
    {
        if (!CryptographicOperations.FixedTimeEquals(actual, expected))
            AlertAndThrow(AlertDescription.IllegalParameter, message);
    }

    private void ValidateClientCertificateSignatureScheme(SignatureScheme[] allowed, SignatureScheme scheme)
    {
        if (Array.IndexOf(allowed, scheme) < 0)
            AlertAndThrow(AlertDescription.HandshakeFailure,
                $"Client certificate signature scheme was not allowed by CertificateRequest: {scheme}");
    }

    // RFC 8449: clamp our outgoing record size to the peer's advertised record_size_limit.
    private void ApplyPeerRecordSizeLimit(ushort limit)
    {
        if (limit == 0) return; // not negotiated
        if (limit < 64)
            AlertAndThrow(AlertDescription.IllegalParameter, "record_size_limit below 64");
        _record.MaxSendPlaintext = Math.Min(TlsConst.MaxPlaintextLength, limit - 1);
    }

    /// <summary>Curve OID for a RFC 9367 GOST named group, or null if not a GOST group.</summary>
    internal static string? GostGroupCurveOid(NamedGroup g) => g switch
    {
        NamedGroup.GC256A => "1.2.643.7.1.2.1.1.1",
        NamedGroup.GC256B => "1.2.643.2.2.35.1",
        NamedGroup.GC256C => "1.2.643.2.2.35.2",
        NamedGroup.GC256D => "1.2.643.2.2.35.3",
        NamedGroup.GC512A => "1.2.643.7.1.2.1.2.1",
        NamedGroup.GC512B => "1.2.643.7.1.2.1.2.2",
        NamedGroup.GC512C => "1.2.643.7.1.2.1.2.3",
        _ => null
    };

    /// <summary>Enable certificate compression (server-side, uses brotli).</summary>
    public void EnableCertificateCompression() => _useCertCompression = true;

    /// <summary>Request OCSP stapling from the server (client-side). Must be called before handshake.</summary>
    public void RequestOcspStapling() => _requestOcspStapling = true;

    /// <summary>Set the OCSP response to staple in the Certificate message (server-side).</summary>
    public void SetOcspResponse(byte[] response) => _ocspResponse = response;

    /// <summary>OCSP response received from the server's Certificate message (client-side, null if not stapled).</summary>
    public byte[]? PeerOcspResponse { get; private set; }

    // ================================================================
    //  ECH Configuration API (RFC 9849)
    // ================================================================

    /// <summary>Configure ECH for client (set ECHConfigList from server).</summary>
    public void SetEchConfigs(EncryptedClientHello.EchConfig[] configs) => _echConfigs = configs;

    /// <summary>Client: send a GREASE ECH extension (draft §6.2) when no real ECHConfig is set, so the
    /// presence of ECH isn't a fingerprint. No effect when a real config is configured.</summary>
    public void SetGreaseEch() => _greaseEch = true;

    /// <summary>Client: ECHConfigList the server returned in retry_configs after rejecting our ECH
    /// (draft §7.1), or null. The application should reconnect with these. Populated even though the
    /// current connection aborts on reject.</summary>
    public byte[]? EchRetryConfigs => _echRetryConfigs;

    /// <summary>Configure ECH for server (set private key for ECH decryption).</summary>
    public void SetEchPrivateKey(byte[] privateKey)
    {
        if (privateKey.Length != 32) throw new ArgumentException("ECH private key must be 32 bytes (X25519)");
        _echPrivateKey = privateKey;
    }

    /// <summary>True if ECH was used (attempted) in this connection.</summary>
    public bool IsEchConnection => _echContext != null;

    // ECH §7.2 accept-confirmation: 8 bytes placed in ServerHello.random[24..32], binding the server's
    // acceptance to the ClientHelloInner. <paramref name="shMsgZeroed"/> is the framed ServerHello with
    // those 8 bytes set to zero. Server emits it; client recomputes and compares.
    private static byte[] ComputeEchAcceptConfirmation(byte[] innerChMsg, byte[] msgZeroed,
        byte[] innerRandom, HashAlgorithmName hash, int hashLen, string label = "ech accept confirmation")
    {
        var th = new TranscriptHash(hash);
        th.Update(innerChMsg);
        th.Update(msgZeroed);
        byte[] confHash = th.GetHash();
        byte[] secret = Hkdf.Extract(hash, new byte[hashLen], innerRandom); // salt=zeros, ikm=ClientHelloInner.random
        return Hkdf.ExpandLabel(hash, secret, label, confHash, 8);
    }

    private static (HashAlgorithmName hash, int len) EchSuiteHash(CipherSuite s) =>
        s == CipherSuite.TLS_AES_256_GCM_SHA384 ? (HashAlgorithmName.SHA384, 48) : (HashAlgorithmName.SHA256, 32);

    // Server: overwrite ServerHello.random[24..32] (offset 30..38 in the framed message) with the
    // ECH accept-confirmation, when ECH was accepted. No-op otherwise. RFC 9849 §7.2 requires the
    // confirmation be taken over the transcript "up to and including the modified ServerHello" — for
    // an HRR exchange that is message_hash(CH1inner) ‖ HRR ‖ CH2inner ‖ SH(zeroed), not a standalone
    // ClientHelloInner ‖ SH. The running _transcript already holds exactly that prefix (it is the
    // committed inner CH on a normal flow, and the message_hash/HRR/CH2 rewrite after a retry), so we
    // clone it and append the zeroed ServerHello rather than re-deriving from a single inner CH.
    private void PatchEchAcceptConfirmation(byte[] shMsg)
    {
        if (!EchAccepted || _echInnerRandom == null) return;
        byte[] shZeroed = (byte[])shMsg.Clone();
        Array.Clear(shZeroed, 30, 8);
        byte[] conf = ComputeEchConfFromTranscript(_transcript, shZeroed, _echInnerRandom);
        Buffer.BlockCopy(conf, 0, shMsg, 30, 8);
    }

    // RFC 9849 §7.2 accept_confirmation over the running handshake transcript: clone the transcript
    // (so the live one is untouched), append the zeroed ServerHello, and key the HKDF off
    // ClientHelloInner.random. Used on both sides for the ServerHello confirmation so the HRR and
    // non-HRR cases fall out from whatever the transcript already contains.
    private byte[] ComputeEchConfFromTranscript(TranscriptHash baseTranscript, byte[] shMsgZeroed, byte[] innerRandom)
    {
        var th = baseTranscript.Clone();
        th.Update(shMsgZeroed);
        byte[] confHash = th.GetHash();
        var hash = _keySchedule!.HashAlgorithm;
        byte[] secret = Hkdf.Extract(hash, new byte[_keySchedule.HashLen], innerRandom);
        return Hkdf.ExpandLabel(hash, secret, "ech accept confirmation", confHash, 8);
    }

    // Server: patch the HRR accept-confirmation (draft §7.2.1) into the HRR's tail-8 bytes. No-op
    // unless ECH was accepted. The confirmation is over ClientHelloInner1 ‖ HRR(tail-8 zeroed).
    private void PatchEchHrrConfirmation(byte[] hrrMsg)
    {
        if (!EchAccepted || _echInnerChMsg == null || _echInnerRandom == null) return;
        byte[] conf = ComputeEchAcceptConfirmation(_echInnerChMsg, hrrMsg, _echInnerRandom,
            _keySchedule!.HashAlgorithm, _keySchedule.HashLen, "hrr ech accept confirmation");
        Buffer.BlockCopy(conf, 0, hrrMsg, hrrMsg.Length - 8, 8);
    }

    // Client: verify the HRR accept-confirmation (tail-8 of the HRR) and commit the deferred CH1
    // transcript (inner on accept, outer on reject). No-op unless we attempted ECH.
    private void VerifyEchHrrAndCommit(byte[] hrrMsg, ParsedServerHello sh)
    {
        if (_echContext == null) return;
        byte[] hrrZeroed = (byte[])hrrMsg.Clone();
        Array.Clear(hrrZeroed, hrrZeroed.Length - 8, 8);
        var (hash, hashLen) = EchSuiteHash(sh.CipherSuite);
        byte[] expected = ComputeEchAcceptConfirmation(_echContext.InnerChMsg, hrrZeroed,
            _echContext.InnerRandom, hash, hashLen, "hrr ech accept confirmation");
        EchAccepted = CryptographicOperations.FixedTimeEquals(expected, hrrMsg.AsSpan(hrrMsg.Length - 8, 8));
        _transcript.Update(EchAccepted ? _echContext.InnerChMsg : _echOuterChMsg!);
    }

    // Client: rebuild CH2 as ECH after an HRR — inner2 reuses ClientHelloInner1's random; returns the
    // outer CH2 to send and the inner CH2 to transcript (inner on accept, outer on reject).
    private (byte[] outer, byte[] transcript) BuildEchClientHello2(byte[] clientRandom, byte[] sessionId,
        CipherSuite[] suites, (NamedGroup, byte[])[] keyShares, string? serverName, byte[]? cookie)
    {
        byte[] inner2 = HandshakeMessages.BuildClientHello(_echInnerRandom!, sessionId, suites, keyShares,
            serverName, cookie, _alpnProtocols, _requestOcspStapling, offeredSigAlgs: _offeredSigAlgs,
            offeredGroups: _offeredGroups, postHandshakeAuth: _offerPostHandshakeAuth);
        var cfg = _echConfigs![0];
        var (outer2, _) = EncryptedClientHello.EncryptClientHello(inner2, _echInnerRandom!, cfg,
            echExtBody => HandshakeMessages.BuildClientHelloInner(clientRandom, sessionId, suites, keyShares,
                cfg.PublicNameString, cookie, null, false, _alpnProtocols, _requestOcspStapling, 0, echExtBody,
                offeredSigAlgs: _offeredSigAlgs, offeredGroups: _offeredGroups, postHandshakeAuth: _offerPostHandshakeAuth));
        _echOuterChMsg = outer2;
        return (outer2, EchAccepted ? inner2 : outer2);
    }

    // Client: verify the ECH accept-confirmation. If we attempted ECH and it matches, ECH was accepted
    // (we already transcripted the inner CH). A mismatch means the server rejected ECH → abort.
    private void VerifyEchAcceptConfirmation(byte[] shMsg, ParsedServerHello sh)
    {
        if (_echContext == null || sh.IsHelloRetryRequest) return;
        byte[] shZeroed = (byte[])shMsg.Clone();
        Array.Clear(shZeroed, 30, 8);
        var (hash, hashLen) = EchSuiteHash(sh.CipherSuite);
        byte[] expected = ComputeEchAcceptConfirmation(_echContext.InnerChMsg, shZeroed,
            _echContext.InnerRandom, hash, hashLen);
        EchAccepted = CryptographicOperations.FixedTimeEquals(expected, shMsg.AsSpan(30, 8));
        // Commit the deferred ClientHello transcript: the inner on accept, the outer (public_name) on
        // reject. On reject the handshake still completes to the public_name — the application checks
        // EchAccepted + EchRetryConfigs and reconnects (draft §7.1).
        _transcript.Update(EchAccepted ? _echContext.InnerChMsg : _echOuterChMsg!);
    }

    /// <summary>Build the ClientHelloOuter for ECH and stash the inner-CH state needed for the
    /// accept-confirmation; returns null if ECH isn't configured (caller builds a normal CH).
    /// Shared by the sync and async client handshakes (it is pure CPU — no IO).</summary>
    private byte[]? TryBuildEchClientHello(byte[] clientRandom, byte[] sessionId, CipherSuite[] suites,
        (NamedGroup, byte[])[] keyShares, string? serverName)
    {
        if (_echConfigs == null || _echConfigs.Length == 0 || serverName == null) return null;
        var echConfig = _echConfigs[0];
        byte[] innerRandom = RandomnessWrapper.GetHandshakeBytes(32);
        byte[] innerCh = HandshakeMessages.BuildClientHello(innerRandom, sessionId, suites, keyShares,
            serverName, alpnProtocols: _alpnProtocols, requestOcspStapling: _requestOcspStapling,
            offeredSigAlgs: _offeredSigAlgs, offeredGroups: _offeredGroups, postHandshakeAuth: _offerPostHandshakeAuth);
        string publicName = echConfig.PublicNameString;
        var (outerCh, echContext) = EncryptedClientHello.EncryptClientHello(innerCh, innerRandom, echConfig,
            echExtBody => HandshakeMessages.BuildClientHelloInner(clientRandom, sessionId, suites, keyShares,
                publicName, null, null, false, _alpnProtocols, _requestOcspStapling, 0, echExtBody,
                offeredSigAlgs: _offeredSigAlgs, offeredGroups: _offeredGroups, postHandshakeAuth: _offerPostHandshakeAuth));
        _echContext = echContext;
        _echInnerRandom = innerRandom;
        _echTranscriptOverride = innerCh;
        _echOuterChMsg = outerCh;
        return outerCh;
    }

    /// <summary>GREASE-ECH (draft §6.2): a well-formed but meaningless outer ECH extension on an
    /// otherwise-normal ClientHello, so a non-ECH client is indistinguishable from an ECH one. We do
    /// NOT set _echContext (no acceptance is expected — the server can't decrypt random bytes and
    /// proceeds on the real SNI). Returns null unless GREASE is enabled and no real config is set.</summary>
    private byte[]? BuildGreaseEchClientHello(byte[] clientRandom, byte[] sessionId, CipherSuite[] suites,
        (NamedGroup, byte[])[] keyShares, string? serverName)
    {
        if (!_greaseEch || (_echConfigs != null && _echConfigs.Length > 0)) return null;
        byte[] enc = RandomnessWrapper.GetBytes(32);      // looks like an X25519 enc
        byte[] payload = RandomnessWrapper.GetBytes(128); // plausible sealed-CH length
        byte configId = RandomnessWrapper.GetBytes(1)[0];
        byte[] echExt = EncryptedClientHello.BuildOuterEchExtBody(configId,
            Hpke.KDF_HKDF_SHA256, Hpke.AEAD_AES_128_GCM, enc, payload);
        return HandshakeMessages.BuildClientHelloInner(clientRandom, sessionId, suites, keyShares,
            serverName, null, null, false, _alpnProtocols, _requestOcspStapling, 0, echExt,
            offeredSigAlgs: _offeredSigAlgs, offeredGroups: _offeredGroups, postHandshakeAuth: _offerPostHandshakeAuth);
    }

    /// <summary>Server: the ECHConfigList to return as retry_configs after an ECH reject (its own
    /// published configs, rebuilt from their raw bytes), or null.</summary>
    private byte[]? EchServerRetryConfigs()
    {
        if (!_echServerRejected || _echConfigs == null || _echConfigs.Length == 0) return null;
        return EncryptedClientHello.BuildEchConfigList(_echConfigs.Select(c => c.RawBytes).ToArray());
    }

    /// <summary>Server: force a single HelloRetryRequest (testing only — lets the HRR + ECH-HRR-confirmation
    /// path be exercised in a loopback where the server otherwise accepts any offered key-share group).</summary>
    internal void ForceHelloRetryRequest() => _forceHrr = true;

    /// <summary>Server: toggle the RFC 8446 §4.1.4 second-ClientHello consistency check (default on).</summary>
    internal void SetEnforceHelloRetryConsistency(bool enabled) => _enforceHrrConsistency = enabled;

    /// <summary>Server: if <paramref name="ch"/> is an ECH ClientHelloOuter we can decrypt, swap it to the
    /// inner CH and return the framed inner CH to feed the transcript; otherwise return <paramref name="chMsg"/>.
    /// Updates EchAccepted / _echInnerChMsg / _echInnerRandom / _echServerRejected. Used for CH1 and (post-HRR) CH2.</summary>
    private byte[] ServerDecryptEch(byte[] chMsg, byte[] chBody, ref ParsedClientHello ch)
    {
        if (ch.IsOuterClientHello && _echPrivateKey != null && _echConfigs != null)
        {
            byte[]? innerChMsg = EncryptedClientHello.DecryptClientHello(chBody, _echPrivateKey, _echConfigs);
            if (innerChMsg != null)
            {
                var (_, innerBody) = HandshakeMessages.Unframe(innerChMsg);
                ch = HandshakeMessages.ParseClientHello(innerBody);
                EchAccepted = true;
                _echInnerChMsg = innerChMsg;
                _echInnerRandom = ch.ClientRandom;
                return innerChMsg;
            }
            _echServerRejected = true; // couldn't decrypt → return retry_configs in EE
        }
        return chMsg;
    }

    // ================================================================
    //  Exporter Interface (RFC 8446 §7.5)
    // ================================================================

    /// <summary>Export keying material from the TLS session.</summary>
    public byte[] ExportKeyingMaterial(string label, byte[] context, int length)
    {
        if (!IsHandshakeComplete || _keySchedule?.ExporterMasterSecret == null)
            throw new InvalidOperationException("Handshake not complete");
        return _keySchedule.ExportKeyingMaterial(label, context, length);
    }

    // ================================================================
    //  TLS Channel Binding Interface (RFC 9266)
    // ================================================================

    private byte[]? _clientFinishedValue;
    private byte[]? _serverFinishedValue;

    /// <summary>Get TLS channel binding data for the specified binding type (RFC 9266).</summary>
    public byte[] GetChannelBinding(ChannelBindingType bindingType)
    {
        if (!IsHandshakeComplete)
            throw new InvalidOperationException("Handshake not complete");

        return bindingType switch
        {
            ChannelBindingType.TlsFinished => GetTlsFinishedBinding(),
            ChannelBindingType.TlsUnique => GetTlsUniqueBinding(),
            ChannelBindingType.TlsServerEndPoint => GetTlsServerEndPointBinding(),
            ChannelBindingType.TlsExporter => GetTlsExporterBinding(),
            _ => throw new ArgumentException($"Unsupported channel binding type: {bindingType}")
        };
    }

    private byte[] GetTlsFinishedBinding()
    {
        // RFC 9266 §3.1: TLS-Finished uses the verify_data from the Finished message
        // For TLS 1.3, use the peer's Finished verify_data (server's for client, client's for server)
        byte[]? peerFinished = _isServer ? _clientFinishedValue : _serverFinishedValue;
        if (peerFinished == null)
            throw new InvalidOperationException("Peer Finished message not available");
        return peerFinished;
    }

    private byte[] GetTlsUniqueBinding()
    {
        // RFC 9266 §3.2: TLS-Unique not defined for TLS 1.3, use TLS-Exporter instead
        return GetTlsExporterBinding();
    }

    private byte[] GetTlsServerEndPointBinding()
    {
        // RFC 9266 §3.3: TLS-Server-End-Point uses hash of server certificate
        if (PeerCertificateData == null)
            throw new InvalidOperationException("No peer certificate available");

        // Use SHA-256 for certificate hashing (RFC 9266 recommendation)
        return Sha2Managed.Sha256(PeerCertificateData);
    }

    private byte[] GetTlsExporterBinding()
    {
        // RFC 9266 §3.4: TLS-Exporter uses the TLS exporter with specific label
        return ExportKeyingMaterial("EXPORTER-Channel-Binding", Array.Empty<byte>(), 32);
    }

    // ================================================================
    //  External PSK Importer (RFC 9258)
    // ================================================================

    private static (HashAlgorithmName hash, int len, ushort kdfId) ExternalPskKdf(CipherSuite suite) => suite switch
    {
        CipherSuite.TLS_AES_128_GCM_SHA256 or CipherSuite.TLS_CHACHA20_POLY1305_SHA256 => (HashAlgorithmName.SHA256, 32, (ushort)1),
        CipherSuite.TLS_AES_256_GCM_SHA384 => (HashAlgorithmName.SHA384, 48, (ushort)2),
        _ => throw new ArgumentException($"Unsupported cipher suite for external PSK: {suite}")
    };

    /// <summary>RFC 9258 §3 ImportedIdentity, serialized — this is the on-wire PSK identity used for
    /// an imported external PSK and the value hashed into the derivation:
    /// opaque external_identity&lt;1..2^16-1&gt; ‖ opaque context&lt;0..2^16-1&gt; ‖
    /// uint16 target_protocol (0x0304) ‖ uint16 target_kdf.</summary>
    private static byte[] BuildImportedIdentity(ExternalPsk psk)
    {
        ushort targetKdf = ExternalPskKdf(psk.Suite).kdfId;
        var w = new System.Buffers.ArrayBufferWriter<byte>(psk.Identity.Length + 8);
        BinaryHelper.WriteUInt16(w, (ushort)psk.Identity.Length);
        w.Write(psk.Identity);                                  // external_identity
        BinaryHelper.WriteUInt16(w, 0);                         // context (empty)
        BinaryHelper.WriteUInt16(w, TlsConst.Tls13Version);     // target_protocol = TLS 1.3
        BinaryHelper.WriteUInt16(w, targetKdf);                 // target_kdf
        return w.WrittenSpan.ToArray();
    }

    /// <summary>RFC 9258 §4.1: derive the imported PSK from external key material.
    /// epskx = HKDF-Extract(0, epsk); ipskx = HKDF-Expand-Label(epskx, "derived psk",
    /// Hash(ImportedIdentity), L). The ImportedIdentity is also what we advertise on the wire.</summary>
    private static byte[] DeriveExternalPskKey(ExternalPsk psk)
    {
        var (hashAlg, hashLen, _) = ExternalPskKdf(psk.Suite);

        byte[] salt = new byte[hashLen];                          // salt = 0^hash_len
        byte[] epskx = Hkdf.Extract(hashAlg, salt, psk.Key);      // HKDF-Extract(0, epsk)

        byte[] importedIdentity = BuildImportedIdentity(psk);
        byte[] idHash = hashAlg == HashAlgorithmName.SHA384
            ? Sha2Managed.Sha384(importedIdentity)
            : Sha2Managed.Sha256(importedIdentity);
        return Hkdf.ExpandLabel(hashAlg, epskx, "derived psk", idHash, hashLen); // ipskx
    }

    // ================================================================
    //  Exported Authenticators (RFC 9261)
    // ================================================================

    /// <summary>Generate exported authenticator for certificate (RFC 9261).</summary>
    public byte[] ExportAuthenticator(TlsCertificate certificate, byte[] context, bool isServer = true)
    {
        if (!IsHandshakeComplete || _keySchedule?.ExporterMasterSecret == null)
            throw new InvalidOperationException("Handshake not complete");

        // RFC 9261 §3.1: Derive authenticator traffic secret
        string label = isServer ? "EXPORTER-server authenticator" : "EXPORTER-client authenticator";
        byte[] authSecret = ExportKeyingMaterial(label, context, _keySchedule.HashLen);

        // Build CertificateVerify-style structure
        string signContext = isServer ? "TLS 1.3, server authenticator" : "TLS 1.3, client authenticator";
        byte[] signContent = HandshakeMessages.BuildCertVerifyContent(signContext, context);
        byte[] signature = CertificateUtils.Sign(signContent, certificate.PrivateKey,
            certificate.PublicKey, certificate.SignatureAlgorithm);

        // Build exported authenticator structure (simplified Certificate + CertificateVerify)
        using var ms = new MemoryStream();

        // Certificate message structure
        BinaryHelper.WriteUInt24(ms, 0); // certificate_request_context length = 0

        // Certificate entries
        byte[][] chainCerts = certificate.ChainCertificates ?? Array.Empty<byte[]>();
        int totalCertLen = certificate.DerData.Length + 3 + 2; // cert + len + ext_len
        foreach (var chainCert in chainCerts)
            totalCertLen += chainCert.Length + 3 + 2;

        BinaryHelper.WriteUInt24(ms, (uint)totalCertLen);

        // Write primary certificate
        BinaryHelper.WriteUInt24(ms, (uint)certificate.DerData.Length);
        ms.Write(certificate.DerData);
        BinaryHelper.WriteUInt16(ms, 0); // extensions length = 0

        // Write chain certificates
        foreach (var chainCert in chainCerts)
        {
            BinaryHelper.WriteUInt24(ms, (uint)chainCert.Length);
            ms.Write(chainCert);
            BinaryHelper.WriteUInt16(ms, 0); // extensions length = 0
        }

        // CertificateVerify structure
        BinaryHelper.WriteUInt16(ms, (ushort)certificate.SignatureAlgorithm);
        BinaryHelper.WriteUInt16(ms, (ushort)signature.Length);
        ms.Write(signature);

        return ms.ToArray();
    }

    /// <summary>Verify exported authenticator (RFC 9261).</summary>
    public bool VerifyExportedAuthenticator(byte[] authenticator, byte[] context, bool isServer = true,
        TlsCertificate? caCertificate = null)
    {
        if (!IsHandshakeComplete || _keySchedule?.ExporterMasterSecret == null)
            throw new InvalidOperationException("Handshake not complete");

        try
        {
            // Parse authenticator structure
            int pos = 0;

            // Skip certificate_request_context
            int contextLen = (int)BinaryHelper.ReadUInt24(authenticator.AsSpan(pos)); pos += 3;
            pos += contextLen; // should be 0

            // Parse certificate list
            int certListLen = (int)BinaryHelper.ReadUInt24(authenticator.AsSpan(pos)); pos += 3;

            if (certListLen == 0) return false; // No certificates

            // Extract first certificate
            int firstCertLen = (int)BinaryHelper.ReadUInt24(authenticator.AsSpan(pos)); pos += 3;
            byte[] certDer = authenticator[pos..(pos + firstCertLen)]; pos += firstCertLen;
            int extLen = (int)BinaryHelper.ReadUInt16(authenticator.AsSpan(pos)); pos += 2;
            pos += extLen; // skip extensions

            // Skip remaining certificates in chain
            while (pos < 3 + 3 + certListLen)
            {
                int nextCertLen = (int)BinaryHelper.ReadUInt24(authenticator.AsSpan(pos)); pos += 3;
                pos += nextCertLen;
                int nextExtLen = (int)BinaryHelper.ReadUInt16(authenticator.AsSpan(pos)); pos += 2;
                pos += nextExtLen;
            }

            // Parse CertificateVerify
            var sigAlg = (SignatureScheme)BinaryHelper.ReadUInt16(authenticator.AsSpan(pos)); pos += 2;
            int sigLen = BinaryHelper.ReadUInt16(authenticator.AsSpan(pos)); pos += 2;
            byte[] signature = authenticator[pos..(pos + sigLen)];

            // Verify certificate chain if CA provided
            if (caCertificate != null)
            {
                var cert = new TlsCertificate { DerData = certDer };
                if (!CertificateUtils.VerifyChain(cert, caCertificate))
                    return false;
            }

            // Verify signature against the public key parsed from the certificate DER (the TlsCertificate
            // built above carries only DerData — its PublicKey field is not populated from the bytes).
            var (pubKey, _) = CertificateUtils.ParseCertificatePublicKey(certDer);
            string signContext = isServer ? "TLS 1.3, server authenticator" : "TLS 1.3, client authenticator";
            byte[] signContent = HandshakeMessages.BuildCertVerifyContent(signContext, context);

            return CertificateUtils.Verify(signContent, signature, pubKey, sigAlg);
        }
        catch
        {
            return false;
        }
    }

    // ================================================================
    //  Client handshake
    // ================================================================

    public void HandshakeAsClient(string? serverName = null)
    {
        HandshakePhaseHook.Mark("client/start");

        // 1. Lazy ephemeral key pair generation — only generate for groups we'll actually
        // offer in the ClientHello key_share extension. Previously we generated all five
        // (X25519 + P-256 + P-384 + X448 + ML-KEM-768) unconditionally; profiling showed
        // X25519=656 KB, X448=1687 KB, P-384=292 KB, P-256=63 KB, ML-KEM=60 KB per call
        // (~2.7 MB combined) — pure waste when the caller restricted the offered set.
        //
        // For each unoffered group the key fields stay Array.Empty<byte>(); they're never
        // read downstream because ComputeClientSharedSecret only dispatches based on the
        // group the server chose (which must be one we offered). HRR fallback (below)
        // does its own keygen for the requested group, so that path is unaffected.
        var offered = _offeredGroups ?? new[]
        {
            NamedGroup.X25519MLKEM768, NamedGroup.X25519, NamedGroup.X448,
            NamedGroup.Secp256r1, NamedGroup.Secp384r1
        };

        bool wantX25519 = false, wantP256 = false, wantP384 = false, wantX448 = false, wantHybrid = false, wantHybridP256 = false, wantHybridP384 = false;
        foreach (var g in offered)
        {
            switch (g)
            {
                case NamedGroup.X25519: wantX25519 = true; break;
                case NamedGroup.Secp256r1: wantP256 = true; break;
                case NamedGroup.Secp384r1: wantP384 = true; break;
                case NamedGroup.X448: wantX448 = true; break;
                case NamedGroup.X25519MLKEM768: wantHybrid = true; break;
                case NamedGroup.SecP256r1MLKEM768: wantHybridP256 = true; break;
                case NamedGroup.SecP384r1MLKEM1024: wantHybridP384 = true; break;
                // GOST + SM2 groups are handled inside BuildClientKeyShares (their key
                // generators live there and stash the private into _gostKexPriv / _sm2KexPriv).
            }
        }
        // The hybrid groups reuse a classical keypair as their ECDH component, so generating
        // them implies that keygen even if the classical group alone wasn't offered.
        if (wantHybrid) wantX25519 = true;
        if (wantHybridP256) wantP256 = true;
        if (wantHybridP384) wantP384 = true;

        byte[] x25519Priv = Array.Empty<byte>(), x25519Pub = Array.Empty<byte>();
        byte[] p256Priv = Array.Empty<byte>(), p256Pub = Array.Empty<byte>();
        byte[] p384Priv = Array.Empty<byte>(), p384Pub = Array.Empty<byte>();
        byte[] x448Priv = Array.Empty<byte>(), x448Pub = Array.Empty<byte>();
        byte[] mlkemDk = Array.Empty<byte>();
        byte[] hybridPub = Array.Empty<byte>();
        byte[] secp256HybridPub = Array.Empty<byte>();
        byte[] secp384HybridPub = Array.Empty<byte>();

        if (wantX25519)
        {
            x25519Priv = X25519.GeneratePrivateKey();
            x25519Pub = X25519.PublicFromPrivate(x25519Priv);
        }
        HandshakePhaseHook.Mark("client/after-X25519-keygen");
        if (wantP256)
            (p256Priv, p256Pub) = EcdhP256.GenerateKeyPair();
        HandshakePhaseHook.Mark("client/after-P256-keygen");
        if (wantP384)
            (p384Priv, p384Pub) = EcdhP384.GenerateKeyPair();
        HandshakePhaseHook.Mark("client/after-P384-keygen");
        if (wantX448)
        {
            x448Priv = X448.GeneratePrivateKey();
            x448Pub = X448.PublicFromPrivate(x448Priv);
        }
        HandshakePhaseHook.Mark("client/after-X448-keygen");

        if (wantHybrid)
        {
            // X25519MLKEM768: ML-KEM ek ‖ X25519 share (ML-KEM first, per draft-ietf-tls-ecdhe-mlkem §4.1)
            var (mlkemEk, dk) = MlKem768.KeyGen();
            mlkemDk = dk;
            hybridPub = new byte[mlkemEk.Length + x25519Pub.Length];
            Buffer.BlockCopy(mlkemEk, 0, hybridPub, 0, mlkemEk.Length);
            Buffer.BlockCopy(x25519Pub, 0, hybridPub, mlkemEk.Length, x25519Pub.Length);
        }
        if (wantHybridP256)
        {
            // SecP256r1MLKEM768: secp256r1 point (65) ‖ ML-KEM ek (1184) — ECDH first (§4.1)
            var (mlkemEkP, dkP) = MlKem768.KeyGen();
            _mlkemDkSecp256 = dkP;
            secp256HybridPub = new byte[p256Pub.Length + mlkemEkP.Length];
            Buffer.BlockCopy(p256Pub, 0, secp256HybridPub, 0, p256Pub.Length);
            Buffer.BlockCopy(mlkemEkP, 0, secp256HybridPub, p256Pub.Length, mlkemEkP.Length);
        }
        if (wantHybridP384)
        {
            // SecP384r1MLKEM1024: secp384r1 point (97) ‖ ML-KEM-1024 ek (1568) — ECDH first (§4.1)
            var (mlkemEk384, dk384) = MlKem1024.KeyGen();
            _mlkemDkSecp384 = dk384;
            secp384HybridPub = new byte[p384Pub.Length + mlkemEk384.Length];
            Buffer.BlockCopy(p384Pub, 0, secp384HybridPub, 0, p384Pub.Length);
            Buffer.BlockCopy(mlkemEk384, 0, secp384HybridPub, p384Pub.Length, mlkemEk384.Length);
        }
        HandshakePhaseHook.Mark("client/after-MLKEM-keygen");

        byte[] clientRandom = RandomnessWrapper.GetHandshakeBytes(32);
        _clientRandom = clientRandom;
        byte[] sessionId = RandomnessWrapper.GetBytes(32);

        var suites = _offeredSuites ?? new[]
        {
            CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_AES_128_GCM_SHA256
        };
        var keyShares = BuildClientKeyShares(hybridPub, x25519Pub, x448Pub, p256Pub, p384Pub, secp256HybridPub, secp384HybridPub);

        // 2. Build ClientHello (with PSK if available)
        byte[] chMsg;
        byte[]? psk = null;
        bool offer0Rtt = false;

        if (_pskTicket != null)
        {
            // ResumptionSecret is already the derived PSK
            // (HKDF-Expand-Label(rms, "resumption", nonce, hash_len) was applied at ticket creation)
            psk = _pskTicket.ResumptionSecret;

            _keySchedule = new KeySchedule(_pskTicket.CipherSuite, psk);
            _transcript.SetAlgorithm(_keySchedule.HashAlgorithm);

            // Compute obfuscated ticket age
            var elapsed = DateTime.UtcNow - _pskTicket.IssuedAt;
            uint ticketAgeMs = (uint)elapsed.TotalMilliseconds;
            uint obfuscatedAge = ticketAgeMs + _pskTicket.AgeAdd;

            // Build CH with placeholder binder
            int binderLen = _keySchedule.HashLen;
            byte[] placeholder = new byte[binderLen];
            offer0Rtt = _pskTicket.MaxEarlyDataSize > 0;

            chMsg = HandshakeMessages.BuildClientHelloWithPsk(
                clientRandom, sessionId, suites, keyShares,
                _pskTicket.Ticket, obfuscatedAge, placeholder,
                offer0Rtt, serverName, alpnProtocols: _alpnProtocols,
                requestOcspStapling: _requestOcspStapling, offeredSigAlgs: _offeredSigAlgs,
                offeredGroups: _offeredGroups, postHandshakeAuth: _offerPostHandshakeAuth);

            // Compute and patch the real binder
            // Truncated transcript = ClientHello up to (but not including) the binders list
            int bindersLen = HandshakeMessages.PskBindersTailLength(binderLen);
            byte[] truncatedCh = chMsg[..^bindersLen];

            var binderTranscript = new TranscriptHash(_keySchedule.HashAlgorithm);
            binderTranscript.Update(truncatedCh);
            byte[] truncatedHash = binderTranscript.GetHash();

            byte[] binderKey = _keySchedule.DeriveBinderKey();
            byte[] binder = HandshakeMessages.ComputePskBinder(binderKey, truncatedHash, _keySchedule.HashAlgorithm);
            HandshakeMessages.PatchPskBinder(chMsg, binder);
        }
        else if (_externalPsk != null)
        {
            // RFC 9258: Use imported external PSK
            psk = DeriveExternalPskKey(_externalPsk);

            _keySchedule = new KeySchedule(_externalPsk.Suite, psk);
            _transcript.SetAlgorithm(_keySchedule.HashAlgorithm);

            // Build CH with placeholder binder
            int binderLen = _keySchedule.HashLen;
            byte[] placeholder = new byte[binderLen];
            // draft-ietf-tls-8773bis forbids early_data alongside tls_cert_with_extern_psk.
            offer0Rtt = !_certWithExternPsk && _externalPsk.MaxEarlyDataSize > 0;

            chMsg = HandshakeMessages.BuildClientHelloWithPsk(
                clientRandom, sessionId, suites, keyShares,
                BuildImportedIdentity(_externalPsk), 0, placeholder, // External PSK age is always 0
                offer0Rtt, serverName, alpnProtocols: _alpnProtocols,
                requestOcspStapling: _requestOcspStapling, certWithExternPsk: _certWithExternPsk,
                offeredSigAlgs: _offeredSigAlgs, offeredGroups: _offeredGroups, postHandshakeAuth: _offerPostHandshakeAuth);

            // Compute and patch the real binder
            int bindersLen = HandshakeMessages.PskBindersTailLength(binderLen);
            byte[] truncatedCh = chMsg[..^bindersLen];

            var binderTranscript = new TranscriptHash(_keySchedule.HashAlgorithm);
            binderTranscript.Update(truncatedCh);
            byte[] truncatedHash = binderTranscript.GetHash();

            // RFC 8446 §4.2.11.2: external (RFC 9258) PSKs use the "ext binder" label.
            byte[] binderKey = _keySchedule.DeriveBinderKey(external: true);
            byte[] binder = HandshakeMessages.ComputePskBinder(binderKey, truncatedHash, _keySchedule.HashAlgorithm);
            HandshakeMessages.PatchPskBinder(chMsg, binder);
        }
        else
        {
            // ECH (or GREASE-ECH) if configured, else a normal ClientHello.
            chMsg = TryBuildEchClientHello(clientRandom, sessionId, suites, keyShares, serverName)
                ?? BuildGreaseEchClientHello(clientRandom, sessionId, suites, keyShares, serverName)
                ?? HandshakeMessages.BuildClientHello(clientRandom, sessionId, suites, keyShares,
                    serverName, alpnProtocols: _alpnProtocols, requestOcspStapling: _requestOcspStapling,
                    offeredSigAlgs: _offeredSigAlgs, offeredGroups: _offeredGroups, postHandshakeAuth: _offerPostHandshakeAuth);
        }

        _record.WriteRecord(ContentType.Handshake, chMsg);
        // ECH accept path transcripts the ClientHelloInner, not the outer that went on the wire.
        if (_echContext == null) _transcript.Update(chMsg); // real ECH defers until accept/reject is known (at the ServerHello)
        HandshakePhaseHook.Mark("client/after-CH-sent");

        // 2b. Send 0-RTT early data if applicable
        if (offer0Rtt && _keySchedule != null)
        {
            byte[] chHash = _transcript.GetHash();
            byte[] earlySecret = _keySchedule.DeriveClientEarlyTrafficSecret(chHash);
            if (_clientRandom != null) KeyLogger.LogEarlyTrafficSecret(_clientRandom, earlySecret);
            var (ek, eiv) = _keySchedule.DeriveKeyAndIv(earlySecret);
            _record.SetWriteCipher(new AeadCipher(ek, eiv, _keySchedule.Aead, _keySchedule.Suite));

            // Write actual early data under early traffic keys
            if (_earlyData != null && _earlyData.Length > 0)
            {
                int maxSize = (int)(_pskTicket?.MaxEarlyDataSize ?? _externalPsk?.MaxEarlyDataSize ?? 0);
                int toSend = Math.Min(_earlyData.Length, maxSize);
                int pos = 0;
                while (pos < toSend)
                {
                    int chunk = Math.Min(toSend - pos, TlsConst.MaxPlaintextLength);
                    // AsSpan instead of Range slice — RecordLayer.WriteRecord now takes
                    // ReadOnlySpan<byte>, so this passes a zero-copy view instead of
                    // allocating a fresh byte[chunk] per record.
                    _record.WriteRecord(ContentType.ApplicationData, _earlyData.AsSpan(pos, chunk));
                    pos += chunk;
                }
            }
            // EndOfEarlyData will be sent under these keys later
        }

        // 3. Receive ServerHello (might be HelloRetryRequest)
        byte[] shMsg = NextHandshake(HandshakeType.ServerHello);
        var (_, shBody) = HandshakeMessages.Unframe(shMsg);
        var sh = HandshakeMessages.ParseServerHello(shBody);
        CheckSessionIdEcho(sessionId, sh.SessionId);
        ValidateServerCipherSuiteOffered(sh.CipherSuite, suites);
        if (!sh.IsHelloRetryRequest) CheckDowngradeSentinel(sh.ServerRandom);
        VerifyEchAcceptConfirmation(shMsg, sh);
        HandshakePhaseHook.Mark("client/after-SH-received");

        // 4. Handle HelloRetryRequest
        if (sh.IsHelloRetryRequest)
        {
            ValidateSelectedGroupOffered(sh.KeyShareGroup); // RFC 8446 §4.1.4
            if (_keySchedule == null)
            {
                _keySchedule = new KeySchedule(sh.CipherSuite);
                _transcript.SetAlgorithm(_keySchedule.HashAlgorithm);
            }

            VerifyEchHrrAndCommit(shMsg, sh); // ECH: verify HRR confirmation + commit the deferred CH1
            _transcript.ReplaceWithMessageHash();
            _transcript.Update(shMsg);

            if (sh.KeyShareGroup == NamedGroup.X25519)
            {
                x25519Priv = X25519.GeneratePrivateKey();
                x25519Pub = X25519.PublicFromPrivate(x25519Priv);
                keyShares = new (NamedGroup, byte[])[] { (NamedGroup.X25519, x25519Pub) };
            }
            else if (sh.KeyShareGroup == NamedGroup.X448)
            {
                x448Priv = X448.GeneratePrivateKey();
                x448Pub = X448.PublicFromPrivate(x448Priv);
                keyShares = new (NamedGroup, byte[])[] { (NamedGroup.X448, x448Pub) };
            }
            else if (sh.KeyShareGroup == NamedGroup.Secp256r1)
            {
                (p256Priv, p256Pub) = EcdhP256.GenerateKeyPair();
                keyShares = new (NamedGroup, byte[])[] { (NamedGroup.Secp256r1, p256Pub) };
            }
            else if (sh.KeyShareGroup == NamedGroup.Secp384r1)
            {
                (p384Priv, p384Pub) = EcdhP384.GenerateKeyPair();
                keyShares = new (NamedGroup, byte[])[] { (NamedGroup.Secp384r1, p384Pub) };
            }
            else if (sh.KeyShareGroup == NamedGroup.X25519MLKEM768)
            {
                x25519Priv = X25519.GeneratePrivateKey();
                x25519Pub = X25519.PublicFromPrivate(x25519Priv);
                // mlkemEk is local to the HRR branch — only used here to build hybridPub.
                // mlkemDk is the outer-scope variable since ComputeClientSharedSecret needs it.
                var (mlkemEk, dk) = MlKem768.KeyGen();
                mlkemDk = dk;
                hybridPub = new byte[mlkemEk.Length + x25519Pub.Length];
                Buffer.BlockCopy(mlkemEk, 0, hybridPub, 0, mlkemEk.Length);
                Buffer.BlockCopy(x25519Pub, 0, hybridPub, mlkemEk.Length, x25519Pub.Length);
                keyShares = new (NamedGroup, byte[])[] { (NamedGroup.X25519MLKEM768, hybridPub) };
            }
            else if (sh.KeyShareGroup == NamedGroup.SecP256r1MLKEM768)
            {
                (p256Priv, p256Pub) = EcdhP256.GenerateKeyPair();
                var (mlkemEkP, dkP) = MlKem768.KeyGen();
                _mlkemDkSecp256 = dkP;
                secp256HybridPub = new byte[p256Pub.Length + mlkemEkP.Length];
                Buffer.BlockCopy(p256Pub, 0, secp256HybridPub, 0, p256Pub.Length);
                Buffer.BlockCopy(mlkemEkP, 0, secp256HybridPub, p256Pub.Length, mlkemEkP.Length);
                keyShares = new (NamedGroup, byte[])[] { (NamedGroup.SecP256r1MLKEM768, secp256HybridPub) };
            }
            else if (sh.KeyShareGroup == NamedGroup.SecP384r1MLKEM1024)
            {
                (p384Priv, p384Pub) = EcdhP384.GenerateKeyPair();
                var (mlkemEk384, dk384) = MlKem1024.KeyGen();
                _mlkemDkSecp384 = dk384;
                secp384HybridPub = new byte[p384Pub.Length + mlkemEk384.Length];
                Buffer.BlockCopy(p384Pub, 0, secp384HybridPub, 0, p384Pub.Length);
                Buffer.BlockCopy(mlkemEk384, 0, secp384HybridPub, p384Pub.Length, mlkemEk384.Length);
                keyShares = new (NamedGroup, byte[])[] { (NamedGroup.SecP384r1MLKEM1024, secp384HybridPub) };
            }
            else
            {
                AlertAndThrow(AlertDescription.IllegalParameter, $"Unsupported group in HRR: {sh.KeyShareGroup}");
            }

            // HRR invalidates 0-RTT — clear early write cipher if it was installed (RFC 8446 §4.2.10)
            if (offer0Rtt)
            {
                _record.ClearWriteCipher();
                offer0Rtt = false;
            }

            _record.WriteChangeCipherSpec();
            _sentCcs = true;

            byte[] ch2Msg;
            if (psk != null && (_pskTicket != null || _externalPsk != null))
            {
                // Rebuild CH2 with PSK extension (RFC 8446 §4.2.11)
                byte[] pskIdentity;
                uint obfuscatedAge2;
                bool externalPskBinder = _pskTicket == null;
                if (_pskTicket != null)
                {
                    var elapsed2 = DateTime.UtcNow - _pskTicket.IssuedAt;
                    obfuscatedAge2 = (uint)elapsed2.TotalMilliseconds + _pskTicket.AgeAdd;
                    pskIdentity = _pskTicket.Ticket;
                }
                else
                {
                    obfuscatedAge2 = 0;
                    pskIdentity = BuildImportedIdentity(_externalPsk!);
                }
                int binderLen2 = _keySchedule.HashLen;

                ch2Msg = HandshakeMessages.BuildClientHelloWithPsk(
                    clientRandom, sessionId, suites, keyShares,
                    pskIdentity, obfuscatedAge2, new byte[binderLen2],
                    false, serverName, sh.Cookie, _alpnProtocols,
                    requestOcspStapling: _requestOcspStapling, certWithExternPsk: _certWithExternPsk,
                    offeredSigAlgs: _offeredSigAlgs,
                    offeredGroups: _offeredGroups, postHandshakeAuth: _offerPostHandshakeAuth); // no 0-RTT after HRR

                // Binder computed over: transcript(message_hash(CH1) || HRR) + truncated(CH2)
                int bindersLen2 = HandshakeMessages.PskBindersTailLength(binderLen2);
                var binderTranscript2 = _transcript.Clone();
                binderTranscript2.Update(ch2Msg[..^bindersLen2]);

                byte[] binder2 = HandshakeMessages.ComputePskBinder(
                    _keySchedule.DeriveBinderKey(external: externalPskBinder), binderTranscript2.GetHash(), _keySchedule.HashAlgorithm);
                HandshakeMessages.PatchPskBinder(ch2Msg, binder2);
                _record.WriteRecord(ContentType.Handshake, ch2Msg);
                _transcript.Update(ch2Msg);
            }
            else if (_echContext != null)
            {
                // ECH after HRR: rebuild the outer CH2 carrying a re-sealed inner CH2.
                var (outer2, transcript2) = BuildEchClientHello2(clientRandom, sessionId, suites, keyShares, serverName, sh.Cookie);
                ch2Msg = outer2;
                _record.WriteRecord(ContentType.Handshake, ch2Msg);
                _transcript.Update(transcript2);
            }
            else
            {
                ch2Msg = HandshakeMessages.BuildClientHello(
                    clientRandom, sessionId, suites, keyShares, serverName, sh.Cookie, _alpnProtocols,
                    requestOcspStapling: _requestOcspStapling, offeredSigAlgs: _offeredSigAlgs,
                    offeredGroups: _offeredGroups, postHandshakeAuth: _offerPostHandshakeAuth);
                _record.WriteRecord(ContentType.Handshake, ch2Msg);
                _transcript.Update(ch2Msg);
            }

            shMsg = NextHandshake(HandshakeType.ServerHello);
            (_, shBody) = HandshakeMessages.Unframe(shMsg);
            sh = HandshakeMessages.ParseServerHello(shBody);
            CheckSessionIdEcho(sessionId, sh.SessionId);
            ValidateServerCipherSuiteOffered(sh.CipherSuite, suites);

            if (sh.IsHelloRetryRequest)
                AlertAndThrow(AlertDescription.UnexpectedMessage, "Second HelloRetryRequest not allowed");
            CheckDowngradeSentinel(sh.ServerRandom);
            if (sh.CipherSuite != _keySchedule.Suite)
                AlertAndThrow(AlertDescription.IllegalParameter, "Cipher suite changed after HRR");

            // RFC 9849 §7.2: the post-HRR ServerHello also carries an ECH accept-confirmation, taken
            // over the full transcript message_hash(CH1inner) ‖ HRR ‖ CH2inner ‖ SH(zeroed). When we
            // attempted ECH and the HRR signalled acceptance, verify it matches (the running transcript
            // already holds that prefix), so a server that accepted ECH must prove it consistently.
            if (_echContext != null && EchAccepted)
            {
                byte[] shZeroed = (byte[])shMsg.Clone();
                Array.Clear(shZeroed, 30, 8);
                byte[] expected = ComputeEchConfFromTranscript(_transcript, shZeroed, _echContext.InnerRandom);
                if (!CryptographicOperations.FixedTimeEquals(expected, shMsg.AsSpan(30, 8)))
                    AlertAndThrow(AlertDescription.IllegalParameter,
                        "ECH accept-confirmation mismatch in post-HRR ServerHello");
            }
        }

        // 5. Set up key schedule (if not already from PSK/HRR)
        // draft-ietf-tls-8773bis: a server that echoes tls_cert_with_extern_psk mixes the PSK into the
        // key schedule but still runs a FULL certificate handshake (not a resumption skip).
        ValidateServerPskSelection(sh, psk, _certWithExternPsk && _externalPsk != null,
            _pskTicket?.CipherSuite ?? _externalPsk?.Suite);
        bool certWithPsk = sh.CertWithExternPsk && psk != null;
        bool isPskResumption = !certWithPsk && sh.SelectedPskIndex >= 0 && psk != null;
        if (_keySchedule == null || (!isPskResumption && !certWithPsk && psk != null))
        {
            // Recreate the key schedule when first time (no HRR), or the server rejected our PSK
            // (the early secret would otherwise have the wrong PSK baked in).
            _keySchedule = (isPskResumption || certWithPsk) ? new KeySchedule(sh.CipherSuite, psk) : new KeySchedule(sh.CipherSuite);
            _transcript.SetAlgorithm(_keySchedule.HashAlgorithm);
        }
        _transcript.Update(shMsg);
        IsResumed = isPskResumption;
        UsedCertWithExternalPsk = certWithPsk;

        // 6. Compute shared secret based on selected group
        _negotiatedGroup = sh.KeyShareGroup;
        if (sh.KeyShare == null || sh.KeyShare.Length == 0)
            AlertAndThrow(AlertDescription.DecodeError, "ServerHello has empty KeyShare");
        ValidateSelectedGroupOffered(sh.KeyShareGroup); // RFC 8446 §4.2.8 (final selected_group)
        byte[] shared = ComputeClientSharedSecret(
            sh.KeyShareGroup, sh.KeyShare, x25519Priv, x25519Pub,
            p256Priv, p256Pub, p384Priv, p384Pub, x448Priv, mlkemDk);
        HandshakePhaseHook.Mark("client/after-ECDH");
        _keySchedule.DeriveHandshakeSecrets(shared, _transcript.GetHash());
        HandshakePhaseHook.Mark("client/after-DeriveHandshakeSecrets");

        // Key logging
        if (KeyLogger.IsEnabled)
            KeyLogger.LogHandshakeTrafficSecrets(clientRandom,
                _keySchedule.ClientHandshakeTrafficSecret!, _keySchedule.ServerHandshakeTrafficSecret!);

        // 7. Install server handshake read cipher
        var (sKey, sIv) = _keySchedule.DeriveKeyAndIv(_keySchedule.ServerHandshakeTrafficSecret!);
        _record.SetReadCipher(new AeadCipher(sKey, sIv, _keySchedule.Aead, _keySchedule.Suite));

        // 8. EncryptedExtensions
        byte[] eeMsg = NextHandshake(HandshakeType.EncryptedExtensions);
        _transcript.Update(eeMsg);
        var (_, eeBody) = HandshakeMessages.Unframe(eeMsg);
        var ee = HandshakeMessages.ParseEncryptedExtensionsEx(eeBody);
        HandshakePhaseHook.Mark("client/after-EE");
        RejectUnsolicitedEncryptedExtensions(ee, offer0Rtt, isPskResumption);
        bool earlyDataServerAccepted = ee.AcceptEarlyData;
        _negotiatedAlpn = ee.AlpnProtocol;
        _peerCertCompAlgorithm = ee.CertCompressionAlgorithm;
        ApplyPeerRecordSizeLimit(ee.RecordSizeLimit);
        // ECH reject: the server returned a fresh ECHConfigList (retry_configs) for the next attempt.
        if (_echContext != null && !EchAccepted) _echRetryConfigs = ee.EchRetryConfigs;
        EarlyDataAccepted = earlyDataServerAccepted && offer0Rtt && isPskResumption;

        // 9. If PSK resumption: skip to Finished (no Certificate/CertificateVerify)
        if (isPskResumption)
        {
            // Server Finished
            byte[] preFinHash = _transcript.GetHash();
            byte[] sfMsg = NextHandshake(HandshakeType.Finished);
            var (_, sfBody) = HandshakeMessages.Unframe(sfMsg);

            byte[] expectedSF = _keySchedule.ComputeFinishedVerifyData(
                _keySchedule.ServerHandshakeTrafficSecret!, preFinHash);
            if (!CryptographicOperations.FixedTimeEquals(sfBody, expectedSF))
                AlertAndThrow(AlertDescription.DecryptError, "Server Finished verification failed");

            // Store server finished for channel binding
            _serverFinishedValue = expectedSF;

            _transcript.Update(sfMsg);
            _serverFinishedHash = _transcript.GetHash();
            _keySchedule.DeriveAppSecrets(_serverFinishedHash);
        LogAppSecrets();

            // Send CCS + EndOfEarlyData (if 0-RTT) + client Finished
            if (!_sentCcs) _record.WriteChangeCipherSpec();

            // EndOfEarlyData MUST be sent under early traffic keys (RFC 8446 §4.5)
            if (EarlyDataAccepted)
            {
                // Write cipher is still set to early traffic keys from the 0-RTT setup
                byte[] eodMsg = HandshakeMessages.BuildEndOfEarlyData();
                _record.WriteRecord(ContentType.Handshake, eodMsg);
                _transcript.Update(eodMsg);
            }

            // Now switch to handshake keys for Finished
            var (cKey, cIv) = _keySchedule.DeriveKeyAndIv(_keySchedule.ClientHandshakeTrafficSecret!);
            _record.SetWriteCipher(new AeadCipher(cKey, cIv, _keySchedule.Aead, _keySchedule.Suite));

            byte[] cfVerify = _keySchedule.ComputeFinishedVerifyData(
                _keySchedule.ClientHandshakeTrafficSecret!, _transcript.GetHash());
            byte[] cfMsg = HandshakeMessages.BuildFinished(cfVerify);
            _record.WriteRecord(ContentType.Handshake, cfMsg);
            _transcript.Update(cfMsg);

            // Store client finished for channel binding
            _clientFinishedValue = cfVerify;

            byte[] fullHash = _transcript.GetHash();
            _keySchedule.DeriveResumptionMasterSecret(fullHash);
            InstallAppKeys();
            IsHandshakeComplete = true;
            return;
        }

        // 10. Check for CertificateRequest (mTLS) or Certificate / CompressedCertificate
        byte[] nextMsg = NextHandshakeAny(out HandshakeType nextType);
        byte[]? certReqContext = null;
        SignatureScheme[]? certReqSigAlgorithms = null;

        if (nextType == HandshakeType.CertificateRequest)
        {
            _transcript.Update(nextMsg);
            var (_, crBody) = HandshakeMessages.Unframe(nextMsg);
            var (ctx, sigAlgs, _) = HandshakeMessages.ParseCertificateRequest(crBody);
            ValidateCertificateContext(ctx, Array.Empty<byte>(),
                "Initial CertificateRequest certificate_request_context must be empty");
            certReqContext = ctx;
            certReqSigAlgorithms = sigAlgs;
            _serverCertReqCompAlgs = HandshakeMessages.ParseCertReqCertCompression(crBody);
            nextMsg = NextHandshakeAny(out nextType);
        }
        else if (nextType != HandshakeType.Certificate && nextType != HandshakeType.CompressedCertificate)
        {
            AlertAndThrow(AlertDescription.UnexpectedMessage,
                $"Expected CertificateRequest or Certificate, got {nextType}");
        }

        // 11. Server Certificate (possibly compressed)
        _transcript.Update(nextMsg);
        byte[] certBody;
        if (nextType == HandshakeType.CompressedCertificate)
        {
            var (_, compBody) = HandshakeMessages.Unframe(nextMsg);
            certBody = HandshakeMessages.ParseCompressedCertificate(compBody, CertCompAdvertise);
        }
        else
        {
            (_, certBody) = HandshakeMessages.Unframe(nextMsg);
        }
        var (serverCertContext, serverCertEntries) = HandshakeMessages.ParseCertificateEx(certBody);
        ValidateCertificateContext(serverCertContext, Array.Empty<byte>(),
            "Server Certificate certificate_request_context must be empty");
        if (serverCertEntries.Count == 0)
            AlertAndThrow(AlertDescription.CertificateRequired, "Server sent empty certificate");
        byte[] serverCertDer = serverCertEntries[0].CertDer;
        PeerCertificateData = serverCertDer;
        if (_requestOcspStapling && serverCertEntries[0].OcspResponse != null)
            PeerOcspResponse = serverCertEntries[0].OcspResponse;
        ValidatePeerCertificate(serverCertDer, serverName);
        byte[][] serverIntermediates = new byte[serverCertEntries.Count - 1][];
        for (int ci = 1; ci < serverCertEntries.Count; ci++)
            serverIntermediates[ci - 1] = serverCertEntries[ci].CertDer;
        EnforceServerCertificateTrust(serverCertDer, serverIntermediates, serverName);
        HandshakePhaseHook.Mark("client/after-Certificate-parsed");

        // 12. CertificateVerify
        byte[] preCvHash = _transcript.GetHash();
        byte[] cvMsg = NextHandshake(HandshakeType.CertificateVerify);
        HandshakePhaseHook.Mark("client/CV/after-read");
        var (_, cvBody) = HandshakeMessages.Unframe(cvMsg);
        var (sigScheme, sig) = HandshakeMessages.ParseCertificateVerify(cvBody);
        ValidateSignatureScheme(sigScheme);
        HandshakePhaseHook.Mark("client/CV/after-parse");

        var (serverPubKey, _) = CertificateUtils.ParseCertificatePublicKey(serverCertDer);
        HandshakePhaseHook.Mark("client/CV/after-ParsePubKey");
        byte[] cvContent = HandshakeMessages.BuildCertVerifyContent(
            "TLS 1.3, server CertificateVerify", preCvHash);
        if (!CertificateUtils.Verify(cvContent, sig, serverPubKey, sigScheme))
            AlertAndThrow(AlertDescription.DecryptError, "Server CertificateVerify failed");
        HandshakePhaseHook.Mark("client/CV/after-Verify");

        _transcript.Update(cvMsg);
        HandshakePhaseHook.Mark("client/after-CertVerify");

        // 13. Server Finished
        byte[] preFinHash2 = _transcript.GetHash();
        byte[] sfMsg2 = NextHandshake(HandshakeType.Finished);
        var (_, sfBody2) = HandshakeMessages.Unframe(sfMsg2);

        byte[] expectedSF2 = _keySchedule.ComputeFinishedVerifyData(
            _keySchedule.ServerHandshakeTrafficSecret!, preFinHash2);
        if (!CryptographicOperations.FixedTimeEquals(sfBody2, expectedSF2))
            AlertAndThrow(AlertDescription.DecryptError, "Server Finished verification failed");

        // Store server finished for channel binding
        _serverFinishedValue = expectedSF2;

        _transcript.Update(sfMsg2);

        // 14. Derive application secrets
        _serverFinishedHash = _transcript.GetHash();
        _keySchedule.DeriveAppSecrets(_serverFinishedHash);
        LogAppSecrets();

        // 15. Send CCS then install client write cipher
        if (!_sentCcs)
            _record.WriteChangeCipherSpec();

        var (cKey2, cIv2) = _keySchedule.DeriveKeyAndIv(_keySchedule.ClientHandshakeTrafficSecret!);
        _record.SetWriteCipher(new AeadCipher(cKey2, cIv2, _keySchedule.Aead, _keySchedule.Suite));

        // 16. If mTLS: send client Certificate [+ CertificateVerify]
        if (certReqContext != null)
        {
            if (_certificate != null)
            {
                ValidateClientCertificateSignatureScheme(certReqSigAlgorithms!, _certificate.SignatureAlgorithm);
                byte[] clientCertMsg = HandshakeMessages.BuildCertificateMsg(
                    _certificate.DerData, certReqContext, _certificate.ChainCertificates);
                ushort clientCompAlg = SelectClientCertCompression();
                if (clientCompAlg != 0)
                    clientCertMsg = HandshakeMessages.BuildCompressedCertificate(clientCertMsg, clientCompAlg);
                _record.WriteRecord(ContentType.Handshake, clientCertMsg);
                _transcript.Update(clientCertMsg);

                byte[] clientCvContent = HandshakeMessages.BuildCertVerifyContent(
                    "TLS 1.3, client CertificateVerify", _transcript.GetHash());
                byte[] clientCvSig = CertificateUtils.Sign(clientCvContent,
                    _certificate.PrivateKey, _certificate.PublicKey, _certificate.SignatureAlgorithm);
                byte[] clientCvMsg = HandshakeMessages.BuildCertificateVerify(
                    _certificate.SignatureAlgorithm, clientCvSig);
                _record.WriteRecord(ContentType.Handshake, clientCvMsg);
                _transcript.Update(clientCvMsg);
            }
            else
            {
                byte[] emptyCertMsg = HandshakeMessages.BuildCertificateMsg(null, certReqContext);
                _record.WriteRecord(ContentType.Handshake, emptyCertMsg);
                _transcript.Update(emptyCertMsg);
            }
        }

        // 17. Client Finished
        byte[] cfVerify2 = _keySchedule.ComputeFinishedVerifyData(
            _keySchedule.ClientHandshakeTrafficSecret!, _transcript.GetHash());
        byte[] cfMsg2 = HandshakeMessages.BuildFinished(cfVerify2);
        _record.WriteRecord(ContentType.Handshake, cfMsg2);
        _transcript.Update(cfMsg2);

        // Store client finished for channel binding
        _clientFinishedValue = cfVerify2;

        // 18. Derive resumption master secret + switch to app keys
        byte[] fullHash2 = _transcript.GetHash();
        _keySchedule.DeriveResumptionMasterSecret(fullHash2);
        InstallAppKeys();
        IsHandshakeComplete = true;
    }

    // ================================================================
    //  Server handshake
    // ================================================================

    public void HandshakeAsServer()
    {
        if (_certificate == null)
            throw new InvalidOperationException("Server certificate is required");

        // 1. Receive ClientHello
        byte[] chMsg = NextHandshake(HandshakeType.ClientHello);
        var (_, chBody) = HandshakeMessages.Unframe(chMsg);
        var ch = HandshakeMessages.ParseClientHello(chBody);

        // 1b. ECH: if this is a ClientHelloOuter we can decrypt, swap to the inner — and the TLS 1.3
        // transcript MUST then be over the inner CH (draft §7). DecryptClientHello returns the framed
        // ClientHelloInner, reconstructed byte-exactly with the client's.
        byte[] transcriptCh = chMsg;
        if (ch.IsOuterClientHello && _echPrivateKey != null && _echConfigs != null)
        {
            byte[]? innerChMsg = EncryptedClientHello.DecryptClientHello(chBody, _echPrivateKey, _echConfigs);
            if (innerChMsg != null)
            {
                var (_, innerBody) = HandshakeMessages.Unframe(innerChMsg);
                ch = HandshakeMessages.ParseClientHello(innerBody);
                transcriptCh = innerChMsg;
                EchAccepted = true;
                _echInnerChMsg = innerChMsg;
                _echInnerRandom = ch.ClientRandom;
            }
            else _echServerRejected = true; // saw ECH we couldn't decrypt → return retry_configs in EE
            // else: ECH reject — fall through to the public_name handshake on the outer CH.
        }
        _transcript.Update(transcriptCh);
        _peerAllowsPostHandshakeAuth = ch.OffersPostHandshakeAuth;

        // RFC 9149: Store ticket request count
        _ticketRequestCount = ch.TicketRequestCount;

        // 2-3. Try PSK resumption first — PSK determines the cipher suite (RFC 8446 §4.2.11)
        CipherSuite suite = default;
        byte[]? psk = null;
        bool isPskResumption = false;
        bool certWithPsk = false;   // draft-ietf-tls-8773bis: cert + external PSK (full cert handshake)
        bool accept0Rtt = false;
        uint pskMaxEarlyData = 0;
        int selectedPskIndex = -1;
        bool selectedPskIsExternal = false;

        // draft-ietf-tls-8773bis §4: tls_cert_with_extern_psk MUST NOT be combined with early_data.
        if (ch.OffersCertWithExternPsk && ch.OffersEarlyData)
            AlertAndThrow(AlertDescription.IllegalParameter,
                "tls_cert_with_extern_psk MUST NOT be offered with early_data (draft-ietf-tls-8773bis)");

        // RFC 8446 §4.2.9: a server MUST NOT select a PSK unless the client offered a compatible
        // psk_key_exchange_mode. We only support psk_dhe_ke, so absent that the PSK is ignored and we
        // fall through to a full handshake.
        if (ch.PreSharedKeyData != null && ch.OffersPskDheKe && (_ticketEncryption != null || _externalPsk != null))
        {
            var (identities, ages, binders) = HandshakeMessages.ParsePreSharedKeyExtension(ch.PreSharedKeyData);
            for (int i = 0; i < identities.Length; i++)
            {
                // Try session ticket first
                byte[]? plaintext = _ticketEncryption?.Open(identities[i]);
                if (plaintext != null)
                {
                    var decoded = TicketEncryption.DecodeTicketState(plaintext);
                    if (decoded == null) continue;
                    var (resumptionSecret, ticketSuite, ageAdd, issuedAt, maxEarly) = decoded.Value;

                    // Ticket suite must be offered by client and supported by us
                    if (Array.IndexOf(ch.CipherSuites, ticketSuite) < 0) continue;
                    if (!IsSupportedSuite(ticketSuite)) continue;
                    var elapsed = DateTime.UtcNow - issuedAt;
                    if (elapsed.TotalSeconds > 604800) continue; // max 7 days

                    // Validate obfuscated ticket age (RFC 8446 §4.2.11.1)
                    uint reportedAgeMs = ages[i] - ageAdd;
                    uint expectedAgeMs = (uint)Math.Min(elapsed.TotalMilliseconds, uint.MaxValue);
                    long ageDelta = (long)reportedAgeMs - (long)expectedAgeMs;
                    if (ageDelta < 0) ageDelta = -ageDelta;
                    if (ageDelta > 10_000) continue; // reject if age mismatch > 10 seconds

                    // resumptionSecret from ticket is already the derived PSK
                    psk = resumptionSecret;
                    var hashAlg = ticketSuite == CipherSuite.TLS_AES_256_GCM_SHA384
                        ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256;

                    // Verify binder
                    var tempKs = new KeySchedule(ticketSuite, psk);
                    byte[] binderKey = tempKs.DeriveBinderKey();

                    // Truncated transcript: CH up to the binders
                    int bindersLen = HandshakeMessages.PskBindersTailLength(binders);
                    byte[] truncatedCh = transcriptCh[..^bindersLen];
                    var binderTranscript = new TranscriptHash(hashAlg);
                    binderTranscript.Update(truncatedCh);
                    byte[] expectedBinder = HandshakeMessages.ComputePskBinder(
                        binderKey, binderTranscript.GetHash(), hashAlg);

                    if (CryptographicOperations.FixedTimeEquals(binders[i], expectedBinder))
                    {
                        isPskResumption = true;
                        selectedPskIndex = i;
                        selectedPskIsExternal = false;
                        suite = ticketSuite; // RFC 8446 §4.2.11: MUST use the PSK's original suite
                        pskMaxEarlyData = maxEarly;
                        // 0-RTT anti-replay: only accept if ticket hasn't been used before (RFC 8446 §8)
                        accept0Rtt = i == 0 && _accept0Rtt && ch.OffersEarlyData && maxEarly > 0
                            && _ticketEncryption!.TryMarkUsedForEarlyData(identities[i]);
                        break;
                    }
                }
                // Try external PSK if ticket didn't match (RFC 9258)
                else if (_externalPsk != null && identities[i].AsSpan().SequenceEqual(BuildImportedIdentity(_externalPsk).AsSpan()))
                {
                    // External PSK suite must be offered by client and supported by us
                    if (Array.IndexOf(ch.CipherSuites, _externalPsk.Suite) < 0) continue;
                    if (!IsSupportedSuite(_externalPsk.Suite)) continue;

                    // External PSK age must be 0 (RFC 9258)
                    if (ages[i] != 0) continue;

                    psk = DeriveExternalPskKey(_externalPsk);
                    var hashAlg = _externalPsk.Suite == CipherSuite.TLS_AES_256_GCM_SHA384
                        ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256;

                    // Verify binder — external PSKs use the "ext binder" label (RFC 8446 §4.2.11.2).
                    var tempKs = new KeySchedule(_externalPsk.Suite, psk);
                    byte[] binderKey = tempKs.DeriveBinderKey(external: true);

                    // Truncated transcript: CH up to the binders
                    int bindersLen = HandshakeMessages.PskBindersTailLength(binders);
                    byte[] truncatedCh = transcriptCh[..^bindersLen];
                    var binderTranscript = new TranscriptHash(hashAlg);
                    binderTranscript.Update(truncatedCh);
                    byte[] expectedBinder = HandshakeMessages.ComputePskBinder(
                        binderKey, binderTranscript.GetHash(), hashAlg);

                    if (CryptographicOperations.FixedTimeEquals(binders[i], expectedBinder))
                    {
                        suite = _externalPsk.Suite; // RFC 8446 §4.2.11: MUST use the PSK's original suite
                        selectedPskIndex = i;
                        selectedPskIsExternal = true;
                        if (ch.OffersCertWithExternPsk)
                        {
                            // draft-ietf-tls-8773bis: the client asked to combine this external PSK with a
                            // certificate. Mix the PSK into the key schedule but run a FULL cert handshake
                            // (no resumption skip, and no 0-RTT — early_data is forbidden with this ext).
                            certWithPsk = true;
                        }
                        else
                        {
                            isPskResumption = true;
                            pskMaxEarlyData = _externalPsk.MaxEarlyDataSize;
                            // 0-RTT anti-replay for external PSKs (RFC 8446 §8): an external PSK identity is
                            // long-lived, so we can't single-use the identity itself. Instead single-use the
                            // binder, which is bound to this exact ClientHello (it covers client_random) — a
                            // verbatim replay reuses the binder and is rejected, while a fresh ClientHello with
                            // the same PSK still gets 0-RTT. Requires a replay store; without one we refuse
                            // 0-RTT (fall back to 1-RTT resumption) rather than accept un-tracked early data.
                            accept0Rtt = i == 0 && _accept0Rtt && ch.OffersEarlyData && _externalPsk.MaxEarlyDataSize > 0
                                && _ticketEncryption != null
                                && _ticketEncryption.TryMarkUsedForEarlyData(binders[i]);
                        }
                        break;
                    }
                }
            }
        }

        // Select cipher suite (if PSK didn't determine it)
        if (!isPskResumption && !certWithPsk)
            suite = SelectCipherSuite(ch.CipherSuites);

        // 4. Initialize key schedule
        _keySchedule = (isPskResumption || certWithPsk) ? new KeySchedule(suite, psk) : new KeySchedule(suite);
        UsedCertWithExternalPsk = certWithPsk;
        _transcript.SetAlgorithm(_keySchedule.HashAlgorithm);

        // 5. Select key share from client's offerings
        var selectedKS = SelectKeyShare(ch.KeyShares);

        // 6. If no key share match, send HelloRetryRequest
        if (selectedKS == null || _forceHrr)
        {
            NamedGroup requestedGroup = SelectGroupForHrr(ch.SupportedGroups);

            _transcript.ReplaceWithMessageHash();

            byte[] hrrMsg = HandshakeMessages.BuildHelloRetryRequest(ch.SessionId, suite, requestedGroup, withEch: EchAccepted);
            PatchEchHrrConfirmation(hrrMsg); // ECH §7.2.1 (no-op unless ECH accepted)
            _record.WriteRecord(ContentType.Handshake, hrrMsg);
            _transcript.Update(hrrMsg);

            _record.WriteChangeCipherSpec();
            _sentCcs = true;

            byte[] ch2Msg = NextHandshake(HandshakeType.ClientHello);

            // RFC 8446 §4.2.11.2: server MUST re-verify PSK binder in CH2 after HRR
            var (_, ch2Body) = HandshakeMessages.Unframe(ch2Msg);
            var ch1 = ch; // CH1 (already swapped to the ECH inner above, if accepted)
            ch = HandshakeMessages.ParseClientHello(ch2Body);
            byte[] transcriptCh2 = ServerDecryptEch(ch2Msg, ch2Body, ref ch); // ECH: swap CH2 to its inner
            if (_enforceHrrConsistency) CheckHelloRetryConsistency(ch1, ch); // RFC 8446 §4.1.4

            _peerAllowsPostHandshakeAuth = ch.OffersPostHandshakeAuth;
            if (isPskResumption || certWithPsk)
            {
                if (ch.PreSharedKeyData == null)
                    AlertAndThrow(AlertDescription.MissingExtension,
                        "Second ClientHello after HRR omitted the selected PSK extension");
                var (_, _, binders2) = HandshakeMessages.ParsePreSharedKeyExtension(ch.PreSharedKeyData);
                if (selectedPskIndex >= 0 && selectedPskIndex < binders2.Length)
                {
                    int bindersLen2 = HandshakeMessages.PskBindersTailLength(binders2);
                    byte[] truncatedCh2 = transcriptCh2[..^bindersLen2];
                    var binderTranscript2 = _transcript.Clone();
                    binderTranscript2.Update(truncatedCh2);
                    byte[] binderKey2 = _keySchedule.DeriveBinderKey(external: selectedPskIsExternal);
                    byte[] expectedBinder2 = HandshakeMessages.ComputePskBinder(
                        binderKey2, binderTranscript2.GetHash(), _keySchedule.HashAlgorithm);

                    if (!CryptographicOperations.FixedTimeEquals(binders2[selectedPskIndex], expectedBinder2))
                    {
                        AlertAndThrow(AlertDescription.DecryptError,
                            "Second ClientHello PSK binder verification failed after HRR");
                    }
                }
                else
                {
                    AlertAndThrow(AlertDescription.IllegalParameter,
                        "Second ClientHello after HRR does not contain the selected PSK binder");
                }
            }

            _transcript.Update(transcriptCh2);

            selectedKS = FindKeyShare(ch.KeyShares, requestedGroup);
            if (selectedKS == null)
                AlertAndThrow(AlertDescription.IllegalParameter, "CH2 missing requested key share");
        }

        var (group, clientKey) = selectedKS.Value;
        _negotiatedGroup = group;

        // 7. Generate server key share and compute shared secret
        byte[] shared = ComputeServerSharedSecret(group, clientKey, out byte[] sPub);

        byte[] serverRandom = RandomnessWrapper.GetHandshakeBytes(32);
        _clientRandom = ch.ClientRandom;

        // 8. Send ServerHello (with PSK extension if resuming)
        byte[] shMsg;
        if (certWithPsk)
            // draft-ietf-tls-8773bis: echo tls_cert_with_extern_psk + the selected PSK; a full cert handshake follows.
            shMsg = HandshakeMessages.BuildServerHelloWithPsk(serverRandom, ch.SessionId, suite, group, sPub, (ushort)selectedPskIndex, certWithExternPsk: true);
        else if (isPskResumption)
            shMsg = HandshakeMessages.BuildServerHelloWithPsk(serverRandom, ch.SessionId, suite, group, sPub, (ushort)selectedPskIndex);
        else
            shMsg = HandshakeMessages.BuildServerHello(serverRandom, ch.SessionId, suite, group, sPub);
        PatchEchAcceptConfirmation(shMsg); // ECH §7.2 (no-op unless ECH accepted)
        _record.WriteRecord(ContentType.Handshake, shMsg);
        _transcript.Update(shMsg);

        // 9. Derive handshake secrets
        _keySchedule.DeriveHandshakeSecrets(shared, _transcript.GetHash());

        // Key logging
        if (KeyLogger.IsEnabled)
            KeyLogger.LogHandshakeTrafficSecrets(ch.ClientRandom,
                _keySchedule.ClientHandshakeTrafficSecret!, _keySchedule.ServerHandshakeTrafficSecret!);

        // 10. CCS for middlebox compat
        if (!_sentCcs) _record.WriteChangeCipherSpec();

        // 11. Install server handshake write cipher
        var (sKey, sIv) = _keySchedule.DeriveKeyAndIv(_keySchedule.ServerHandshakeTrafficSecret!);
        _record.SetWriteCipher(new AeadCipher(sKey, sIv, _keySchedule.Aead, _keySchedule.Suite));

        // 12. EncryptedExtensions (with ALPN and cert compression negotiation)
        string? negotiatedAlpn = NegotiateAlpn(ch.AlpnProtocols);
        _negotiatedAlpn = negotiatedAlpn;
        ushort certCompAlg = NegotiateCertCompression(ch.CertCompressionAlgorithms);
        // RFC 8449: echo a record_size_limit only if the client offered one; honor the client's limit.
        ushort rslToSend = ch.RecordSizeLimit > 0 ? (ushort)TlsConst.MaxPlaintextLength : (ushort)0;
        byte[] eeMsg = HandshakeMessages.BuildEncryptedExtensions(accept0Rtt, negotiatedAlpn, certCompAlg, rslToSend, EchServerRetryConfigs());
        _record.WriteRecord(ContentType.Handshake, eeMsg);
        _transcript.Update(eeMsg);
        ApplyPeerRecordSizeLimit(ch.RecordSizeLimit);

        if (isPskResumption)
        {
            // PSK resumption: skip Certificate/CertificateVerify, go to Finished

            // 13. Server Finished
            byte[] sfVerify = _keySchedule.ComputeFinishedVerifyData(
                _keySchedule.ServerHandshakeTrafficSecret!, _transcript.GetHash());
            byte[] sfMsg = HandshakeMessages.BuildFinished(sfVerify);
            _record.WriteRecord(ContentType.Handshake, sfMsg);
            _transcript.Update(sfMsg);

            // Store server finished for channel binding
            _serverFinishedValue = sfVerify;

            _serverFinishedHash = _transcript.GetHash();
            _keySchedule.DeriveAppSecrets(_serverFinishedHash);
        LogAppSecrets();

            // 14. Read 0-RTT early data (AFTER sending our flight to prevent deadlock)
            if (accept0Rtt)
            {
                // Derive early traffic keys from the CH-only transcript
                var earlyTranscript = new TranscriptHash(_keySchedule.HashAlgorithm);
                earlyTranscript.Update(chMsg);
                byte[] earlyTrafficSecret = _keySchedule.DeriveClientEarlyTrafficSecret(earlyTranscript.GetHash());
                if (_clientRandom != null) KeyLogger.LogEarlyTrafficSecret(_clientRandom, earlyTrafficSecret);
                var (ek, eiv) = _keySchedule.DeriveKeyAndIv(earlyTrafficSecret);
                _record.SetReadCipher(new AeadCipher(ek, eiv, _keySchedule.Aead, _keySchedule.Suite));

                // Read early data records until EndOfEarlyData
                using var earlyBuf = new MemoryStream();
                bool gotEndOfEarlyData = false;
                while (!gotEndOfEarlyData)
                {
                    var (type, payload) = _record.ReadRecord();
                    if (type == ContentType.ApplicationData)
                    {
                        if (earlyBuf.Length + payload.Length > pskMaxEarlyData)
                            AlertAndThrow(AlertDescription.UnexpectedMessage,
                                "0-RTT data exceeded max_early_data_size");
                        earlyBuf.Write(payload);
                    }
                    else if (type == ContentType.Handshake)
                    {
                        EnqueueHandshake(payload);
                        gotEndOfEarlyData = true;
                    }
                    else if (type == ContentType.ChangeCipherSpec) continue;
                    else break;
                }
                ReceivedEarlyData = earlyBuf.Length > 0 ? earlyBuf.ToArray() : null;
                EarlyDataAccepted = true;
            }

            // 15. Install client handshake read cipher
            var (cKey, cIv) = _keySchedule.DeriveKeyAndIv(_keySchedule.ClientHandshakeTrafficSecret!);
            _record.SetReadCipher(new AeadCipher(cKey, cIv, _keySchedule.Aead, _keySchedule.Suite));

            // 15b. Skip rejected 0-RTT early data via trial decryption (RFC 8446 §4.2.10)
            // When the client offered early_data but we rejected it, the client may have
            // already sent early data records (encrypted under early keys). We use trial
            // decryption with the handshake key: records that fail AEAD are early data to discard;
            // the first record that succeeds is the start of handshake messages.
            if (!accept0Rtt && ch.OffersEarlyData)
            {
                long skipped = 0;
                while (skipped < _maxEarlyDataSize + TlsConst.MaxCiphertextLength)
                {
                    var result = _record.TryReadRecord();
                    if (result == null)
                    {
                        skipped += TlsConst.MaxCiphertextLength; // conservative bound
                        continue;
                    }
                    var (type, payload) = result.Value;
                    if (type == ContentType.ChangeCipherSpec) continue;
                    if (type == ContentType.Handshake)
                    {
                        EnqueueHandshake(payload);
                    }
                    break;
                }
            }

            // 16. Receive EndOfEarlyData from buffer (already read under early keys)
            if (accept0Rtt)
            {
                byte[] eodMsg = NextHandshake(HandshakeType.EndOfEarlyData);
                _transcript.Update(eodMsg);
            }

            // 17. Receive client Finished
            byte[] cfMsg = NextHandshake(HandshakeType.Finished);
            var (_, cfBody) = HandshakeMessages.Unframe(cfMsg);

            byte[] expectedCF = _keySchedule.ComputeFinishedVerifyData(
                _keySchedule.ClientHandshakeTrafficSecret!, _transcript.GetHash());
            if (!CryptographicOperations.FixedTimeEquals(cfBody, expectedCF))
                AlertAndThrow(AlertDescription.DecryptError, "Client Finished verification failed");

            // Store client finished for channel binding
            _clientFinishedValue = expectedCF;

            _transcript.Update(cfMsg);
            byte[] fullHashPsk = _transcript.GetHash();
            _keySchedule.DeriveResumptionMasterSecret(fullHashPsk);
            InstallAppKeys();
            IsHandshakeComplete = true;
            IsResumed = true;

            { int ticketCount = EffectiveTicketCount(ch); if (ticketCount > 0) SendNewSessionTicket((ushort)ticketCount); }
            return;
        }

        // 14. CertificateRequest (if mTLS)
        if (_requireClientCert)
        {
            byte[] crMsg = HandshakeMessages.BuildCertificateRequest(Array.Empty<byte>(), _offeredSigAlgs ?? AdvertisedSigAlgs,
                certCompAlgs: _useCertCompression ? CertCompAdvertise : null);
            _record.WriteRecord(ContentType.Handshake, crMsg);
            _transcript.Update(crMsg);
        }

        // RFC 8446 §4.2.3: the server's signature scheme must be one the client advertised.
        ValidateServerCertSigAlg(ch);

        // 15. Certificate (with chain, optionally compressed, optionally OCSP-stapled)
        byte[]? stapleResponse = (ch.RequestsOcspStapling && _ocspResponse != null) ? _ocspResponse : null;
        byte[] certMsg = HandshakeMessages.BuildCertificate(_certificate.DerData, _certificate.ChainCertificates, stapleResponse);
        if (certCompAlg != 0)
        {
            byte[] compMsg = HandshakeMessages.BuildCompressedCertificate(certMsg, certCompAlg);
            _record.WriteRecord(ContentType.Handshake, compMsg);
            _transcript.Update(compMsg);
        }
        else
        {
            _record.WriteRecord(ContentType.Handshake, certMsg);
            _transcript.Update(certMsg);
        }

        // 16. CertificateVerify
        byte[] cvContent = HandshakeMessages.BuildCertVerifyContent(
            "TLS 1.3, server CertificateVerify", _transcript.GetHash());
        byte[] cvSig = CertificateUtils.Sign(cvContent,
            _certificate.PrivateKey, _certificate.PublicKey, _certificate.SignatureAlgorithm);
        byte[] cvMsg = HandshakeMessages.BuildCertificateVerify(_certificate.SignatureAlgorithm, cvSig);
        _record.WriteRecord(ContentType.Handshake, cvMsg);
        _transcript.Update(cvMsg);

        // 17. Server Finished
        byte[] sfVerify2 = _keySchedule.ComputeFinishedVerifyData(
            _keySchedule.ServerHandshakeTrafficSecret!, _transcript.GetHash());
        byte[] sfMsg2 = HandshakeMessages.BuildFinished(sfVerify2);
        _record.WriteRecord(ContentType.Handshake, sfMsg2);
        _transcript.Update(sfMsg2);

        // Store server finished for channel binding
        _serverFinishedValue = sfVerify2;

        // 18. Derive application secrets
        _serverFinishedHash = _transcript.GetHash();
        _keySchedule.DeriveAppSecrets(_serverFinishedHash);
        LogAppSecrets();

        // 19. Install client handshake read cipher
        var (cKey2, cIv2) = _keySchedule.DeriveKeyAndIv(_keySchedule.ClientHandshakeTrafficSecret!);
        _record.SetReadCipher(new AeadCipher(cKey2, cIv2, _keySchedule.Aead, _keySchedule.Suite));

        // 20. If mTLS: receive client Certificate [+ CertificateVerify]
        if (_requireClientCert)
        {
            byte[] clientCertMsg = NextHandshakeAny(out HandshakeType clientCertType);
            if (clientCertType != HandshakeType.Certificate && clientCertType != HandshakeType.CompressedCertificate)
                AlertAndThrow(AlertDescription.UnexpectedMessage, $"Expected client Certificate, got {clientCertType}");
            _transcript.Update(clientCertMsg);
            var (_, clientCertRaw) = HandshakeMessages.Unframe(clientCertMsg);
            if (clientCertType == HandshakeType.CompressedCertificate)
            {
                if (clientCertRaw.Length < 2)
                    AlertAndThrow(AlertDescription.DecodeError, "CompressedCertificate missing algorithm");
                ushort clientCompAlg = BinaryHelper.ReadUInt16(clientCertRaw.AsSpan(0));
                if (!_useCertCompression || Array.IndexOf(CertCompAdvertise, clientCompAlg) < 0)
                    AlertAndThrow(AlertDescription.BadCertificate,
                        $"Client used an unadvertised certificate compression algorithm: {clientCompAlg}");
            }
            byte[] clientCertBody = clientCertType == HandshakeType.CompressedCertificate
                ? HandshakeMessages.ParseCompressedCertificate(clientCertRaw)  // RFC 8879 → Certificate body
                : clientCertRaw;
            var (clientCertContext, clientCertEntries) = HandshakeMessages.ParseCertificateEx(clientCertBody);
            ValidateCertificateContext(clientCertContext, Array.Empty<byte>(),
                "Initial client Certificate certificate_request_context must be empty");

            if (clientCertEntries.Count > 0)
            {
                byte[] clientCertDer = clientCertEntries[0].CertDer;
                PeerCertificateData = clientCertDer;

                if (_caCertificate != null)
                {
                    var clientCertObj = new TlsCertificate
                    {
                        DerData = clientCertDer,
                        PrivateKey = Array.Empty<byte>(),
                        PublicKey = Array.Empty<byte>(),
                        SignatureAlgorithm = SignatureScheme.EcdsaSecp256r1Sha256
                    };
                    byte[][] clientIntermediates = new byte[clientCertEntries.Count - 1][];
                    for (int ci = 1; ci < clientCertEntries.Count; ci++)
                        clientIntermediates[ci - 1] = clientCertEntries[ci].CertDer;
                    if (!CertificateUtils.VerifyChain(clientCertObj, clientIntermediates, _caCertificate))
                        AlertAndThrow(AlertDescription.BadCertificate,
                            "Client certificate not signed by trusted CA");
                }

                byte[] preCvHash = _transcript.GetHash();
                byte[] clientCvMsg = NextHandshake(HandshakeType.CertificateVerify);
                var (_, clientCvBody) = HandshakeMessages.Unframe(clientCvMsg);
                var (clientSigScheme, clientSig) = HandshakeMessages.ParseCertificateVerify(clientCvBody);
                ValidateSignatureScheme(clientSigScheme);

                var (clientPubKey, _) = CertificateUtils.ParseCertificatePublicKey(clientCertDer);
                byte[] clientCvContent = HandshakeMessages.BuildCertVerifyContent(
                    "TLS 1.3, client CertificateVerify", preCvHash);
                if (!CertificateUtils.Verify(clientCvContent, clientSig, clientPubKey, clientSigScheme))
                    AlertAndThrow(AlertDescription.DecryptError, "Client CertificateVerify failed");

                _transcript.Update(clientCvMsg);
            }
            else
            {
                AlertAndThrow(AlertDescription.CertificateRequired,
                    "Client certificate required but not provided");
            }
        }

        // 21. Receive client Finished
        byte[] cfMsg2 = NextHandshake(HandshakeType.Finished);
        var (_, cfBody2) = HandshakeMessages.Unframe(cfMsg2);

        byte[] expectedCF2 = _keySchedule.ComputeFinishedVerifyData(
            _keySchedule.ClientHandshakeTrafficSecret!, _transcript.GetHash());
        if (!CryptographicOperations.FixedTimeEquals(cfBody2, expectedCF2))
            AlertAndThrow(AlertDescription.DecryptError, "Client Finished verification failed");

        // Store client finished for channel binding
        _clientFinishedValue = expectedCF2;

        _transcript.Update(cfMsg2);

        // 22. Derive resumption master secret + switch to app keys
        byte[] fullHashFull = _transcript.GetHash();
        _keySchedule.DeriveResumptionMasterSecret(fullHashFull);
        InstallAppKeys();
        IsHandshakeComplete = true;

        { int ticketCount = EffectiveTicketCount(ch); if (ticketCount > 0) SendNewSessionTicket((ushort)ticketCount); }
    }

    // ================================================================
    //  Post-Handshake Client Authentication (RFC 8446 §4.6.2)
    // ================================================================

    /// <summary>Server: request client authentication post-handshake.</summary>
    public void RequestPostHandshakeAuth()
    {
        if (!_isServer || !IsHandshakeComplete)
            throw new InvalidOperationException("Only server can request post-handshake auth after handshake");
        if (!_peerAllowsPostHandshakeAuth)
            throw new InvalidOperationException("Peer did not advertise post_handshake_auth");
        if (_postHsAuthState != PostHsAuthState.None)
            throw new InvalidOperationException("A post-handshake auth flow is already in progress");

        _writeLock.Wait();
        try
        {
            byte[] context = RandomnessWrapper.GetBytes(16);
            _pendingPostHsContext = context;
            byte[] crMsg = HandshakeMessages.BuildCertificateRequest(context, _offeredSigAlgs ?? AdvertisedSigAlgs);
            _record.WriteRecord(ContentType.Handshake, crMsg);
            _postHsAuthState = PostHsAuthState.AwaitingCertificate;
        }
        finally { _writeLock.Release(); }
    }

    // ================================================================
    //  Session Ticket (server sends after handshake)
    // ================================================================

    private void SendNewSessionTicket(ushort count = 1)
    {
        if (_ticketEncryption == null || _keySchedule?.ResumptionMasterSecret == null) return;

        for (int i = 0; i < count; i++)
        {
            byte[] nonce = RandomnessWrapper.GetBytes(8);
            byte[] ticketPsk = _keySchedule.DerivePsk(nonce);

            uint lifetime = 86400; // 24 hours
            uint ageAdd = BitConverter.ToUInt32(RandomnessWrapper.GetBytes(4));

            byte[] plaintext = TicketEncryption.EncodeTicketState(
                ticketPsk, _keySchedule.Suite, ageAdd, DateTime.UtcNow, _maxEarlyDataSize);
            byte[] ticket = _ticketEncryption.Seal(plaintext);

            byte[] nstMsg = HandshakeMessages.BuildNewSessionTicket(lifetime, ageAdd, nonce, ticket, _maxEarlyDataSize);
            _writeLock.Wait();
            try { _record.WriteRecord(ContentType.Handshake, nstMsg); }
            finally { _writeLock.Release(); }
        }
    }

    // ================================================================
    //  Application data
    // ================================================================

    /// <summary>Read decrypted application data into buffer. Returns bytes read (0 = EOF from close_notify).</summary>
    public int Read(byte[] buffer, int offset, int count)
    {
        if (_closed) return 0;

        // Drain any leftover plaintext stashed by a previous Read that returned less
        // than a full record. _readBuf here is a fresh byte[] holding the *remainder*
        // (the lease itself was already released when the remainder was copied out).
        if (_readOff < _readBuf.Length)
        {
            int avail = _readBuf.Length - _readOff;
            int n = Math.Min(avail, count);
            Buffer.BlockCopy(_readBuf, _readOff, buffer, offset, n);
            _readOff += n;
            if (_readOff >= _readBuf.Length) { _readBuf = Array.Empty<byte>(); _readOff = 0; }
            return n;
        }

        // Loop until we get an ApplicationData record (Alert/CCS/post-handshake messages
        // are processed inline and we keep reading). The new ReadRecordInto path decrypts
        // straight into the caller's buffer when the record fits — that's the bulk-path
        // win that drops per-record allocations to near zero.
        while (true)
        {
            if (_closed) return 0;

            var result = _record.ReadRecordInto(buffer.AsSpan(offset, count));
            try
            {
                if (result.Type == ContentType.ApplicationData)
                {
                    if (result.LeasedBuffer == null)
                    {
                        // Direct path: data is already in the caller's buffer.
                        return result.Length;
                    }
                    // Overflow path: caller's buffer was smaller than the record.
                    // Copy what fits, stash the remainder in _readBuf as a fresh byte[]
                    // (the lease itself goes back to the pool in finally below).
                    int copy = Math.Min(result.Length, count);
                    Buffer.BlockCopy(result.LeasedBuffer, 0, buffer, offset, copy);
                    if (copy < result.Length)
                    {
                        int rem = result.Length - copy;
                        var stash = new byte[rem];
                        Buffer.BlockCopy(result.LeasedBuffer, copy, stash, 0, rem);
                        _readBuf = stash;
                        _readOff = 0;
                    }
                    return copy;
                }

                // Non-ApplicationData (rare): payload is in destination if LeasedBuffer
                // is null, otherwise in the lease. View as a span either way.
                ReadOnlySpan<byte> payload = result.LeasedBuffer == null
                    ? buffer.AsSpan(offset, result.Length)
                    : new ReadOnlySpan<byte>(result.LeasedBuffer, 0, result.Length);

                if (result.Type == ContentType.Alert)
                {
                    HandleAlert(payload);
                    if (_closed) return 0;
                    continue;
                }
                if (result.Type == ContentType.Handshake)
                {
                    // Post-handshake message handlers (KeyUpdate / NewSessionTicket / etc.)
                    // still expect byte[] because SplitMessages returns List<byte[]>.
                    // Materialise — this path is rare and the cost is bounded.
                    HandlePostHandshakeMessages(payload.ToArray());
                    continue;
                }
                if (result.Type == ContentType.ChangeCipherSpec)
                {
                    // Middlebox-compat record; ignore and loop.
                    continue;
                }
                // Unknown type — keep behaviour of legacy ReadAppData (silently loops).
            }
            finally
            {
                if (result.LeasedBuffer != null)
                {
                    Array.Clear(result.LeasedBuffer, 0, result.Length);
                    ArrayPool<byte>.Shared.Return(result.LeasedBuffer);
                }
            }
        }
    }

    /// <summary>Read a complete application-data record.</summary>
    public byte[] ReadAll()
    {
        if (_closed) return Array.Empty<byte>();

        if (_readOff < _readBuf.Length)
        {
            byte[] rem = _readBuf[_readOff..];
            _readBuf = Array.Empty<byte>();
            _readOff = 0;
            return rem;
        }
        return ReadAppData();
    }

    /// <summary>Write application data (fragments automatically at 16 KiB). Thread-safe.</summary>
    public void Write(byte[] data, int offset, int count)
    {
        _writeLock.Wait();
        try
        {
            int pos = offset;
            int end = offset + count;
            while (pos < end)
            {
                int chunk = Math.Min(end - pos, TlsConst.MaxPlaintextLength);
                // AsSpan instead of Range slice — saves ~chunk bytes/record on the bulk
                // path (was the biggest unfixed allocation in TlsConnection.Write).
                _record.WriteRecord(ContentType.ApplicationData, data.AsSpan(pos, chunk));
                pos += chunk;

                // RFC 8446 §5.5: automatically initiate KeyUpdate as we approach the
                // per-key usage limit. Only meaningful once the handshake is complete.
                if (IsHandshakeComplete && _record.WriteCipherNeedsKeyUpdate)
                    RotateOwnWriteKeyLocked(requestUpdate: false);
            }
        }
        finally { _writeLock.Release(); }
    }

    public void SendAlert(AlertLevel level, AlertDescription desc)
    {
        _writeLock.Wait();
        try { _record.WriteRecord(ContentType.Alert, new[] { (byte)level, (byte)desc }); }
        catch { /* best-effort on close */ }
        finally { _writeLock.Release(); }
    }

    /// <summary>Send a KeyUpdate message and rotate our write key. Thread-safe.</summary>
    public void SendKeyUpdate(bool requestUpdate)
    {
        _writeLock.Wait();
        try { RotateOwnWriteKeyLocked(requestUpdate); }
        finally { _writeLock.Release(); }
    }

    /// <summary>Send KeyUpdate + rotate our own write key. Caller MUST hold _writeLock.</summary>
    private void RotateOwnWriteKeyLocked(bool requestUpdate)
    {
        byte[] kuMsg = HandshakeMessages.BuildKeyUpdate(requestUpdate);
        _record.WriteRecord(ContentType.Handshake, kuMsg);

        if (_isServer)
        {
            _keySchedule!.UpdateServerAppTrafficSecret();
            var (k, iv) = _keySchedule.DeriveKeyAndIv(_keySchedule.ServerAppTrafficSecret!);
            _record.SetWriteCipher(new AeadCipher(k, iv, _keySchedule.Aead, _keySchedule.Suite));
        }
        else
        {
            _keySchedule!.UpdateClientAppTrafficSecret();
            var (k, iv) = _keySchedule.DeriveKeyAndIv(_keySchedule.ClientAppTrafficSecret!);
            _record.SetWriteCipher(new AeadCipher(k, iv, _keySchedule.Aead, _keySchedule.Suite));
        }
    }

    // ================================================================
    //  Internal helpers
    // ================================================================

    private byte[] ReadAppData()
    {
        while (true)
        {
            if (_closed) return Array.Empty<byte>();

            var (type, payload) = _record.ReadRecord();

            if (type == ContentType.ApplicationData) return payload;

            if (type == ContentType.Alert)
            {
                HandleAlert(payload);
                if (_closed) return Array.Empty<byte>();
                continue;
            }

            if (type == ContentType.Handshake)
            {
                HandlePostHandshakeMessages(payload);
                continue;
            }
        }
    }

    // Carry-over for a post-handshake handshake message fragmented across application-data records.
    private byte[] _postHsPartial = Array.Empty<byte>();

    private void HandlePostHandshakeMessages(byte[] payload)
    {
        // RFC 8446 §5.1: a post-handshake handshake message (a large NewSessionTicket, or a
        // post-handshake Certificate chain) MAY be fragmented across several records. Accumulate across
        // records, dispatch only complete length-prefixed messages, and retain any incomplete tail —
        // mirrors EnqueueHandshake on the main handshake path (which previously was the only reassembled
        // path; per-record SplitMessages here silently dropped a fragmented tail).
        byte[] buf;
        if (_postHsPartial.Length == 0)
        {
            buf = payload;
        }
        else
        {
            buf = new byte[_postHsPartial.Length + payload.Length];
            Buffer.BlockCopy(_postHsPartial, 0, buf, 0, _postHsPartial.Length);
            Buffer.BlockCopy(payload, 0, buf, _postHsPartial.Length, payload.Length);
        }

        int p = 0;
        while (p + 4 <= buf.Length)
        {
            uint len = BinaryHelper.ReadUInt24(buf.AsSpan(p + 1));
            long total = 4L + len;
            if (total > MaxHandshakeMessageLength)
                throw new TlsException(AlertDescription.DecodeError,
                    $"Post-handshake message length {len} exceeds reassembly limit");
            if (p + total > buf.Length) break; // incomplete tail — wait for more records
            byte[] m = buf[p..(p + (int)total)];
            p += (int)total;

            var (hsType, body) = HandshakeMessages.Unframe(m);
            switch (hsType)
            {
                case HandshakeType.KeyUpdate:
                    HandleKeyUpdate(body);
                    break;
                case HandshakeType.NewSessionTicket:
                    HandleNewSessionTicket(body);
                    break;
                case HandshakeType.CertificateRequest:
                    HandlePostHandshakeCertRequest(body);
                    break;
                case HandshakeType.Certificate:
                    HandlePostHandshakeCert(m);
                    break;
                case HandshakeType.CertificateVerify:
                    HandlePostHandshakeCertVerify(m);
                    break;
                case HandshakeType.Finished:
                    HandlePostHandshakeFinished(body);
                    break;
                default:
                    AlertAndThrow(AlertDescription.UnexpectedMessage,
                        $"Unexpected post-handshake message: {hsType}");
                    break;
            }
        }
        _postHsPartial = p == buf.Length ? Array.Empty<byte>() : buf[p..];
    }

    // Session ticket handling (client side)
    private Action<SessionTicket>? _onNewTicket;
    internal void SetNewTicketCallback(Action<SessionTicket> cb) => _onNewTicket = cb;

    private void HandleNewSessionTicket(byte[] body)
    {
        if (_isServer) return;
        var nst = HandshakeMessages.ParseNewSessionTicket(body);
        if (_onNewTicket != null && _keySchedule?.ResumptionMasterSecret != null)
        {
            // Derive the per-ticket PSK
            byte[] ticketPsk = _keySchedule.DerivePsk(nst.Nonce);
            var ticket = new SessionTicket
            {
                Ticket = nst.Ticket,
                ResumptionSecret = ticketPsk,
                CipherSuite = _keySchedule.Suite,
                IssuedAt = DateTime.UtcNow,
                // RFC 8446 §4.6.1: a client MUST NOT cache a ticket for longer than 7 days,
                // regardless of the lifetime the server advertises — clamp on intake.
                LifetimeSeconds = Math.Min(nst.Lifetime, 604800),
                AgeAdd = nst.AgeAdd,
                MaxEarlyDataSize = nst.MaxEarlyDataSize
            };
            _onNewTicket(ticket);
        }
    }

    // Post-handshake client auth — client side
    private void HandlePostHandshakeCertRequest(byte[] body)
    {
        if (_isServer) return;
        if (!_offerPostHandshakeAuth)
            AlertAndThrow(AlertDescription.UnexpectedMessage,
                "Received post-handshake CertificateRequest without negotiating post_handshake_auth");
        var (ctx, sigAlgs, _) = HandshakeMessages.ParseCertificateRequest(body);

        // Post-handshake auth signs over the *continued* handshake transcript (RFC 8446 §4.4):
        // the full CH..client-Finished transcript, then CertificateRequest, Certificate,
        // CertificateVerify. The message_hash(254) synthetic is only the HRR CH1 rewrite (§4.4.1),
        // not this — so clone the live transcript and keep appending to it.
        var phTranscript = _transcript.Clone();
        byte[] crMsg = HandshakeMessages.Frame(HandshakeType.CertificateRequest, body);
        phTranscript.Update(crMsg);

        if (_certificate != null)
        {
            ValidateClientCertificateSignatureScheme(sigAlgs, _certificate.SignatureAlgorithm);
            byte[] certMsg = HandshakeMessages.BuildCertificateMsg(
                _certificate.DerData, ctx, _certificate.ChainCertificates);
            _record.WriteRecord(ContentType.Handshake, certMsg);
            phTranscript.Update(certMsg);

            byte[] cvContent = HandshakeMessages.BuildCertVerifyContent(
                "TLS 1.3, client CertificateVerify", phTranscript.GetHash());
            byte[] cvSig = CertificateUtils.Sign(cvContent,
                _certificate.PrivateKey, _certificate.PublicKey, _certificate.SignatureAlgorithm);
            byte[] cvMsg = HandshakeMessages.BuildCertificateVerify(_certificate.SignatureAlgorithm, cvSig);
            _record.WriteRecord(ContentType.Handshake, cvMsg);
            phTranscript.Update(cvMsg);

            byte[] finVerify = _keySchedule!.ComputeFinishedVerifyData(
                _keySchedule.ClientAppTrafficSecret!, phTranscript.GetHash());
            _record.WriteRecord(ContentType.Handshake, HandshakeMessages.BuildFinished(finVerify));
        }
        else
        {
            byte[] emptyCert = HandshakeMessages.BuildCertificateMsg(null, ctx);
            _record.WriteRecord(ContentType.Handshake, emptyCert);
            phTranscript.Update(emptyCert);

            byte[] finVerify = _keySchedule!.ComputeFinishedVerifyData(
                _keySchedule.ClientAppTrafficSecret!, phTranscript.GetHash());
            _record.WriteRecord(ContentType.Handshake, HandshakeMessages.BuildFinished(finVerify));
        }
    }

    // Post-handshake client auth — server side (collecting responses)
    private TranscriptHash? _postHsTranscript;
    private byte[]? _postHsCertDer;

    private void HandlePostHandshakeCert(byte[] fullMsg)
    {
        if (!_isServer)
            AlertAndThrow(AlertDescription.UnexpectedMessage, "Client received unexpected post-handshake Certificate");
        if (_postHsAuthState != PostHsAuthState.AwaitingCertificate)
            AlertAndThrow(AlertDescription.UnexpectedMessage, "Unexpected post-handshake Certificate");

        // Continue the live CH..client-Finished transcript (RFC 8446 §4.4): CertificateRequest then
        // the peer's Certificate. (message_hash(254) is only the HRR CH1 rewrite, not used here.)
        _postHsTranscript = _transcript.Clone();
        byte[] crMsg = HandshakeMessages.BuildCertificateRequest(_pendingPostHsContext!, _offeredSigAlgs ?? AdvertisedSigAlgs);
        _postHsTranscript.Update(crMsg);
        _postHsTranscript.Update(fullMsg);

        var (_, certBody) = HandshakeMessages.Unframe(fullMsg);
        var (certContext, certEntries) = HandshakeMessages.ParseCertificateEx(certBody);
        ValidateCertificateContext(certContext, _pendingPostHsContext!,
            "Post-handshake client Certificate context does not match CertificateRequest");
        _postHsCertDer = certEntries.Count > 0 ? certEntries[0].CertDer : null;

        // Verify against CA if available
        if (_postHsCertDer != null && _caCertificate != null)
        {
            var clientCertObj = new TlsCertificate
            {
                DerData = _postHsCertDer,
                PrivateKey = Array.Empty<byte>(),
                PublicKey = Array.Empty<byte>(),
                SignatureAlgorithm = SignatureScheme.EcdsaSecp256r1Sha256
            };
            byte[][] phaIntermediates = new byte[certEntries.Count - 1][];
            for (int ci = 1; ci < certEntries.Count; ci++)
                phaIntermediates[ci - 1] = certEntries[ci].CertDer;
            if (!CertificateUtils.VerifyChain(clientCertObj, phaIntermediates, _caCertificate))
                AlertAndThrow(AlertDescription.BadCertificate, "Post-handshake client cert not signed by trusted CA");
        }

        _postHsAuthState = _postHsCertDer != null
            ? PostHsAuthState.AwaitingCertificateVerify
            : PostHsAuthState.AwaitingFinished;
    }

    private void HandlePostHandshakeCertVerify(byte[] fullMsg)
    {
        if (_postHsAuthState != PostHsAuthState.AwaitingCertificateVerify)
            AlertAndThrow(AlertDescription.UnexpectedMessage, "Unexpected post-handshake CertificateVerify");

        byte[] preHash = _postHsTranscript!.GetHash();
        var (_, cvBody) = HandshakeMessages.Unframe(fullMsg);
        var (scheme, sig) = HandshakeMessages.ParseCertificateVerify(cvBody);
        ValidateSignatureScheme(scheme);

        var (pubKey, _) = CertificateUtils.ParseCertificatePublicKey(_postHsCertDer!);
        byte[] cvContent = HandshakeMessages.BuildCertVerifyContent("TLS 1.3, client CertificateVerify", preHash);
        if (!CertificateUtils.Verify(cvContent, sig, pubKey, scheme))
            AlertAndThrow(AlertDescription.DecryptError, "Post-handshake CertificateVerify failed");

        _postHsTranscript.Update(fullMsg);
        PeerCertificateData = _postHsCertDer;
        ValidatePeerCertificate(_postHsCertDer!, null);

        _postHsAuthState = PostHsAuthState.AwaitingFinished;
    }

    private void HandlePostHandshakeFinished(byte[] body)
    {
        if (_postHsAuthState != PostHsAuthState.AwaitingFinished)
            AlertAndThrow(AlertDescription.UnexpectedMessage, "Unexpected post-handshake Finished");

        byte[] expected = _keySchedule!.ComputeFinishedVerifyData(
            _keySchedule.ClientAppTrafficSecret!, _postHsTranscript!.GetHash());
        if (!CryptographicOperations.FixedTimeEquals(body, expected))
            AlertAndThrow(AlertDescription.DecryptError, "Post-handshake Finished failed");

        _postHsAuthState = PostHsAuthState.None;
        _pendingPostHsContext = null;
        _postHsTranscript = null;
        _postHsCertDer = null;
    }

    private void HandleKeyUpdate(byte[] body)
    {
        bool updateRequested = HandshakeMessages.ParseKeyUpdate(body);

        if (_isServer)
        {
            _keySchedule!.UpdateClientAppTrafficSecret();
            var (k, iv) = _keySchedule.DeriveKeyAndIv(_keySchedule.ClientAppTrafficSecret!);
            _record.SetReadCipher(new AeadCipher(k, iv, _keySchedule.Aead, _keySchedule.Suite));
        }
        else
        {
            _keySchedule!.UpdateServerAppTrafficSecret();
            var (k, iv) = _keySchedule.DeriveKeyAndIv(_keySchedule.ServerAppTrafficSecret!);
            _record.SetReadCipher(new AeadCipher(k, iv, _keySchedule.Aead, _keySchedule.Suite));
        }

        if (updateRequested) SendKeyUpdate(false);
    }

    private byte[] NextHandshake(HandshakeType expected)
    {
        while (_hsBuffer.Count == 0)
        {
            var (type, payload) = _record.ReadRecord();
            if (type == ContentType.ChangeCipherSpec) continue;
            if (type == ContentType.Alert)
            {
                HandleAlert(payload);
                if (_closed)
                    throw new TlsException(AlertDescription.CloseNotify, "Connection closed during handshake");
                continue;
            }
            if (type != ContentType.Handshake)
                throw new TlsException(AlertDescription.UnexpectedMessage, $"Expected Handshake, got {type}");

            EnqueueHandshake(payload);
        }

        byte[] msg = _hsBuffer.Dequeue();
        var (hsType, _) = HandshakeMessages.Unframe(msg);
        if (hsType != expected)
            throw new TlsException(AlertDescription.UnexpectedMessage, $"Expected {expected}, got {hsType}");
        return msg;
    }

    private byte[] NextHandshakeAny(out HandshakeType hsType)
    {
        while (_hsBuffer.Count == 0)
        {
            var (type, payload) = _record.ReadRecord();
            if (type == ContentType.ChangeCipherSpec) continue;
            if (type == ContentType.Alert)
            {
                HandleAlert(payload);
                if (_closed)
                    throw new TlsException(AlertDescription.CloseNotify, "Connection closed during handshake");
                continue;
            }
            if (type != ContentType.Handshake)
                throw new TlsException(AlertDescription.UnexpectedMessage, $"Expected Handshake, got {type}");

            EnqueueHandshake(payload);
        }

        byte[] msg = _hsBuffer.Dequeue();
        (hsType, _) = HandshakeMessages.Unframe(msg);
        return msg;
    }

    // Append a Handshake-record payload to the reassembly buffer, then peel off every complete
    // length-prefixed handshake message into _hsBuffer. RFC 8446 §5.1: a single message may be
    // fragmented across records, and several messages may be coalesced into one record. Any
    // incomplete trailing message is retained in _hsPartial until the next record arrives.
    private void EnqueueHandshake(byte[] payload)
    {
        byte[] buf;
        if (_hsPartial.Length == 0)
        {
            buf = payload;
        }
        else
        {
            buf = new byte[_hsPartial.Length + payload.Length];
            Buffer.BlockCopy(_hsPartial, 0, buf, 0, _hsPartial.Length);
            Buffer.BlockCopy(payload, 0, buf, _hsPartial.Length, payload.Length);
        }

        int p = 0;
        while (p + 4 <= buf.Length)
        {
            uint len = BinaryHelper.ReadUInt24(buf.AsSpan(p + 1));
            long total = 4L + len;
            if (total > MaxHandshakeMessageLength)
                throw new TlsException(AlertDescription.DecodeError,
                    $"Handshake message length {len} exceeds reassembly limit");
            if (p + total > buf.Length) break; // incomplete tail — wait for more records
            _hsBuffer.Enqueue(buf[p..(p + (int)total)]);
            p += (int)total;
        }
        _hsPartial = p == buf.Length ? Array.Empty<byte>() : buf[p..];
    }

    private void InstallAppKeys()
    {
        var (sk, si) = _keySchedule!.DeriveKeyAndIv(_keySchedule.ServerAppTrafficSecret!);
        var (ck, ci) = _keySchedule.DeriveKeyAndIv(_keySchedule.ClientAppTrafficSecret!);
        var aead = _keySchedule.Aead;

        var suite = _keySchedule.Suite;
        if (_isServer)
        {
            _record.SetWriteCipher(new AeadCipher(sk, si, aead, suite));
            _record.SetReadCipher(new AeadCipher(ck, ci, aead, suite));
        }
        else
        {
            _record.SetReadCipher(new AeadCipher(sk, si, aead, suite));
            _record.SetWriteCipher(new AeadCipher(ck, ci, aead, suite));
        }
    }

    /// <summary>Client-side shared secret computation supporting all groups including hybrid ML-KEM.</summary>
    private byte[] ComputeClientSharedSecret(
        NamedGroup group, byte[] peerKey,
        byte[] x25519Priv, byte[] x25519Pub,
        byte[] p256Priv, byte[] p256Pub,
        byte[] p384Priv, byte[] p384Pub,
        byte[] x448Priv, byte[] mlkemDk)
    {
        string? gostOid = GostGroupCurveOid(group);
        if (gostOid != null)
        {
            if (_gostKexPriv == null)
                throw new TlsException(AlertDescription.IllegalParameter, $"No GOST ephemeral for group: {group}");
            return GostEcdh.ComputeSharedSecret(_gostKexPriv, peerKey, gostOid);
        }
        if (group == NamedGroup.Curvesm2)
        {
            if (_sm2KexPriv == null)
                throw new TlsException(AlertDescription.IllegalParameter, "No SM2 ephemeral for curveSM2");
            return ChineseCrypto.SM2.EcdhSharedSecret(_sm2KexPriv, peerKey);
        }
        return group switch
        {
            NamedGroup.X25519 => X25519.SharedSecret(x25519Priv, peerKey),
            NamedGroup.X448 => X448.SharedSecret(x448Priv, peerKey),
            NamedGroup.Secp256r1 => EcdhP256.SharedSecret(p256Priv, p256Pub, peerKey),
            NamedGroup.Secp384r1 => EcdhP384.SharedSecret(p384Priv, p384Pub, peerKey),
            NamedGroup.X25519MLKEM768 => ComputeHybridSharedSecret(peerKey, x25519Priv, mlkemDk),
            NamedGroup.SecP256r1MLKEM768 => ComputeHybridP256SharedSecret(peerKey, p256Priv, p256Pub, _mlkemDkSecp256),
            NamedGroup.SecP384r1MLKEM1024 => ComputeHybridP384SharedSecret(peerKey, p384Priv, p384Pub, _mlkemDkSecp384),
            _ => throw new TlsException(AlertDescription.IllegalParameter, $"Unsupported key share group: {group}")
        };
    }

    /// <summary>SecP256r1MLKEM768 client shared secret: ECDHE(x-coord) ‖ ML-KEM SS (ECDH first, draft §4.3).
    /// Server share = secp256r1 point (65) ‖ ML-KEM ciphertext (1088).</summary>
    private static byte[] ComputeHybridP256SharedSecret(byte[] serverShare, byte[] p256Priv, byte[] p256Pub, byte[] mlkemDk)
    {
        if (serverShare.Length != 65 + 1088)
            throw new TlsException(AlertDescription.DecodeError, "SecP256r1MLKEM768 server share must be 1153 bytes");
        byte[] serverP256 = serverShare[..65];
        byte[] mlkemCiphertext = serverShare[65..];

        byte[] ecdhShared = EcdhP256.SharedSecret(p256Priv, p256Pub, serverP256); // 32-byte x-coordinate
        byte[] mlkemShared = MlKem768.Decaps(mlkemDk, mlkemCiphertext);

        byte[] combined = new byte[ecdhShared.Length + mlkemShared.Length];
        Buffer.BlockCopy(ecdhShared, 0, combined, 0, ecdhShared.Length);
        Buffer.BlockCopy(mlkemShared, 0, combined, ecdhShared.Length, mlkemShared.Length);
        return combined;
    }

    /// <summary>SecP384r1MLKEM1024 client shared secret: ECDHE(x-coord, 48B) ‖ ML-KEM-1024 SS (ECDH first).
    /// Server share = secp384r1 point (97) ‖ ML-KEM-1024 ciphertext (1568).</summary>
    private static byte[] ComputeHybridP384SharedSecret(byte[] serverShare, byte[] p384Priv, byte[] p384Pub, byte[] mlkemDk)
    {
        if (serverShare.Length != 97 + 1568)
            throw new TlsException(AlertDescription.DecodeError, "SecP384r1MLKEM1024 server share must be 1665 bytes");
        byte[] serverP384 = serverShare[..97];
        byte[] mlkemCiphertext = serverShare[97..];

        byte[] ecdhShared = EcdhP384.SharedSecret(p384Priv, p384Pub, serverP384); // 48-byte x-coordinate
        byte[] mlkemShared = MlKem1024.Decaps(mlkemDk, mlkemCiphertext);

        byte[] combined = new byte[ecdhShared.Length + mlkemShared.Length];
        Buffer.BlockCopy(ecdhShared, 0, combined, 0, ecdhShared.Length);
        Buffer.BlockCopy(mlkemShared, 0, combined, ecdhShared.Length, mlkemShared.Length);
        return combined;
    }

    /// <summary>Compute hybrid shared secret: ML-KEM shared secret ‖ X25519 shared secret.</summary>
    private static byte[] ComputeHybridSharedSecret(byte[] serverShare, byte[] x25519Priv, byte[] mlkemDk)
    {
        // Server share format: ML-KEM ciphertext (1088) + X25519 public (32) (per draft-ietf-tls-ecdhe-mlkem)
        if (serverShare.Length < 1088 + 32)
            throw new TlsException(AlertDescription.DecodeError, "Hybrid key share too short");
        byte[] mlkemCiphertext = serverShare[..1088];
        byte[] serverX25519 = serverShare[1088..];

        byte[] x25519Shared = X25519.SharedSecret(x25519Priv, serverX25519);
        byte[] mlkemShared = MlKem768.Decaps(mlkemDk, mlkemCiphertext);

        // Concatenate: ML-KEM SS ‖ X25519 SS
        byte[] combined = new byte[mlkemShared.Length + x25519Shared.Length];
        Buffer.BlockCopy(mlkemShared, 0, combined, 0, mlkemShared.Length);
        Buffer.BlockCopy(x25519Shared, 0, combined, mlkemShared.Length, x25519Shared.Length);
        return combined;
    }

    /// <summary>Server-side shared secret computation.</summary>
    private static byte[] ComputeServerSharedSecret(
        NamedGroup group, byte[] clientKey, out byte[] serverPublicKey)
    {
        switch (group)
        {
            case NamedGroup.X25519:
            {
                byte[] sPriv = X25519.GeneratePrivateKey();
                serverPublicKey = X25519.PublicFromPrivate(sPriv);
                return X25519.SharedSecret(sPriv, clientKey);
            }
            case NamedGroup.X448:
            {
                byte[] sPriv = X448.GeneratePrivateKey();
                serverPublicKey = X448.PublicFromPrivate(sPriv);
                return X448.SharedSecret(sPriv, clientKey);
            }
            case NamedGroup.Secp256r1:
            {
                var (sPriv, sPub) = EcdhP256.GenerateKeyPair();
                serverPublicKey = sPub;
                return EcdhP256.SharedSecret(sPriv, sPub, clientKey);
            }
            case NamedGroup.Secp384r1:
            {
                var (sPriv, sPub) = EcdhP384.GenerateKeyPair();
                serverPublicKey = sPub;
                return EcdhP384.SharedSecret(sPriv, sPub, clientKey);
            }
            case NamedGroup.SecP256r1MLKEM768:
            {
                // Client share: secp256r1 point (65) ‖ ML-KEM ek (1184) — ECDH first (draft §4.1)
                if (clientKey.Length != 65 + 1184)
                    throw new TlsException(AlertDescription.DecodeError, "SecP256r1MLKEM768 client share must be 1249 bytes");
                byte[] clientP256 = clientKey[..65];
                byte[] mlkemEkP = clientKey[65..];

                var (sPrivP, sPubP) = EcdhP256.GenerateKeyPair();
                byte[] ecdhShared = EcdhP256.SharedSecret(sPrivP, sPubP, clientP256); // 32-byte x-coordinate
                var (mlkemSharedP, mlkemCtP) = MlKem768.Encaps(mlkemEkP);

                // Server share: secp256r1 point (65) ‖ ML-KEM ciphertext (1088) — ECDH first (draft §4.2)
                serverPublicKey = new byte[sPubP.Length + mlkemCtP.Length];
                Buffer.BlockCopy(sPubP, 0, serverPublicKey, 0, sPubP.Length);
                Buffer.BlockCopy(mlkemCtP, 0, serverPublicKey, sPubP.Length, mlkemCtP.Length);

                // Shared secret: ECDHE ‖ ML-KEM (ECDH first, draft §4.3)
                byte[] combinedP = new byte[ecdhShared.Length + mlkemSharedP.Length];
                Buffer.BlockCopy(ecdhShared, 0, combinedP, 0, ecdhShared.Length);
                Buffer.BlockCopy(mlkemSharedP, 0, combinedP, ecdhShared.Length, mlkemSharedP.Length);
                return combinedP;
            }
            case NamedGroup.SecP384r1MLKEM1024:
            {
                // Client share: secp384r1 point (97) ‖ ML-KEM-1024 ek (1568) — ECDH first
                if (clientKey.Length != 97 + 1568)
                    throw new TlsException(AlertDescription.DecodeError, "SecP384r1MLKEM1024 client share must be 1665 bytes");
                byte[] clientP384 = clientKey[..97];
                byte[] mlkemEk384 = clientKey[97..];

                var (sPriv384, sPub384) = EcdhP384.GenerateKeyPair();
                byte[] ecdhShared384 = EcdhP384.SharedSecret(sPriv384, sPub384, clientP384); // 48-byte x-coord
                var (mlkemShared384, mlkemCt384) = MlKem1024.Encaps(mlkemEk384);

                // Server share: secp384r1 point (97) ‖ ML-KEM-1024 ciphertext (1568) — ECDH first
                serverPublicKey = new byte[sPub384.Length + mlkemCt384.Length];
                Buffer.BlockCopy(sPub384, 0, serverPublicKey, 0, sPub384.Length);
                Buffer.BlockCopy(mlkemCt384, 0, serverPublicKey, sPub384.Length, mlkemCt384.Length);

                byte[] combined384 = new byte[ecdhShared384.Length + mlkemShared384.Length];
                Buffer.BlockCopy(ecdhShared384, 0, combined384, 0, ecdhShared384.Length);
                Buffer.BlockCopy(mlkemShared384, 0, combined384, ecdhShared384.Length, mlkemShared384.Length);
                return combined384;
            }
            case NamedGroup.X25519MLKEM768:
            {
                // Client share: ML-KEM encapsulation key (1184) + X25519 public (32) (per draft-ietf-tls-ecdhe-mlkem)
                if (clientKey.Length < 1184 + 32)
                    throw new TlsException(AlertDescription.DecodeError, "Hybrid client key share too short");
                byte[] mlkemEk = clientKey[..1184];
                byte[] clientX25519 = clientKey[1184..];

                byte[] sPriv25519 = X25519.GeneratePrivateKey();
                byte[] sPub25519 = X25519.PublicFromPrivate(sPriv25519);
                byte[] x25519Shared = X25519.SharedSecret(sPriv25519, clientX25519);

                var (mlkemShared, mlkemCt) = MlKem768.Encaps(mlkemEk);

                // Server share: ML-KEM ciphertext (1088) + X25519 public (32) (per draft-ietf-tls-ecdhe-mlkem)
                serverPublicKey = new byte[mlkemCt.Length + sPub25519.Length];
                Buffer.BlockCopy(mlkemCt, 0, serverPublicKey, 0, mlkemCt.Length);
                Buffer.BlockCopy(sPub25519, 0, serverPublicKey, mlkemCt.Length, sPub25519.Length);

                // Combined: ML-KEM SS ‖ X25519 SS
                byte[] combined = new byte[mlkemShared.Length + x25519Shared.Length];
                Buffer.BlockCopy(mlkemShared, 0, combined, 0, mlkemShared.Length);
                Buffer.BlockCopy(x25519Shared, 0, combined, mlkemShared.Length, x25519Shared.Length);
                return combined;
            }
            case NamedGroup.Curvesm2:
            {
                var (sPriv, sPub) = ChineseCrypto.SM2.EcdhGenerateKeyPair();
                serverPublicKey = sPub;
                return ChineseCrypto.SM2.EcdhSharedSecret(sPriv, clientKey);
            }
            default:
            {
                string? gostOid = GostGroupCurveOid(group);
                if (gostOid != null)
                {
                    var (sPriv, sPub) = GostEcdh.GenerateKeyPair(gostOid);
                    serverPublicKey = sPub;
                    return GostEcdh.ComputeSharedSecret(sPriv, clientKey, gostOid);
                }
                throw new TlsException(AlertDescription.IllegalParameter, $"Unsupported key share group: {group}");
            }
        }
    }

    private void LogAppSecrets()
    {
        if (KeyLogger.IsEnabled && _clientRandom != null)
        {
            KeyLogger.LogAppTrafficSecrets(_clientRandom,
                _keySchedule!.ClientAppTrafficSecret!, _keySchedule.ServerAppTrafficSecret!);
            if (_keySchedule.ExporterMasterSecret != null)
                KeyLogger.LogExporterSecret(_clientRandom, _keySchedule.ExporterMasterSecret);
        }
    }

    private string? NegotiateAlpn(string[]? clientProtocols)
    {
        // If client did not advertise ALPN, server cannot select.
        if (clientProtocols == null || clientProtocols.Length == 0) return null;
        // If server does not support ALPN at all, don't include extension.
        if (_alpnProtocols == null || _alpnProtocols.Length == 0) return null;
        // Server picks first match in server preference order.
        foreach (var sp in _alpnProtocols)
            foreach (var cp in clientProtocols)
                if (sp == cp) return sp;
        // RFC 7301 §3.2: client offered ALPN, server supports it, but no overlap.
        // Server MUST abort with fatal no_application_protocol(120).
        throw new TlsException(AlertDescription.NoApplicationProtocol,
            "ALPN: no overlap between client and server protocols");
    }

    private ushort NegotiateCertCompression(ushort[]? clientAlgorithms)
    {
        if (!_useCertCompression || clientAlgorithms == null) return 0;
        foreach (var alg in clientAlgorithms)
            if (CertificateCompression.IsSupported(alg)) return alg;
        return 0;
    }

    /// <summary>Client (mTLS): pick the first server-advertised compress_certificate algorithm we can
    /// produce, to compress our own certificate. Not gated on _useCertCompression (a server flag) —
    /// the trigger is the server advertising algorithms in its CertificateRequest (RFC 8879).</summary>
    private ushort SelectClientCertCompression()
    {
        if (_serverCertReqCompAlgs == null) return 0;
        foreach (var a in _serverCertReqCompAlgs)
            if (CertificateCompression.IsSupported(a)) return a;
        return 0;
    }

    private static bool IsSupportedSuite(CipherSuite s) =>
        s is CipherSuite.TLS_AES_128_GCM_SHA256
            or CipherSuite.TLS_AES_256_GCM_SHA384
            or CipherSuite.TLS_CHACHA20_POLY1305_SHA256
            or CipherSuite.TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L
            or CipherSuite.TLS_GOSTR341112_256_WITH_MAGMA_MGM_L
            or CipherSuite.TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S
            or CipherSuite.TLS_GOSTR341112_256_WITH_MAGMA_MGM_S
            or CipherSuite.TLS_SM4_GCM_SM3
            or CipherSuite.TLS_SM4_CCM_SM3
            or CipherSuite.TLS_AEGIS_128L_SHA256
            or CipherSuite.TLS_AEGIS_256_SHA512;

    private CipherSuite SelectCipherSuite(CipherSuite[] clientSuites)
    {
        CipherSuite[] pref =
        {
            CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_AES_128_GCM_SHA256,
            CipherSuite.TLS_AEGIS_256_SHA512,
            CipherSuite.TLS_AEGIS_128L_SHA256,
            CipherSuite.TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L,
            CipherSuite.TLS_GOSTR341112_256_WITH_MAGMA_MGM_L,
            CipherSuite.TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S,
            CipherSuite.TLS_GOSTR341112_256_WITH_MAGMA_MGM_S,
            CipherSuite.TLS_SM4_GCM_SM3,
            CipherSuite.TLS_SM4_CCM_SM3
        };
        foreach (var s in pref)
        {
            // Server allow-list (SetAllowedCipherSuites): skip any suite the operator excluded.
            if (_allowedSuites != null && Array.IndexOf(_allowedSuites, s) < 0) continue;
            if (Array.IndexOf(clientSuites, s) >= 0) return s;
        }
        throw new TlsException(AlertDescription.HandshakeFailure, "No common cipher suite");
    }

    /// <summary>RFC 8446 §4.2.3: for the standard TLS 1.3 suites, the server's CertificateVerify
    /// signature scheme must be one the client offered in signature_algorithms. National suites
    /// (GOST/SM) negotiate schemes the client selects directly without advertising them on the wire,
    /// so the check is scoped to the standard suites to preserve that self-interop path.</summary>
    private void ValidateServerCertSigAlg(ParsedClientHello ch)
    {
        bool standard = _keySchedule!.Suite is CipherSuite.TLS_AES_128_GCM_SHA256
            or CipherSuite.TLS_AES_256_GCM_SHA384 or CipherSuite.TLS_CHACHA20_POLY1305_SHA256;
        if (!standard) return; // national suites (GOST/SM) negotiate the scheme off-wire by design
        // RFC 8446 §9.2: a ClientHello that wants certificate-based authentication MUST carry
        // signature_algorithms. This method is only reached on the certificate path (never a PSK-only
        // resumption), so an absent extension here is a missing mandatory extension, not an option.
        if (ch.SignatureAlgorithms == null)
            AlertAndThrow(AlertDescription.MissingExtension,
                "ClientHello for a certificate handshake is missing signature_algorithms (RFC 8446 §9.2)");
        // RFC 8446 §4.2.3: signature_algorithms_cert, if present, constrains certificate chain
        // signature algorithms. If absent, signature_algorithms applies to both.
        var certSigAlgs = ch.SignatureAlgorithmsCert ?? ch.SignatureAlgorithms;
        if (Array.IndexOf(certSigAlgs, _certificate!.SignatureAlgorithm) < 0)
            AlertAndThrow(AlertDescription.HandshakeFailure,
                "Client's signature_algorithms_cert does not permit the server certificate's signature scheme");
    }

    private (NamedGroup group, byte[] key)? SelectKeyShare(
        (NamedGroup group, byte[] key)[] clientShares)
    {
        foreach (var sg in ServerGroupPreference)
        {
            // Server allow-list (SetAllowedGroups): skip any group the operator excluded.
            if (_allowedGroups != null && Array.IndexOf(_allowedGroups, sg) < 0) continue;
            foreach (var cs in clientShares)
                if (cs.group == sg) return cs;
        }
        return null;
    }

    private static (NamedGroup group, byte[] key)? FindKeyShare(
        (NamedGroup group, byte[] key)[] shares, NamedGroup group)
    {
        foreach (var s in shares)
            if (s.group == group) return s;
        return null;
    }

    private NamedGroup SelectGroupForHrr(NamedGroup[]? clientGroups)
    {
        if (clientGroups != null)
        {
            foreach (var sg in ServerGroupPreference)
            {
                if (_allowedGroups != null && Array.IndexOf(_allowedGroups, sg) < 0) continue;
                if (Array.IndexOf(clientGroups, sg) >= 0) return sg;
            }
        }
        throw new TlsException(AlertDescription.HandshakeFailure, "No common supported group for HRR");
    }

    private void ValidateSignatureScheme(SignatureScheme scheme)
    {
        if (Array.IndexOf(_offeredSigAlgs ?? AdvertisedSigAlgs, scheme) < 0)
            AlertAndThrow(AlertDescription.IllegalParameter,
                $"CertificateVerify uses unadvertised scheme: {scheme}");
    }

    // RFC 8446 §4.1.4 / §4.2.8 (client side): a server — in a HelloRetryRequest or a ServerHello — MUST
    // select a key-exchange group the client actually advertised in supported_groups. Reject anything
    // else with a clean illegal_parameter instead of letting it fall through to an opaque ECDH/decode
    // failure. (We intentionally do NOT also enforce §4.1.4's lesser "the HRR group must differ from a
    // group already in our key_share" no-op rule: this client advertises a broader supported_groups than
    // it pre-shares, the transcript binds the retry regardless, and that rule collides with the
    // ForceHelloRetryRequest test knob for no real-world benefit — a conformant server never HRRs us.)
    private void ValidateSelectedGroupOffered(NamedGroup group)
    {
        var advertised = _offeredGroups ?? HandshakeMessages.DefaultSupportedGroups;
        if (Array.IndexOf(advertised, group) < 0)
            AlertAndThrow(AlertDescription.IllegalParameter,
                $"Server selected a key-exchange group not offered in supported_groups: {group}");
    }

    // RFC 8446 §4.2 (client side): a server MUST NOT send an extension response the client did not
    // solicit. Reject the recognized EncryptedExtensions responses we didn't offer. (Unknown extension
    // types are ignored, per §4.2; cert-compression is always advertised by this client, and
    // record_size_limit is sent independently by each peer per RFC 8449 — so neither is gated here.)
    private void RejectUnsolicitedEncryptedExtensions(ParsedEncryptedExtensions ee, bool offeredEarlyData, bool pskResumptionAccepted)
    {
        if (ee.AcceptEarlyData && (!offeredEarlyData || !pskResumptionAccepted))
            AlertAndThrow(AlertDescription.UnsupportedExtension,
                "EncryptedExtensions accepted early_data without a valid 0-RTT PSK resumption");
        if (ee.AlpnProtocol != null && (_alpnProtocols == null || _alpnProtocols.Length == 0))
            AlertAndThrow(AlertDescription.UnsupportedExtension,
                "EncryptedExtensions carries an unsolicited ALPN protocol");
        if (ee.AlpnProtocol != null && Array.IndexOf(_alpnProtocols!, ee.AlpnProtocol) < 0)
            AlertAndThrow(AlertDescription.IllegalParameter,
                "EncryptedExtensions selected an ALPN protocol the client did not offer");
        if (ee.EchRetryConfigs != null && _echContext == null)
            AlertAndThrow(AlertDescription.UnsupportedExtension,
                "EncryptedExtensions carries unsolicited ECH retry_configs");
    }

    // RFC 8446 §4.1.4 (server side): the second ClientHello (after a HelloRetryRequest) MUST be
    // identical to the first except for the explicitly-permitted changes — replacing key_share, removing
    // early_data, adding a cookie, updating pre_shared_key/binders, adjusting padding. Verify the
    // security-relevant invariant fields are unchanged; a mismatch → illegal_parameter. Both hellos are
    // compared in their post-ECH-decrypt (inner) form. Gated by EnforceHelloRetryConsistency (default on);
    // it is defense-in-depth (the transcript already binds both hellos) but rejects a client that tries
    // to alter its negotiated parameters across the retry.
    private void CheckHelloRetryConsistency(ParsedClientHello ch1, ParsedClientHello ch2)
    {
        if (!HelloRetryConsistent(ch1, ch2))
            AlertAndThrow(AlertDescription.IllegalParameter,
                "Second ClientHello after HelloRetryRequest changed a field RFC 8446 §4.1.4 requires to stay unchanged");
    }

    /// <summary>Pure RFC 8446 §4.1.4 CH1↔CH2 invariant predicate (internal for testing): the fields a
    /// second ClientHello must NOT change across a HelloRetryRequest. key_share / early_data /
    /// pre_shared_key / cookie / padding are deliberately excluded (they are allowed to change).</summary>
    internal static bool HelloRetryConsistent(ParsedClientHello ch1, ParsedClientHello ch2) =>
        SeqEq(ch1.ClientRandom, ch2.ClientRandom) &&
        SeqEq(ch1.SessionId, ch2.SessionId) &&
        SeqEq(ch1.CipherSuites, ch2.CipherSuites) &&
        SeqEq(ch1.SupportedGroups, ch2.SupportedGroups) &&
        SeqEq(ch1.SignatureAlgorithms, ch2.SignatureAlgorithms) &&
        SeqEq(ch1.SignatureAlgorithmsCert, ch2.SignatureAlgorithmsCert) &&
        SeqEq(ch1.AlpnProtocols, ch2.AlpnProtocols) &&
        SeqEq(ch1.CertCompressionAlgorithms, ch2.CertCompressionAlgorithms) &&
        ch1.ServerName == ch2.ServerName &&
        ch1.RequestsOcspStapling == ch2.RequestsOcspStapling &&
        ch1.OffersCertWithExternPsk == ch2.OffersCertWithExternPsk &&
        ch1.OffersPostHandshakeAuth == ch2.OffersPostHandshakeAuth &&
        ch1.OffersPskDheKe == ch2.OffersPskDheKe &&
        ch1.RecordSizeLimit == ch2.RecordSizeLimit;

    // Null-safe element-wise array equality (no LINQ dependency; works for byte[] and enum/string arrays).
    private static bool SeqEq<T>(T[]? a, T[]? b)
    {
        if (ReferenceEquals(a, b)) return true;
        if (a == null || b == null || a.Length != b.Length) return false;
        var cmp = EqualityComparer<T>.Default;
        for (int i = 0; i < a.Length; i++)
            if (!cmp.Equals(a[i], b[i])) return false;
        return true;
    }

    private void ValidatePeerCertificate(byte[] certDer, string? expectedHostname)
    {
        try
        {
            var (notBefore, notAfter) = CertificateUtils.ParseCertificateValidity(certDer);
            var now = DateTime.UtcNow;
            if (now < notBefore)
                CertificateWarnings.Add($"Certificate is not yet valid (notBefore: {notBefore:u})");
            if (now > notAfter)
                CertificateWarnings.Add($"Certificate has expired (notAfter: {notAfter:u})");
        }
        catch
        {
            CertificateWarnings.Add("Could not parse certificate validity period");
        }

        if (!string.IsNullOrEmpty(expectedHostname))
        {
            try
            {
                var sans = CertificateUtils.ParseCertificateSAN(certDer);
                if (sans.Count == 0)
                {
                    CertificateWarnings.Add($"Certificate has no SAN entries — cannot verify hostname '{expectedHostname}'");
                }
                else
                {
                    bool matched = false;
                    foreach (var san in sans)
                    {
                        if (MatchHostname(expectedHostname, san))
                        { matched = true; break; }
                    }
                    if (!matched)
                        CertificateWarnings.Add(
                            $"Hostname '{expectedHostname}' does not match any SAN ({string.Join(", ", sans)})");
                }
            }
            catch
            {
                CertificateWarnings.Add("Could not parse certificate SAN for hostname verification");
            }
        }
    }

    // RFC 6125 §6.4.3 / §7.2 wildcard matching. A wildcard is honoured ONLY as a complete
    // left-most label, and never across a public-suffix-style 2-label name (so a presented
    // "*.com" / "*.co" never matches). Embedded/partial wildcards ("*foo.example.com") and
    // wildcards in a non-leftmost label are rejected. Trailing dots are normalised away.
    private static bool MatchHostname(string hostname, string pattern)
    {
        hostname = hostname.ToLowerInvariant().TrimEnd('.');
        pattern = pattern.ToLowerInvariant().TrimEnd('.');
        if (hostname.Length == 0 || pattern.Length == 0) return false;

        if (pattern.StartsWith("*."))
        {
            string suffix = pattern[1..];          // ".example.com"
            if (suffix.IndexOf('*') >= 0) return false; // only one wildcard, in the left-most label

            // Require the suffix to span at least two labels (≥2 dots, i.e. the full pattern is
            // *.<label>.<label>… with ≥3 labels) so a wildcard can never match a bare public suffix
            // like *.com.
            int dots = 0;
            foreach (char ch in suffix) if (ch == '.') dots++;
            if (dots < 2) return false;

            int firstDot = hostname.IndexOf('.');
            if (firstDot <= 0) return false;       // need a non-empty left-most label to replace
            return hostname[firstDot..] == suffix; // left-most label is wildcarded; rest must match exactly
        }

        if (pattern.IndexOf('*') >= 0) return false; // partial / non-leftmost wildcard → never matches
        return hostname == pattern;
    }

    // Client-side server-certificate trust enforcement. No-op on the server and when nothing is
    // configured (permissive default). When a validator callback is set it is authoritative;
    // otherwise, when a trust anchor is set, the leaf must be signed by it, be within its validity
    // window, and (when a host was supplied) match a SAN — any failure aborts the handshake.
    private void EnforceServerCertificateTrust(byte[] serverCertDer, byte[][] intermediates, string? serverName)
    {
        if (_isServer) return;

        if (_serverCertValidator != null)
        {
            if (!_serverCertValidator(serverCertDer, CertificateWarnings))
                AlertAndThrow(AlertDescription.BadCertificate,
                    "Server certificate rejected by ServerCertificateValidationCallback");
            return;
        }

        if (_serverCaCertificate == null) return; // permissive: no trust anchor configured

        // 1. Chain: the leaf must be signed by the configured trust anchor.
        var leaf = new TlsCertificate
        {
            DerData = serverCertDer,
            PrivateKey = Array.Empty<byte>(),
            PublicKey = Array.Empty<byte>(),
            SignatureAlgorithm = SignatureScheme.EcdsaSecp256r1Sha256
        };
        if (!CertificateUtils.VerifyChain(leaf, intermediates, _serverCaCertificate))
            AlertAndThrow(AlertDescription.UnknownCa,
                "Server certificate is not signed by the configured trust anchor");

        // 2. Validity window.
        try
        {
            var (notBefore, notAfter) = CertificateUtils.ParseCertificateValidity(serverCertDer);
            var now = DateTime.UtcNow;
            if (now < notBefore || now > notAfter)
                AlertAndThrow(AlertDescription.CertificateExpired,
                    "Server certificate is outside its validity period");
        }
        catch (TlsException) { throw; }
        catch { AlertAndThrow(AlertDescription.BadCertificate, "Server certificate validity period could not be parsed"); }

        // 3. Hostname (SAN) match when a host was supplied.
        if (!string.IsNullOrEmpty(serverName))
        {
            var sans = CertificateUtils.ParseCertificateSAN(serverCertDer);
            bool matched = false;
            foreach (var san in sans)
                if (MatchHostname(serverName, san)) { matched = true; break; }
            if (!matched)
                AlertAndThrow(AlertDescription.BadCertificate,
                    $"Server certificate does not match hostname '{serverName}'");
        }
    }

    // Span input so callers from the new direct-decrypt path don't need to materialise
    // a byte[]. Existing byte[] callers (ReadAppData / ReadAppDataAsync) keep working
    // because byte[] implicitly converts to ReadOnlySpan<byte>.
    private void HandleAlert(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2)
            throw new TlsException(AlertDescription.DecodeError, "Malformed alert record (too short)");

        var desc = (AlertDescription)data[1];
        if (desc == AlertDescription.CloseNotify)
        {
            _closed = true;
            // The session is over — zero key material now rather than waiting for GC.
            _keySchedule?.Dispose();
            return;
        }
        // Fatal alerts terminate the connection; clear key material before unwinding.
        _keySchedule?.Dispose();
        throw new TlsException(desc, $"Received alert: {(AlertLevel)data[0]} {desc}");
    }

    private bool _disposed;

    /// <summary>
    /// Zero key material and release record-layer resources. Safe to call multiple times.
    /// Does NOT send close_notify — callers wanting graceful shutdown should call
    /// <see cref="SendAlert"/>(Warning, CloseNotify) first.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _keySchedule?.Dispose();
        _record.Dispose();
        _writeLock.Dispose();
    }

    [DoesNotReturn]
    private void AlertAndThrow(AlertDescription desc, string message)
    {
        SendAlert(desc == AlertDescription.CloseNotify ? AlertLevel.Warning : AlertLevel.Fatal, desc);
        throw new TlsException(desc, message);
    }

    // ================================================================
    //  Async internal helpers
    // ================================================================

    private async Task<byte[]> NextHandshakeAsync(HandshakeType expected, CancellationToken ct = default)
    {
        while (_hsBuffer.Count == 0)
        {
            var (type, payload) = await _record.ReadRecordAsync(ct).ConfigureAwait(false);
            if (type == ContentType.ChangeCipherSpec) continue;
            if (type == ContentType.Alert)
            {
                HandleAlert(payload);
                if (_closed)
                    throw new TlsException(AlertDescription.CloseNotify, "Connection closed during handshake");
                continue;
            }
            if (type != ContentType.Handshake)
                throw new TlsException(AlertDescription.UnexpectedMessage, $"Expected Handshake, got {type}");

            EnqueueHandshake(payload);
        }

        byte[] msg = _hsBuffer.Dequeue();
        var (hsType, _) = HandshakeMessages.Unframe(msg);
        if (hsType != expected)
            throw new TlsException(AlertDescription.UnexpectedMessage, $"Expected {expected}, got {hsType}");
        return msg;
    }

    private async Task<(byte[] msg, HandshakeType hsType)> NextHandshakeAnyAsync(CancellationToken ct = default)
    {
        while (_hsBuffer.Count == 0)
        {
            var (type, payload) = await _record.ReadRecordAsync(ct).ConfigureAwait(false);
            if (type == ContentType.ChangeCipherSpec) continue;
            if (type == ContentType.Alert)
            {
                HandleAlert(payload);
                if (_closed)
                    throw new TlsException(AlertDescription.CloseNotify, "Connection closed during handshake");
                continue;
            }
            if (type != ContentType.Handshake)
                throw new TlsException(AlertDescription.UnexpectedMessage, $"Expected Handshake, got {type}");

            EnqueueHandshake(payload);
        }

        byte[] msg = _hsBuffer.Dequeue();
        var (hsType, _) = HandshakeMessages.Unframe(msg);
        return (msg, hsType);
    }

    private async Task<byte[]> ReadAppDataAsync(CancellationToken ct = default)
    {
        while (true)
        {
            if (_closed) return Array.Empty<byte>();

            var (type, payload) = await _record.ReadRecordAsync(ct).ConfigureAwait(false);

            if (type == ContentType.ApplicationData) return payload;

            if (type == ContentType.Alert)
            {
                HandleAlert(payload);
                if (_closed) return Array.Empty<byte>();
                continue;
            }

            if (type == ContentType.Handshake)
            {
                HandlePostHandshakeMessages(payload);
                continue;
            }
        }
    }

    internal async Task SendAlertAsync(AlertLevel level, AlertDescription desc, CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try { await _record.WriteRecordAsync(ContentType.Alert, new[] { (byte)level, (byte)desc }, ct).ConfigureAwait(false); }
        catch { /* best-effort on close */ }
        finally { _writeLock.Release(); }
    }

    private async Task SendNewSessionTicketAsync(ushort count = 1, CancellationToken ct = default)
    {
        if (_ticketEncryption == null || _keySchedule?.ResumptionMasterSecret == null) return;

        for (int i = 0; i < count; i++)
        {
            byte[] nonce = RandomnessWrapper.GetBytes(8);
            byte[] ticketPsk = _keySchedule.DerivePsk(nonce);

            uint lifetime = 86400;
            uint ageAdd = BitConverter.ToUInt32(RandomnessWrapper.GetBytes(4));

            byte[] plaintext = TicketEncryption.EncodeTicketState(
                ticketPsk, _keySchedule.Suite, ageAdd, DateTime.UtcNow, _maxEarlyDataSize);
            byte[] ticket = _ticketEncryption.Seal(plaintext);

            byte[] nstMsg = HandshakeMessages.BuildNewSessionTicket(lifetime, ageAdd, nonce, ticket, _maxEarlyDataSize);
            await _writeLock.WaitAsync(ct).ConfigureAwait(false);
            try { await _record.WriteRecordAsync(ContentType.Handshake, nstMsg, ct).ConfigureAwait(false); }
            finally { _writeLock.Release(); }
        }
    }

    // ================================================================
    //  Async application data
    // ================================================================

    /// <summary>Read decrypted application data asynchronously. Returns bytes read (0 = EOF from close_notify).</summary>
    public async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct = default)
    {
        if (_closed) return 0;

        // Drain any leftover plaintext stashed by a previous Read (same _readBuf
        // semantics as the sync path — a fresh byte[] holding only the remainder).
        if (_readOff < _readBuf.Length)
        {
            int avail = _readBuf.Length - _readOff;
            int n = Math.Min(avail, count);
            Buffer.BlockCopy(_readBuf, _readOff, buffer, offset, n);
            _readOff += n;
            if (_readOff >= _readBuf.Length) { _readBuf = Array.Empty<byte>(); _readOff = 0; }
            return n;
        }

        // Loop until we get an ApplicationData record. The new ReadRecordIntoAsync path
        // decrypts straight into the caller's buffer when the record fits.
        while (true)
        {
            if (_closed) return 0;

            var result = await _record.ReadRecordIntoAsync(buffer.AsMemory(offset, count), ct).ConfigureAwait(false);
            try
            {
                if (result.Type == ContentType.ApplicationData)
                {
                    if (result.LeasedBuffer == null)
                    {
                        return result.Length;
                    }
                    int copy = Math.Min(result.Length, count);
                    Buffer.BlockCopy(result.LeasedBuffer, 0, buffer, offset, copy);
                    if (copy < result.Length)
                    {
                        int rem = result.Length - copy;
                        var stash = new byte[rem];
                        Buffer.BlockCopy(result.LeasedBuffer, copy, stash, 0, rem);
                        _readBuf = stash;
                        _readOff = 0;
                    }
                    return copy;
                }

                ReadOnlySpan<byte> payload = result.LeasedBuffer == null
                    ? buffer.AsSpan(offset, result.Length)
                    : new ReadOnlySpan<byte>(result.LeasedBuffer, 0, result.Length);

                if (result.Type == ContentType.Alert)
                {
                    HandleAlert(payload);
                    if (_closed) return 0;
                    continue;
                }
                if (result.Type == ContentType.Handshake)
                {
                    HandlePostHandshakeMessages(payload.ToArray());
                    continue;
                }
                if (result.Type == ContentType.ChangeCipherSpec)
                {
                    continue;
                }
            }
            finally
            {
                if (result.LeasedBuffer != null)
                {
                    Array.Clear(result.LeasedBuffer, 0, result.Length);
                    ArrayPool<byte>.Shared.Return(result.LeasedBuffer);
                }
            }
        }
    }

    /// <summary>Read a complete application-data record asynchronously.</summary>
    public async Task<byte[]> ReadAllAsync(CancellationToken ct = default)
    {
        if (_closed) return Array.Empty<byte>();

        if (_readOff < _readBuf.Length)
        {
            byte[] rem = _readBuf[_readOff..];
            _readBuf = Array.Empty<byte>();
            _readOff = 0;
            return rem;
        }
        return await ReadAppDataAsync(ct).ConfigureAwait(false);
    }

    /// <summary>Write application data asynchronously (fragments automatically at 16 KiB). Thread-safe.</summary>
    public async Task WriteAsync(byte[] data, int offset, int count, CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            int pos = offset;
            int end = offset + count;
            while (pos < end)
            {
                int chunk = Math.Min(end - pos, TlsConst.MaxPlaintextLength);
                // AsMemory instead of Range slice — same fix as the sync path. ReadOnlyMemory
                // because the slice must cross await boundaries (Span can't).
                await _record.WriteRecordAsync(ContentType.ApplicationData, data.AsMemory(pos, chunk), ct).ConfigureAwait(false);
                pos += chunk;
            }
        }
        finally { _writeLock.Release(); }
    }

    /// <summary>Send a KeyUpdate message asynchronously and rotate our write key. Thread-safe.</summary>
    public async Task SendKeyUpdateAsync(bool requestUpdate, CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            byte[] kuMsg = HandshakeMessages.BuildKeyUpdate(requestUpdate);
            await _record.WriteRecordAsync(ContentType.Handshake, kuMsg, ct).ConfigureAwait(false);

            if (_isServer)
            {
                _keySchedule!.UpdateServerAppTrafficSecret();
                var (k, iv) = _keySchedule.DeriveKeyAndIv(_keySchedule.ServerAppTrafficSecret!);
                _record.SetWriteCipher(new AeadCipher(k, iv, _keySchedule.Aead, _keySchedule.Suite));
            }
            else
            {
                _keySchedule!.UpdateClientAppTrafficSecret();
                var (k, iv) = _keySchedule.DeriveKeyAndIv(_keySchedule.ClientAppTrafficSecret!);
                _record.SetWriteCipher(new AeadCipher(k, iv, _keySchedule.Aead, _keySchedule.Suite));
            }
        }
        finally { _writeLock.Release(); }
    }

    /// <summary>Server: request client authentication post-handshake (async).</summary>
    public async Task RequestPostHandshakeAuthAsync(CancellationToken ct = default)
    {
        if (!_isServer || !IsHandshakeComplete)
            throw new InvalidOperationException("Only server can request post-handshake auth after handshake");
        if (!_peerAllowsPostHandshakeAuth)
            throw new InvalidOperationException("Peer did not advertise post_handshake_auth");
        if (_postHsAuthState != PostHsAuthState.None)
            throw new InvalidOperationException("A post-handshake auth flow is already in progress");

        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            byte[] context = RandomnessWrapper.GetBytes(16);
            _pendingPostHsContext = context;
            byte[] crMsg = HandshakeMessages.BuildCertificateRequest(context, _offeredSigAlgs ?? AdvertisedSigAlgs);
            await _record.WriteRecordAsync(ContentType.Handshake, crMsg, ct).ConfigureAwait(false);
            _postHsAuthState = PostHsAuthState.AwaitingCertificate;
        }
        finally { _writeLock.Release(); }
    }

    // ================================================================
    //  Async client handshake
    // ================================================================

    public async Task HandshakeAsClientAsync(string? serverName = null, CancellationToken ct = default)
    {
        // 1. Lazy ephemeral key pair generation — same rationale as the sync HandshakeAsClient:
        // only generate for groups in _offeredGroups, saves ~2.7 MB/handshake when constrained.
        var offered = _offeredGroups ?? new[]
        {
            NamedGroup.X25519MLKEM768, NamedGroup.X25519, NamedGroup.X448,
            NamedGroup.Secp256r1, NamedGroup.Secp384r1
        };

        bool wantX25519 = false, wantP256 = false, wantP384 = false, wantX448 = false, wantHybrid = false, wantHybridP256 = false, wantHybridP384 = false;
        foreach (var g in offered)
        {
            switch (g)
            {
                case NamedGroup.X25519: wantX25519 = true; break;
                case NamedGroup.Secp256r1: wantP256 = true; break;
                case NamedGroup.Secp384r1: wantP384 = true; break;
                case NamedGroup.X448: wantX448 = true; break;
                case NamedGroup.X25519MLKEM768: wantHybrid = true; break;
                case NamedGroup.SecP256r1MLKEM768: wantHybridP256 = true; break;
                case NamedGroup.SecP384r1MLKEM1024: wantHybridP384 = true; break;
            }
        }
        if (wantHybrid) wantX25519 = true; // X25519MLKEM768 reuses the X25519 keypair
        if (wantHybridP256) wantP256 = true; // SecP256r1MLKEM768 reuses the P-256 keypair
        if (wantHybridP384) wantP384 = true; // SecP384r1MLKEM1024 reuses the P-384 keypair

        byte[] x25519Priv = Array.Empty<byte>(), x25519Pub = Array.Empty<byte>();
        byte[] p256Priv = Array.Empty<byte>(), p256Pub = Array.Empty<byte>();
        byte[] p384Priv = Array.Empty<byte>(), p384Pub = Array.Empty<byte>();
        byte[] x448Priv = Array.Empty<byte>(), x448Pub = Array.Empty<byte>();
        byte[] mlkemDk = Array.Empty<byte>();
        byte[] hybridPub = Array.Empty<byte>();
        byte[] secp256HybridPub = Array.Empty<byte>();
        byte[] secp384HybridPub = Array.Empty<byte>();

        if (wantX25519)
        {
            x25519Priv = X25519.GeneratePrivateKey();
            x25519Pub = X25519.PublicFromPrivate(x25519Priv);
        }
        if (wantP256) (p256Priv, p256Pub) = EcdhP256.GenerateKeyPair();
        if (wantP384) (p384Priv, p384Pub) = EcdhP384.GenerateKeyPair();
        if (wantX448)
        {
            x448Priv = X448.GeneratePrivateKey();
            x448Pub = X448.PublicFromPrivate(x448Priv);
        }
        if (wantHybrid)
        {
            // X25519MLKEM768: ML-KEM ek ‖ X25519 share (ML-KEM first, per draft-ietf-tls-ecdhe-mlkem §4.1)
            var (mlkemEk, dk) = MlKem768.KeyGen();
            mlkemDk = dk;
            hybridPub = new byte[mlkemEk.Length + x25519Pub.Length];
            Buffer.BlockCopy(mlkemEk, 0, hybridPub, 0, mlkemEk.Length);
            Buffer.BlockCopy(x25519Pub, 0, hybridPub, mlkemEk.Length, x25519Pub.Length);
        }
        if (wantHybridP256)
        {
            // SecP256r1MLKEM768: secp256r1 point (65) ‖ ML-KEM ek (1184) — ECDH first (§4.1)
            var (mlkemEkP, dkP) = MlKem768.KeyGen();
            _mlkemDkSecp256 = dkP;
            secp256HybridPub = new byte[p256Pub.Length + mlkemEkP.Length];
            Buffer.BlockCopy(p256Pub, 0, secp256HybridPub, 0, p256Pub.Length);
            Buffer.BlockCopy(mlkemEkP, 0, secp256HybridPub, p256Pub.Length, mlkemEkP.Length);
        }
        if (wantHybridP384)
        {
            // SecP384r1MLKEM1024: secp384r1 point (97) ‖ ML-KEM-1024 ek (1568) — ECDH first (§4.1)
            var (mlkemEk384, dk384) = MlKem1024.KeyGen();
            _mlkemDkSecp384 = dk384;
            secp384HybridPub = new byte[p384Pub.Length + mlkemEk384.Length];
            Buffer.BlockCopy(p384Pub, 0, secp384HybridPub, 0, p384Pub.Length);
            Buffer.BlockCopy(mlkemEk384, 0, secp384HybridPub, p384Pub.Length, mlkemEk384.Length);
        }

        byte[] clientRandom = RandomnessWrapper.GetHandshakeBytes(32);
        _clientRandom = clientRandom;
        byte[] sessionId = RandomnessWrapper.GetBytes(32);

        var suites = _offeredSuites ?? new[]
        {
            CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_AES_128_GCM_SHA256
        };
        var keyShares = BuildClientKeyShares(hybridPub, x25519Pub, x448Pub, p256Pub, p384Pub, secp256HybridPub, secp384HybridPub);

        // 2. Build ClientHello (with PSK if available)
        byte[] chMsg;
        byte[]? psk = null;
        bool offer0Rtt = false;

        if (_pskTicket != null)
        {
            psk = _pskTicket.ResumptionSecret;
            _keySchedule = new KeySchedule(_pskTicket.CipherSuite, psk);
            _transcript.SetAlgorithm(_keySchedule.HashAlgorithm);

            var elapsed = DateTime.UtcNow - _pskTicket.IssuedAt;
            uint ticketAgeMs = (uint)elapsed.TotalMilliseconds;
            uint obfuscatedAge = ticketAgeMs + _pskTicket.AgeAdd;

            int binderLen = _keySchedule.HashLen;
            byte[] placeholder = new byte[binderLen];
            offer0Rtt = _pskTicket.MaxEarlyDataSize > 0;

            chMsg = HandshakeMessages.BuildClientHelloWithPsk(
                clientRandom, sessionId, suites, keyShares,
                _pskTicket.Ticket, obfuscatedAge, placeholder,
                offer0Rtt, serverName, alpnProtocols: _alpnProtocols,
                requestOcspStapling: _requestOcspStapling, offeredSigAlgs: _offeredSigAlgs,
                offeredGroups: _offeredGroups, postHandshakeAuth: _offerPostHandshakeAuth);

            // Compute and patch the real binder
            // Truncated transcript = ClientHello up to (but not including) the binders list
            int bindersLen = HandshakeMessages.PskBindersTailLength(binderLen);
            byte[] truncatedCh = chMsg[..^bindersLen];

            var binderTranscript = new TranscriptHash(_keySchedule.HashAlgorithm);
            binderTranscript.Update(truncatedCh);
            byte[] truncatedHash = binderTranscript.GetHash();

            byte[] binderKey = _keySchedule.DeriveBinderKey();
            byte[] binder = HandshakeMessages.ComputePskBinder(binderKey, truncatedHash, _keySchedule.HashAlgorithm);
            HandshakeMessages.PatchPskBinder(chMsg, binder);
        }
        else if (_externalPsk != null)
        {
            // RFC 9258: imported external PSK (mirrors the sync client so the async path supports it too).
            psk = DeriveExternalPskKey(_externalPsk);

            _keySchedule = new KeySchedule(_externalPsk.Suite, psk);
            _transcript.SetAlgorithm(_keySchedule.HashAlgorithm);

            int binderLenE = _keySchedule.HashLen;
            byte[] placeholderE = new byte[binderLenE];
            // draft-ietf-tls-8773bis forbids early_data alongside tls_cert_with_extern_psk.
            offer0Rtt = !_certWithExternPsk && _externalPsk.MaxEarlyDataSize > 0;

            chMsg = HandshakeMessages.BuildClientHelloWithPsk(
                clientRandom, sessionId, suites, keyShares,
                BuildImportedIdentity(_externalPsk), 0, placeholderE, // external PSK age is always 0
                offer0Rtt, serverName, alpnProtocols: _alpnProtocols,
                requestOcspStapling: _requestOcspStapling, certWithExternPsk: _certWithExternPsk,
                offeredSigAlgs: _offeredSigAlgs, offeredGroups: _offeredGroups, postHandshakeAuth: _offerPostHandshakeAuth);

            int bindersLenE = HandshakeMessages.PskBindersTailLength(binderLenE);
            byte[] truncatedChE = chMsg[..^bindersLenE];

            var binderTranscriptE = new TranscriptHash(_keySchedule.HashAlgorithm);
            binderTranscriptE.Update(truncatedChE);
            byte[] truncatedHashE = binderTranscriptE.GetHash();

            // RFC 8446 §4.2.11.2: external PSKs use the "ext binder" label.
            byte[] binderKeyE = _keySchedule.DeriveBinderKey(external: true);
            byte[] binderE = HandshakeMessages.ComputePskBinder(binderKeyE, truncatedHashE, _keySchedule.HashAlgorithm);
            HandshakeMessages.PatchPskBinder(chMsg, binderE);
        }
        else
        {
            // ECH (or GREASE-ECH) if configured, else a normal ClientHello.
            chMsg = TryBuildEchClientHello(clientRandom, sessionId, suites, keyShares, serverName)
                ?? BuildGreaseEchClientHello(clientRandom, sessionId, suites, keyShares, serverName)
                ?? HandshakeMessages.BuildClientHello(clientRandom, sessionId, suites, keyShares,
                    serverName, alpnProtocols: _alpnProtocols, requestOcspStapling: _requestOcspStapling,
                    offeredSigAlgs: _offeredSigAlgs, offeredGroups: _offeredGroups, postHandshakeAuth: _offerPostHandshakeAuth);
        }

        await _record.WriteRecordAsync(ContentType.Handshake, chMsg, ct).ConfigureAwait(false);
        if (_echContext == null) _transcript.Update(chMsg); // real ECH defers until accept/reject is known (at the ServerHello)

        // 2b. Send 0-RTT early data if applicable
        if (offer0Rtt && _keySchedule != null)
        {
            byte[] chHash = _transcript.GetHash();
            byte[] earlySecret = _keySchedule.DeriveClientEarlyTrafficSecret(chHash);
            if (_clientRandom != null) KeyLogger.LogEarlyTrafficSecret(_clientRandom, earlySecret);
            var (ek, eiv) = _keySchedule.DeriveKeyAndIv(earlySecret);
            _record.SetWriteCipher(new AeadCipher(ek, eiv, _keySchedule.Aead, _keySchedule.Suite));

            if (_earlyData != null && _earlyData.Length > 0)
            {
                int maxSize = (int)(_pskTicket?.MaxEarlyDataSize ?? _externalPsk?.MaxEarlyDataSize ?? 0);
                int toSend = Math.Min(_earlyData.Length, maxSize);
                int pos = 0;
                while (pos < toSend)
                {
                    int chunk = Math.Min(toSend - pos, TlsConst.MaxPlaintextLength);
                    // AsMemory instead of Range slice — eliminates the per-record
                    // _earlyData fragmentation allocation on the 0-RTT path.
                    await _record.WriteRecordAsync(ContentType.ApplicationData, _earlyData.AsMemory(pos, chunk), ct).ConfigureAwait(false);
                    pos += chunk;
                }
            }
        }

        // 3. Receive ServerHello (might be HelloRetryRequest)
        byte[] shMsg = await NextHandshakeAsync(HandshakeType.ServerHello, ct).ConfigureAwait(false);
        var (_, shBody) = HandshakeMessages.Unframe(shMsg);
        var sh = HandshakeMessages.ParseServerHello(shBody);
        CheckSessionIdEcho(sessionId, sh.SessionId);
        ValidateServerCipherSuiteOffered(sh.CipherSuite, suites);
        if (!sh.IsHelloRetryRequest) CheckDowngradeSentinel(sh.ServerRandom);
        VerifyEchAcceptConfirmation(shMsg, sh);

        // 4. Handle HelloRetryRequest
        if (sh.IsHelloRetryRequest)
        {
            ValidateSelectedGroupOffered(sh.KeyShareGroup); // RFC 8446 §4.1.4
            if (_keySchedule == null)
            {
                _keySchedule = new KeySchedule(sh.CipherSuite);
                _transcript.SetAlgorithm(_keySchedule.HashAlgorithm);
            }

            VerifyEchHrrAndCommit(shMsg, sh); // ECH: verify HRR confirmation + commit the deferred CH1
            _transcript.ReplaceWithMessageHash();
            _transcript.Update(shMsg);

            if (sh.KeyShareGroup == NamedGroup.X25519)
            {
                x25519Priv = X25519.GeneratePrivateKey();
                x25519Pub = X25519.PublicFromPrivate(x25519Priv);
                keyShares = new (NamedGroup, byte[])[] { (NamedGroup.X25519, x25519Pub) };
            }
            else if (sh.KeyShareGroup == NamedGroup.X448)
            {
                x448Priv = X448.GeneratePrivateKey();
                x448Pub = X448.PublicFromPrivate(x448Priv);
                keyShares = new (NamedGroup, byte[])[] { (NamedGroup.X448, x448Pub) };
            }
            else if (sh.KeyShareGroup == NamedGroup.Secp256r1)
            {
                (p256Priv, p256Pub) = EcdhP256.GenerateKeyPair();
                keyShares = new (NamedGroup, byte[])[] { (NamedGroup.Secp256r1, p256Pub) };
            }
            else if (sh.KeyShareGroup == NamedGroup.Secp384r1)
            {
                (p384Priv, p384Pub) = EcdhP384.GenerateKeyPair();
                keyShares = new (NamedGroup, byte[])[] { (NamedGroup.Secp384r1, p384Pub) };
            }
            else if (sh.KeyShareGroup == NamedGroup.X25519MLKEM768)
            {
                x25519Priv = X25519.GeneratePrivateKey();
                x25519Pub = X25519.PublicFromPrivate(x25519Priv);
                // mlkemEk is local to the HRR branch — only used here to build hybridPub.
                // mlkemDk is the outer-scope variable since ComputeClientSharedSecret needs it.
                var (mlkemEk, dk) = MlKem768.KeyGen();
                mlkemDk = dk;
                hybridPub = new byte[mlkemEk.Length + x25519Pub.Length];
                Buffer.BlockCopy(mlkemEk, 0, hybridPub, 0, mlkemEk.Length);
                Buffer.BlockCopy(x25519Pub, 0, hybridPub, mlkemEk.Length, x25519Pub.Length);
                keyShares = new (NamedGroup, byte[])[] { (NamedGroup.X25519MLKEM768, hybridPub) };
            }
            else if (sh.KeyShareGroup == NamedGroup.SecP256r1MLKEM768)
            {
                (p256Priv, p256Pub) = EcdhP256.GenerateKeyPair();
                var (mlkemEkP, dkP) = MlKem768.KeyGen();
                _mlkemDkSecp256 = dkP;
                secp256HybridPub = new byte[p256Pub.Length + mlkemEkP.Length];
                Buffer.BlockCopy(p256Pub, 0, secp256HybridPub, 0, p256Pub.Length);
                Buffer.BlockCopy(mlkemEkP, 0, secp256HybridPub, p256Pub.Length, mlkemEkP.Length);
                keyShares = new (NamedGroup, byte[])[] { (NamedGroup.SecP256r1MLKEM768, secp256HybridPub) };
            }
            else if (sh.KeyShareGroup == NamedGroup.SecP384r1MLKEM1024)
            {
                (p384Priv, p384Pub) = EcdhP384.GenerateKeyPair();
                var (mlkemEk384, dk384) = MlKem1024.KeyGen();
                _mlkemDkSecp384 = dk384;
                secp384HybridPub = new byte[p384Pub.Length + mlkemEk384.Length];
                Buffer.BlockCopy(p384Pub, 0, secp384HybridPub, 0, p384Pub.Length);
                Buffer.BlockCopy(mlkemEk384, 0, secp384HybridPub, p384Pub.Length, mlkemEk384.Length);
                keyShares = new (NamedGroup, byte[])[] { (NamedGroup.SecP384r1MLKEM1024, secp384HybridPub) };
            }
            else
            {
                AlertAndThrow(AlertDescription.IllegalParameter, $"Unsupported group in HRR: {sh.KeyShareGroup}");
            }

            // HRR invalidates 0-RTT — clear early write cipher if it was installed (RFC 8446 §4.2.10)
            if (offer0Rtt)
            {
                _record.ClearWriteCipher();
                offer0Rtt = false;
            }

            await _record.WriteChangeCipherSpecAsync(ct).ConfigureAwait(false);
            _sentCcs = true;

            byte[] ch2Msg;
            if (psk != null && (_pskTicket != null || _externalPsk != null))
            {
                // Rebuild CH2 with PSK extension (RFC 8446 §4.2.11)
                byte[] pskIdentity;
                uint obfuscatedAge2;
                bool externalPskBinder = _pskTicket == null;
                if (_pskTicket != null)
                {
                    var elapsed2 = DateTime.UtcNow - _pskTicket.IssuedAt;
                    obfuscatedAge2 = (uint)elapsed2.TotalMilliseconds + _pskTicket.AgeAdd;
                    pskIdentity = _pskTicket.Ticket;
                }
                else
                {
                    obfuscatedAge2 = 0;
                    pskIdentity = BuildImportedIdentity(_externalPsk!);
                }
                int binderLen2 = _keySchedule.HashLen;

                ch2Msg = HandshakeMessages.BuildClientHelloWithPsk(
                    clientRandom, sessionId, suites, keyShares,
                    pskIdentity, obfuscatedAge2, new byte[binderLen2],
                    false, serverName, sh.Cookie, _alpnProtocols,
                    requestOcspStapling: _requestOcspStapling, certWithExternPsk: _certWithExternPsk,
                    offeredSigAlgs: _offeredSigAlgs,
                    offeredGroups: _offeredGroups, postHandshakeAuth: _offerPostHandshakeAuth); // no 0-RTT after HRR

                // Binder computed over: transcript(message_hash(CH1) || HRR) + truncated(CH2)
                int bindersLen2 = HandshakeMessages.PskBindersTailLength(binderLen2);
                var binderTranscript2 = _transcript.Clone();
                binderTranscript2.Update(ch2Msg[..^bindersLen2]);

                byte[] binder2 = HandshakeMessages.ComputePskBinder(
                    _keySchedule.DeriveBinderKey(external: externalPskBinder), binderTranscript2.GetHash(), _keySchedule.HashAlgorithm);
                HandshakeMessages.PatchPskBinder(ch2Msg, binder2);
                await _record.WriteRecordAsync(ContentType.Handshake, ch2Msg, ct).ConfigureAwait(false);
                _transcript.Update(ch2Msg);
            }
            else if (_echContext != null)
            {
                // ECH after HRR: rebuild the outer CH2 carrying a re-sealed inner CH2.
                var (outer2, transcript2) = BuildEchClientHello2(clientRandom, sessionId, suites, keyShares, serverName, sh.Cookie);
                ch2Msg = outer2;
                await _record.WriteRecordAsync(ContentType.Handshake, ch2Msg, ct).ConfigureAwait(false);
                _transcript.Update(transcript2);
            }
            else
            {
                ch2Msg = HandshakeMessages.BuildClientHello(
                    clientRandom, sessionId, suites, keyShares, serverName, sh.Cookie, _alpnProtocols,
                    requestOcspStapling: _requestOcspStapling, offeredSigAlgs: _offeredSigAlgs,
                    offeredGroups: _offeredGroups, postHandshakeAuth: _offerPostHandshakeAuth);
                await _record.WriteRecordAsync(ContentType.Handshake, ch2Msg, ct).ConfigureAwait(false);
                _transcript.Update(ch2Msg);
            }

            shMsg = await NextHandshakeAsync(HandshakeType.ServerHello, ct).ConfigureAwait(false);
            (_, shBody) = HandshakeMessages.Unframe(shMsg);
            sh = HandshakeMessages.ParseServerHello(shBody);
            CheckSessionIdEcho(sessionId, sh.SessionId);
            ValidateServerCipherSuiteOffered(sh.CipherSuite, suites);

            if (sh.IsHelloRetryRequest)
                AlertAndThrow(AlertDescription.UnexpectedMessage, "Second HelloRetryRequest not allowed");
            CheckDowngradeSentinel(sh.ServerRandom);
            if (sh.CipherSuite != _keySchedule.Suite)
                AlertAndThrow(AlertDescription.IllegalParameter, "Cipher suite changed after HRR");

            // RFC 9849 §7.2: the post-HRR ServerHello also carries an ECH accept-confirmation, taken
            // over the full transcript message_hash(CH1inner) ‖ HRR ‖ CH2inner ‖ SH(zeroed). When we
            // attempted ECH and the HRR signalled acceptance, verify it matches (the running transcript
            // already holds that prefix), so a server that accepted ECH must prove it consistently.
            if (_echContext != null && EchAccepted)
            {
                byte[] shZeroed = (byte[])shMsg.Clone();
                Array.Clear(shZeroed, 30, 8);
                byte[] expected = ComputeEchConfFromTranscript(_transcript, shZeroed, _echContext.InnerRandom);
                if (!CryptographicOperations.FixedTimeEquals(expected, shMsg.AsSpan(30, 8)))
                    AlertAndThrow(AlertDescription.IllegalParameter,
                        "ECH accept-confirmation mismatch in post-HRR ServerHello");
            }
        }

        // 5. Set up key schedule
        // draft-ietf-tls-8773bis: cert + external PSK uses the PSK-seeded schedule + full cert handshake.
        ValidateServerPskSelection(sh, psk, _certWithExternPsk && _externalPsk != null,
            _pskTicket?.CipherSuite ?? _externalPsk?.Suite);
        bool certWithPsk = sh.CertWithExternPsk && psk != null;
        bool isPskResumption = !certWithPsk && sh.SelectedPskIndex >= 0 && psk != null;
        if (_keySchedule == null || (!isPskResumption && !certWithPsk && psk != null))
        {
            _keySchedule = (isPskResumption || certWithPsk) ? new KeySchedule(sh.CipherSuite, psk) : new KeySchedule(sh.CipherSuite);
            _transcript.SetAlgorithm(_keySchedule.HashAlgorithm);
        }
        _transcript.Update(shMsg);
        IsResumed = isPskResumption;
        UsedCertWithExternalPsk = certWithPsk;

        // 6. Compute shared secret based on selected group
        _negotiatedGroup = sh.KeyShareGroup;
        if (sh.KeyShare == null || sh.KeyShare.Length == 0)
            AlertAndThrow(AlertDescription.DecodeError, "ServerHello has empty KeyShare");
        ValidateSelectedGroupOffered(sh.KeyShareGroup); // RFC 8446 §4.2.8 (final selected_group)
        byte[] shared = ComputeClientSharedSecret(
            sh.KeyShareGroup, sh.KeyShare, x25519Priv, x25519Pub,
            p256Priv, p256Pub, p384Priv, p384Pub, x448Priv, mlkemDk);
        _keySchedule.DeriveHandshakeSecrets(shared, _transcript.GetHash());

        // Key logging
        if (KeyLogger.IsEnabled)
            KeyLogger.LogHandshakeTrafficSecrets(clientRandom,
                _keySchedule.ClientHandshakeTrafficSecret!, _keySchedule.ServerHandshakeTrafficSecret!);

        // 7. Install server handshake read cipher
        var (sKey, sIv) = _keySchedule.DeriveKeyAndIv(_keySchedule.ServerHandshakeTrafficSecret!);
        _record.SetReadCipher(new AeadCipher(sKey, sIv, _keySchedule.Aead, _keySchedule.Suite));

        // 8. EncryptedExtensions
        byte[] eeMsg = await NextHandshakeAsync(HandshakeType.EncryptedExtensions, ct).ConfigureAwait(false);
        _transcript.Update(eeMsg);
        var (_, eeBody) = HandshakeMessages.Unframe(eeMsg);
        var ee = HandshakeMessages.ParseEncryptedExtensionsEx(eeBody);
        RejectUnsolicitedEncryptedExtensions(ee, offer0Rtt, isPskResumption);
        bool earlyDataServerAccepted = ee.AcceptEarlyData;
        _negotiatedAlpn = ee.AlpnProtocol;
        _peerCertCompAlgorithm = ee.CertCompressionAlgorithm;
        ApplyPeerRecordSizeLimit(ee.RecordSizeLimit);
        // ECH reject: the server returned a fresh ECHConfigList (retry_configs) for the next attempt.
        if (_echContext != null && !EchAccepted) _echRetryConfigs = ee.EchRetryConfigs;
        EarlyDataAccepted = earlyDataServerAccepted && offer0Rtt && isPskResumption;

        // 9. PSK resumption: skip to Finished
        if (isPskResumption)
        {
            byte[] preFinHash = _transcript.GetHash();
            byte[] sfMsg = await NextHandshakeAsync(HandshakeType.Finished, ct).ConfigureAwait(false);
            var (_, sfBody) = HandshakeMessages.Unframe(sfMsg);

            byte[] expectedSF = _keySchedule.ComputeFinishedVerifyData(
                _keySchedule.ServerHandshakeTrafficSecret!, preFinHash);
            if (!CryptographicOperations.FixedTimeEquals(sfBody, expectedSF))
                AlertAndThrow(AlertDescription.DecryptError, "Server Finished verification failed");

            _transcript.Update(sfMsg);
            _serverFinishedHash = _transcript.GetHash();
            _keySchedule.DeriveAppSecrets(_serverFinishedHash);
        LogAppSecrets();

            if (!_sentCcs) await _record.WriteChangeCipherSpecAsync(ct).ConfigureAwait(false);

            if (EarlyDataAccepted)
            {
                byte[] eodMsg = HandshakeMessages.BuildEndOfEarlyData();
                await _record.WriteRecordAsync(ContentType.Handshake, eodMsg, ct).ConfigureAwait(false);
                _transcript.Update(eodMsg);
            }

            var (cKey, cIv) = _keySchedule.DeriveKeyAndIv(_keySchedule.ClientHandshakeTrafficSecret!);
            _record.SetWriteCipher(new AeadCipher(cKey, cIv, _keySchedule.Aead, _keySchedule.Suite));

            byte[] cfVerify = _keySchedule.ComputeFinishedVerifyData(
                _keySchedule.ClientHandshakeTrafficSecret!, _transcript.GetHash());
            byte[] cfMsg = HandshakeMessages.BuildFinished(cfVerify);
            await _record.WriteRecordAsync(ContentType.Handshake, cfMsg, ct).ConfigureAwait(false);
            _transcript.Update(cfMsg);

            byte[] fullHash = _transcript.GetHash();
            _keySchedule.DeriveResumptionMasterSecret(fullHash);
            InstallAppKeys();
            IsHandshakeComplete = true;
            return;
        }

        // 10. Check for CertificateRequest (mTLS) or Certificate / CompressedCertificate
        var (nextMsg, nextType) = await NextHandshakeAnyAsync(ct).ConfigureAwait(false);
        byte[]? certReqContext = null;
        SignatureScheme[]? certReqSigAlgorithms = null;

        if (nextType == HandshakeType.CertificateRequest)
        {
            _transcript.Update(nextMsg);
            var (_, crBody) = HandshakeMessages.Unframe(nextMsg);
            var (ctx, sigAlgs, _) = HandshakeMessages.ParseCertificateRequest(crBody);
            ValidateCertificateContext(ctx, Array.Empty<byte>(),
                "Initial CertificateRequest certificate_request_context must be empty");
            certReqContext = ctx;
            certReqSigAlgorithms = sigAlgs;
            _serverCertReqCompAlgs = HandshakeMessages.ParseCertReqCertCompression(crBody);
            (nextMsg, nextType) = await NextHandshakeAnyAsync(ct).ConfigureAwait(false);
        }
        else if (nextType != HandshakeType.Certificate && nextType != HandshakeType.CompressedCertificate)
        {
            AlertAndThrow(AlertDescription.UnexpectedMessage,
                $"Expected CertificateRequest or Certificate, got {nextType}");
        }

        // 11. Server Certificate (possibly compressed)
        _transcript.Update(nextMsg);
        byte[] certBody;
        if (nextType == HandshakeType.CompressedCertificate)
        {
            var (_, compBody) = HandshakeMessages.Unframe(nextMsg);
            certBody = HandshakeMessages.ParseCompressedCertificate(compBody, CertCompAdvertise);
        }
        else
        {
            (_, certBody) = HandshakeMessages.Unframe(nextMsg);
        }
        var (serverCertContext, serverCertEntries) = HandshakeMessages.ParseCertificateEx(certBody);
        ValidateCertificateContext(serverCertContext, Array.Empty<byte>(),
            "Server Certificate certificate_request_context must be empty");
        if (serverCertEntries.Count == 0)
            AlertAndThrow(AlertDescription.CertificateRequired, "Server sent empty certificate");
        byte[] serverCertDer = serverCertEntries[0].CertDer;
        PeerCertificateData = serverCertDer;
        if (_requestOcspStapling && serverCertEntries[0].OcspResponse != null)
            PeerOcspResponse = serverCertEntries[0].OcspResponse;
        ValidatePeerCertificate(serverCertDer, serverName);
        byte[][] serverIntermediates = new byte[serverCertEntries.Count - 1][];
        for (int ci = 1; ci < serverCertEntries.Count; ci++)
            serverIntermediates[ci - 1] = serverCertEntries[ci].CertDer;
        EnforceServerCertificateTrust(serverCertDer, serverIntermediates, serverName);

        // 12. CertificateVerify
        byte[] preCvHash = _transcript.GetHash();
        byte[] cvMsg = await NextHandshakeAsync(HandshakeType.CertificateVerify, ct).ConfigureAwait(false);
        var (_, cvBody) = HandshakeMessages.Unframe(cvMsg);
        var (sigScheme, sig) = HandshakeMessages.ParseCertificateVerify(cvBody);
        ValidateSignatureScheme(sigScheme);

        var (serverPubKey, _) = CertificateUtils.ParseCertificatePublicKey(serverCertDer);
        byte[] cvContent = HandshakeMessages.BuildCertVerifyContent(
            "TLS 1.3, server CertificateVerify", preCvHash);
        if (!CertificateUtils.Verify(cvContent, sig, serverPubKey, sigScheme))
            AlertAndThrow(AlertDescription.DecryptError, "Server CertificateVerify failed");

        _transcript.Update(cvMsg);

        // 13. Server Finished
        byte[] preFinHash2 = _transcript.GetHash();
        byte[] sfMsg2 = await NextHandshakeAsync(HandshakeType.Finished, ct).ConfigureAwait(false);
        var (_, sfBody2) = HandshakeMessages.Unframe(sfMsg2);

        byte[] expectedSF2 = _keySchedule.ComputeFinishedVerifyData(
            _keySchedule.ServerHandshakeTrafficSecret!, preFinHash2);
        if (!CryptographicOperations.FixedTimeEquals(sfBody2, expectedSF2))
            AlertAndThrow(AlertDescription.DecryptError, "Server Finished verification failed");

        _transcript.Update(sfMsg2);

        // 14. Derive application secrets
        _serverFinishedHash = _transcript.GetHash();
        _keySchedule.DeriveAppSecrets(_serverFinishedHash);
        LogAppSecrets();

        // 15. Send CCS then install client write cipher
        if (!_sentCcs)
            await _record.WriteChangeCipherSpecAsync(ct).ConfigureAwait(false);

        var (cKey2, cIv2) = _keySchedule.DeriveKeyAndIv(_keySchedule.ClientHandshakeTrafficSecret!);
        _record.SetWriteCipher(new AeadCipher(cKey2, cIv2, _keySchedule.Aead, _keySchedule.Suite));

        // 16. If mTLS: send client Certificate [+ CertificateVerify]
        if (certReqContext != null)
        {
            if (_certificate != null)
            {
                ValidateClientCertificateSignatureScheme(certReqSigAlgorithms!, _certificate.SignatureAlgorithm);
                byte[] clientCertMsg = HandshakeMessages.BuildCertificateMsg(
                    _certificate.DerData, certReqContext, _certificate.ChainCertificates);
                ushort clientCompAlg = SelectClientCertCompression();
                if (clientCompAlg != 0)
                    clientCertMsg = HandshakeMessages.BuildCompressedCertificate(clientCertMsg, clientCompAlg);
                await _record.WriteRecordAsync(ContentType.Handshake, clientCertMsg, ct).ConfigureAwait(false);
                _transcript.Update(clientCertMsg);

                byte[] clientCvContent = HandshakeMessages.BuildCertVerifyContent(
                    "TLS 1.3, client CertificateVerify", _transcript.GetHash());
                byte[] clientCvSig = CertificateUtils.Sign(clientCvContent,
                    _certificate.PrivateKey, _certificate.PublicKey, _certificate.SignatureAlgorithm);
                byte[] clientCvMsg = HandshakeMessages.BuildCertificateVerify(
                    _certificate.SignatureAlgorithm, clientCvSig);
                await _record.WriteRecordAsync(ContentType.Handshake, clientCvMsg, ct).ConfigureAwait(false);
                _transcript.Update(clientCvMsg);
            }
            else
            {
                byte[] emptyCertMsg = HandshakeMessages.BuildCertificateMsg(null, certReqContext);
                await _record.WriteRecordAsync(ContentType.Handshake, emptyCertMsg, ct).ConfigureAwait(false);
                _transcript.Update(emptyCertMsg);
            }
        }

        // 17. Client Finished
        byte[] cfVerify2 = _keySchedule.ComputeFinishedVerifyData(
            _keySchedule.ClientHandshakeTrafficSecret!, _transcript.GetHash());
        byte[] cfMsg2 = HandshakeMessages.BuildFinished(cfVerify2);
        await _record.WriteRecordAsync(ContentType.Handshake, cfMsg2, ct).ConfigureAwait(false);
        _transcript.Update(cfMsg2);

        // 18. Derive resumption master secret + switch to app keys
        byte[] fullHash2 = _transcript.GetHash();
        _keySchedule.DeriveResumptionMasterSecret(fullHash2);
        InstallAppKeys();
        IsHandshakeComplete = true;
    }

    // ================================================================
    //  Async server handshake
    // ================================================================

    public async Task HandshakeAsServerAsync(CancellationToken ct = default)
    {
        if (_certificate == null)
            throw new InvalidOperationException("Server certificate is required");

        // 1. Receive ClientHello
        byte[] chMsg = await NextHandshakeAsync(HandshakeType.ClientHello, ct).ConfigureAwait(false);
        var (_, chBody) = HandshakeMessages.Unframe(chMsg);
        var ch = HandshakeMessages.ParseClientHello(chBody);

        // ECH: decrypt the inner CH and drive the transcript off it (see the sync server for rationale).
        byte[] transcriptCh = ServerDecryptEch(chMsg, chBody, ref ch);
        _transcript.Update(transcriptCh);
        _peerAllowsPostHandshakeAuth = ch.OffersPostHandshakeAuth;

        // RFC 9149: Store ticket request count
        _ticketRequestCount = ch.TicketRequestCount;

        // 2-3. Try PSK resumption first
        CipherSuite suite = default;
        byte[]? psk = null;
        bool isPskResumption = false;
        bool certWithPsk = false;   // draft-ietf-tls-8773bis: cert + external PSK (full cert handshake)
        bool accept0Rtt = false;
        uint pskMaxEarlyData = 0;
        int selectedPskIndex = -1;
        bool selectedPskIsExternal = false;

        // draft-ietf-tls-8773bis §4: tls_cert_with_extern_psk MUST NOT be combined with early_data.
        if (ch.OffersCertWithExternPsk && ch.OffersEarlyData)
            AlertAndThrow(AlertDescription.IllegalParameter,
                "tls_cert_with_extern_psk MUST NOT be offered with early_data (draft-ietf-tls-8773bis)");

        // RFC 8446 §4.2.9 / §4.2.11 + RFC 9258: try ticket resumption first, then external PSK
        // (mirrors the sync HandshakeAsServer so external PSK works on the async path too).
        if (ch.PreSharedKeyData != null && ch.OffersPskDheKe && (_ticketEncryption != null || _externalPsk != null))
        {
            var (identities, ages, binders) = HandshakeMessages.ParsePreSharedKeyExtension(ch.PreSharedKeyData);
            for (int i = 0; i < identities.Length; i++)
            {
                byte[]? plaintext = _ticketEncryption?.Open(identities[i]);
                if (plaintext != null)
                {
                    var decoded = TicketEncryption.DecodeTicketState(plaintext);
                    if (decoded == null) continue;
                    var (resumptionSecret, ticketSuite, ageAdd, issuedAt, maxEarly) = decoded.Value;

                    if (Array.IndexOf(ch.CipherSuites, ticketSuite) < 0) continue;
                    if (!IsSupportedSuite(ticketSuite)) continue;
                    var elapsed = DateTime.UtcNow - issuedAt;
                    if (elapsed.TotalSeconds > 604800) continue;

                    uint reportedAgeMs = ages[i] - ageAdd;
                    uint expectedAgeMs = (uint)Math.Min(elapsed.TotalMilliseconds, uint.MaxValue);
                    long ageDelta = (long)reportedAgeMs - (long)expectedAgeMs;
                    if (ageDelta < 0) ageDelta = -ageDelta;
                    if (ageDelta > 10_000) continue;

                    psk = resumptionSecret;
                    var hashAlg = ticketSuite == CipherSuite.TLS_AES_256_GCM_SHA384
                        ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256;

                    var tempKs = new KeySchedule(ticketSuite, psk);
                    byte[] binderKey = tempKs.DeriveBinderKey();

                    int bindersLen = HandshakeMessages.PskBindersTailLength(binders);
                    byte[] truncatedCh = transcriptCh[..^bindersLen];
                    var binderTranscript = new TranscriptHash(hashAlg);
                    binderTranscript.Update(truncatedCh);
                    byte[] expectedBinder = HandshakeMessages.ComputePskBinder(
                        binderKey, binderTranscript.GetHash(), hashAlg);

                    if (CryptographicOperations.FixedTimeEquals(binders[i], expectedBinder))
                    {
                        isPskResumption = true;
                        selectedPskIndex = i;
                        selectedPskIsExternal = false;
                        suite = ticketSuite;
                        pskMaxEarlyData = maxEarly;
                        accept0Rtt = i == 0 && _accept0Rtt && ch.OffersEarlyData && maxEarly > 0
                            && _ticketEncryption!.TryMarkUsedForEarlyData(identities[i]);
                        break;
                    }
                }
                else if (_externalPsk != null && identities[i].AsSpan().SequenceEqual(BuildImportedIdentity(_externalPsk).AsSpan()))
                {
                    // External PSK (RFC 9258): suite must be offered + supported, age MUST be 0.
                    if (Array.IndexOf(ch.CipherSuites, _externalPsk.Suite) < 0) continue;
                    if (!IsSupportedSuite(_externalPsk.Suite)) continue;
                    if (ages[i] != 0) continue;

                    psk = DeriveExternalPskKey(_externalPsk);
                    var hashAlg = _externalPsk.Suite == CipherSuite.TLS_AES_256_GCM_SHA384
                        ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256;

                    // External PSKs use the "ext binder" label (RFC 8446 §4.2.11.2).
                    var tempKs = new KeySchedule(_externalPsk.Suite, psk);
                    byte[] binderKey = tempKs.DeriveBinderKey(external: true);

                    int bindersLen = HandshakeMessages.PskBindersTailLength(binders);
                    byte[] truncatedCh = transcriptCh[..^bindersLen];
                    var binderTranscript = new TranscriptHash(hashAlg);
                    binderTranscript.Update(truncatedCh);
                    byte[] expectedBinder = HandshakeMessages.ComputePskBinder(
                        binderKey, binderTranscript.GetHash(), hashAlg);

                    if (CryptographicOperations.FixedTimeEquals(binders[i], expectedBinder))
                    {
                        suite = _externalPsk.Suite;
                        selectedPskIndex = i;
                        selectedPskIsExternal = true;
                        if (ch.OffersCertWithExternPsk)
                        {
                            // draft-ietf-tls-8773bis: combine this external PSK with a full cert handshake.
                            certWithPsk = true;
                        }
                        else
                        {
                            isPskResumption = true;
                            pskMaxEarlyData = _externalPsk.MaxEarlyDataSize;
                            // External-PSK 0-RTT anti-replay: single-use the binder (bound to this exact
                            // ClientHello), requires a replay store; without one, fall back to 1-RTT.
                            accept0Rtt = i == 0 && _accept0Rtt && ch.OffersEarlyData && _externalPsk.MaxEarlyDataSize > 0
                                && _ticketEncryption != null
                                && _ticketEncryption.TryMarkUsedForEarlyData(binders[i]);
                        }
                        break;
                    }
                }
            }
        }

        if (!isPskResumption && !certWithPsk)
            suite = SelectCipherSuite(ch.CipherSuites);

        // 4. Initialize key schedule
        _keySchedule = (isPskResumption || certWithPsk) ? new KeySchedule(suite, psk) : new KeySchedule(suite);
        UsedCertWithExternalPsk = certWithPsk;
        _transcript.SetAlgorithm(_keySchedule.HashAlgorithm);

        // 5. Select key share
        var selectedKS = SelectKeyShare(ch.KeyShares);

        // 6. HRR if needed
        if (selectedKS == null || _forceHrr)
        {
            NamedGroup requestedGroup = SelectGroupForHrr(ch.SupportedGroups);

            _transcript.ReplaceWithMessageHash();

            byte[] hrrMsg = HandshakeMessages.BuildHelloRetryRequest(ch.SessionId, suite, requestedGroup, withEch: EchAccepted);
            PatchEchHrrConfirmation(hrrMsg); // ECH §7.2.1 (no-op unless ECH accepted)
            await _record.WriteRecordAsync(ContentType.Handshake, hrrMsg, ct).ConfigureAwait(false);
            _transcript.Update(hrrMsg);

            await _record.WriteChangeCipherSpecAsync(ct).ConfigureAwait(false);
            _sentCcs = true;

            byte[] ch2Msg = await NextHandshakeAsync(HandshakeType.ClientHello, ct).ConfigureAwait(false);

            // RFC 8446 §4.2.11.2: re-verify PSK binder in CH2
            var (_, ch2Body) = HandshakeMessages.Unframe(ch2Msg);
            var ch1 = ch; // CH1 (already swapped to the ECH inner above, if accepted)
            ch = HandshakeMessages.ParseClientHello(ch2Body);
            byte[] transcriptCh2 = ServerDecryptEch(ch2Msg, ch2Body, ref ch); // ECH: swap CH2 to its inner
            if (_enforceHrrConsistency) CheckHelloRetryConsistency(ch1, ch); // RFC 8446 §4.1.4

            _peerAllowsPostHandshakeAuth = ch.OffersPostHandshakeAuth;
            if (isPskResumption || certWithPsk)
            {
                if (ch.PreSharedKeyData == null)
                    AlertAndThrow(AlertDescription.MissingExtension,
                        "Second ClientHello after HRR omitted the selected PSK extension");
                var (_, _, binders2) = HandshakeMessages.ParsePreSharedKeyExtension(ch.PreSharedKeyData);
                if (selectedPskIndex >= 0 && selectedPskIndex < binders2.Length)
                {
                    int bindersLen2 = HandshakeMessages.PskBindersTailLength(binders2);
                    byte[] truncatedCh2 = transcriptCh2[..^bindersLen2];
                    var binderTranscript2 = _transcript.Clone();
                    binderTranscript2.Update(truncatedCh2);
                    byte[] binderKey2 = _keySchedule.DeriveBinderKey(external: selectedPskIsExternal);
                    byte[] expectedBinder2 = HandshakeMessages.ComputePskBinder(
                        binderKey2, binderTranscript2.GetHash(), _keySchedule.HashAlgorithm);

                    if (!CryptographicOperations.FixedTimeEquals(binders2[selectedPskIndex], expectedBinder2))
                    {
                        AlertAndThrow(AlertDescription.DecryptError,
                            "Second ClientHello PSK binder verification failed after HRR");
                    }
                }
                else
                {
                    AlertAndThrow(AlertDescription.IllegalParameter,
                        "Second ClientHello after HRR does not contain the selected PSK binder");
                }
            }

            _transcript.Update(transcriptCh2);

            selectedKS = FindKeyShare(ch.KeyShares, requestedGroup);
            if (selectedKS == null)
                AlertAndThrow(AlertDescription.IllegalParameter, "CH2 missing requested key share");
        }

        var (group, clientKey) = selectedKS.Value;
        _negotiatedGroup = group;

        // 7. Generate server key share and compute shared secret
        byte[] shared = ComputeServerSharedSecret(group, clientKey, out byte[] sPub);

        byte[] serverRandom = RandomnessWrapper.GetHandshakeBytes(32);
        _clientRandom = ch.ClientRandom;

        // 8. Send ServerHello (with PSK extension if resuming)
        byte[] shMsg;
        if (certWithPsk)
            // draft-ietf-tls-8773bis: echo tls_cert_with_extern_psk + the selected PSK; a full cert handshake follows.
            shMsg = HandshakeMessages.BuildServerHelloWithPsk(serverRandom, ch.SessionId, suite, group, sPub, (ushort)selectedPskIndex, certWithExternPsk: true);
        else if (isPskResumption)
            shMsg = HandshakeMessages.BuildServerHelloWithPsk(serverRandom, ch.SessionId, suite, group, sPub, (ushort)selectedPskIndex);
        else
            shMsg = HandshakeMessages.BuildServerHello(serverRandom, ch.SessionId, suite, group, sPub);
        PatchEchAcceptConfirmation(shMsg); // ECH §7.2 (no-op unless ECH accepted)
        await _record.WriteRecordAsync(ContentType.Handshake, shMsg, ct).ConfigureAwait(false);
        _transcript.Update(shMsg);

        // 9. Derive handshake secrets
        _keySchedule.DeriveHandshakeSecrets(shared, _transcript.GetHash());

        // Key logging
        if (KeyLogger.IsEnabled)
            KeyLogger.LogHandshakeTrafficSecrets(ch.ClientRandom,
                _keySchedule.ClientHandshakeTrafficSecret!, _keySchedule.ServerHandshakeTrafficSecret!);

        // 10. CCS for middlebox compat
        if (!_sentCcs) await _record.WriteChangeCipherSpecAsync(ct).ConfigureAwait(false);

        // 11. Install server handshake write cipher
        var (sKey, sIv) = _keySchedule.DeriveKeyAndIv(_keySchedule.ServerHandshakeTrafficSecret!);
        _record.SetWriteCipher(new AeadCipher(sKey, sIv, _keySchedule.Aead, _keySchedule.Suite));

        // 12. EncryptedExtensions (with ALPN and cert compression negotiation)
        string? negotiatedAlpn = NegotiateAlpn(ch.AlpnProtocols);
        _negotiatedAlpn = negotiatedAlpn;
        ushort certCompAlg = NegotiateCertCompression(ch.CertCompressionAlgorithms);
        byte[] eeMsg = HandshakeMessages.BuildEncryptedExtensions(accept0Rtt, negotiatedAlpn, certCompAlg,
            echRetryConfigs: EchServerRetryConfigs());
        await _record.WriteRecordAsync(ContentType.Handshake, eeMsg, ct).ConfigureAwait(false);
        _transcript.Update(eeMsg);

        if (isPskResumption)
        {
            // 13. Server Finished
            byte[] sfVerify = _keySchedule.ComputeFinishedVerifyData(
                _keySchedule.ServerHandshakeTrafficSecret!, _transcript.GetHash());
            byte[] sfMsg = HandshakeMessages.BuildFinished(sfVerify);
            await _record.WriteRecordAsync(ContentType.Handshake, sfMsg, ct).ConfigureAwait(false);
            _transcript.Update(sfMsg);

            _serverFinishedHash = _transcript.GetHash();
            _keySchedule.DeriveAppSecrets(_serverFinishedHash);
        LogAppSecrets();

            // 14. Read 0-RTT early data
            if (accept0Rtt)
            {
                var earlyTranscript = new TranscriptHash(_keySchedule.HashAlgorithm);
                earlyTranscript.Update(chMsg);
                byte[] earlyTrafficSecret = _keySchedule.DeriveClientEarlyTrafficSecret(earlyTranscript.GetHash());
                if (_clientRandom != null) KeyLogger.LogEarlyTrafficSecret(_clientRandom, earlyTrafficSecret);
                var (ek, eiv) = _keySchedule.DeriveKeyAndIv(earlyTrafficSecret);
                _record.SetReadCipher(new AeadCipher(ek, eiv, _keySchedule.Aead, _keySchedule.Suite));

                using var earlyBuf = new MemoryStream();
                bool gotEndOfEarlyData = false;
                while (!gotEndOfEarlyData)
                {
                    var (type, payload) = await _record.ReadRecordAsync(ct).ConfigureAwait(false);
                    if (type == ContentType.ApplicationData)
                    {
                        if (earlyBuf.Length + payload.Length > pskMaxEarlyData)
                            AlertAndThrow(AlertDescription.UnexpectedMessage,
                                "0-RTT data exceeded max_early_data_size");
                        earlyBuf.Write(payload);
                    }
                    else if (type == ContentType.Handshake)
                    {
                        EnqueueHandshake(payload);
                        gotEndOfEarlyData = true;
                    }
                    else if (type == ContentType.ChangeCipherSpec) continue;
                    else break;
                }
                ReceivedEarlyData = earlyBuf.Length > 0 ? earlyBuf.ToArray() : null;
                EarlyDataAccepted = true;
            }

            // 15. Install client handshake read cipher
            var (cKey, cIv) = _keySchedule.DeriveKeyAndIv(_keySchedule.ClientHandshakeTrafficSecret!);
            _record.SetReadCipher(new AeadCipher(cKey, cIv, _keySchedule.Aead, _keySchedule.Suite));

            // 15b. Skip rejected 0-RTT early data via trial decryption (RFC 8446 §4.2.10)
            if (!accept0Rtt && ch.OffersEarlyData)
            {
                long skipped = 0;
                while (skipped < _maxEarlyDataSize + TlsConst.MaxCiphertextLength)
                {
                    var result = await _record.TryReadRecordAsync(ct).ConfigureAwait(false);
                    if (result == null)
                    {
                        skipped += TlsConst.MaxCiphertextLength;
                        continue;
                    }
                    var (type, payload) = result.Value;
                    if (type == ContentType.ChangeCipherSpec) continue;
                    if (type == ContentType.Handshake)
                    {
                        EnqueueHandshake(payload);
                    }
                    break;
                }
            }

            // 16. EndOfEarlyData
            if (accept0Rtt)
            {
                byte[] eodMsg = await NextHandshakeAsync(HandshakeType.EndOfEarlyData, ct).ConfigureAwait(false);
                _transcript.Update(eodMsg);
            }

            // 17. Client Finished
            byte[] cfMsg = await NextHandshakeAsync(HandshakeType.Finished, ct).ConfigureAwait(false);
            var (_, cfBody) = HandshakeMessages.Unframe(cfMsg);

            byte[] expectedCF = _keySchedule.ComputeFinishedVerifyData(
                _keySchedule.ClientHandshakeTrafficSecret!, _transcript.GetHash());
            if (!CryptographicOperations.FixedTimeEquals(cfBody, expectedCF))
                AlertAndThrow(AlertDescription.DecryptError, "Client Finished verification failed");

            _transcript.Update(cfMsg);
            byte[] fullHashPsk = _transcript.GetHash();
            _keySchedule.DeriveResumptionMasterSecret(fullHashPsk);
            InstallAppKeys();
            IsHandshakeComplete = true;
            IsResumed = true;

            { int ticketCount = EffectiveTicketCount(ch); if (ticketCount > 0) await SendNewSessionTicketAsync((ushort)ticketCount, ct).ConfigureAwait(false); }
            return;
        }

        // 14. CertificateRequest (if mTLS)
        if (_requireClientCert)
        {
            byte[] crMsg = HandshakeMessages.BuildCertificateRequest(Array.Empty<byte>(), _offeredSigAlgs ?? AdvertisedSigAlgs,
                certCompAlgs: _useCertCompression ? CertCompAdvertise : null);
            await _record.WriteRecordAsync(ContentType.Handshake, crMsg, ct).ConfigureAwait(false);
            _transcript.Update(crMsg);
        }

        // RFC 8446 §4.2.3: the server's signature scheme must be one the client advertised.
        ValidateServerCertSigAlg(ch);

        // 15. Certificate (with chain, optionally compressed, optionally OCSP-stapled)
        byte[]? stapleResponse = (ch.RequestsOcspStapling && _ocspResponse != null) ? _ocspResponse : null;
        byte[] certMsg = HandshakeMessages.BuildCertificate(_certificate.DerData, _certificate.ChainCertificates, stapleResponse);
        if (certCompAlg != 0)
        {
            byte[] compMsg = HandshakeMessages.BuildCompressedCertificate(certMsg, certCompAlg);
            await _record.WriteRecordAsync(ContentType.Handshake, compMsg, ct).ConfigureAwait(false);
            _transcript.Update(compMsg);
        }
        else
        {
            await _record.WriteRecordAsync(ContentType.Handshake, certMsg, ct).ConfigureAwait(false);
            _transcript.Update(certMsg);
        }

        // 16. CertificateVerify
        byte[] cvContent = HandshakeMessages.BuildCertVerifyContent(
            "TLS 1.3, server CertificateVerify", _transcript.GetHash());
        byte[] cvSig = CertificateUtils.Sign(cvContent,
            _certificate.PrivateKey, _certificate.PublicKey, _certificate.SignatureAlgorithm);
        byte[] cvMsg = HandshakeMessages.BuildCertificateVerify(_certificate.SignatureAlgorithm, cvSig);
        await _record.WriteRecordAsync(ContentType.Handshake, cvMsg, ct).ConfigureAwait(false);
        _transcript.Update(cvMsg);

        // 17. Server Finished
        byte[] sfVerify2 = _keySchedule.ComputeFinishedVerifyData(
            _keySchedule.ServerHandshakeTrafficSecret!, _transcript.GetHash());
        byte[] sfMsg2 = HandshakeMessages.BuildFinished(sfVerify2);
        await _record.WriteRecordAsync(ContentType.Handshake, sfMsg2, ct).ConfigureAwait(false);
        _transcript.Update(sfMsg2);

        // 18. Derive application secrets
        _serverFinishedHash = _transcript.GetHash();
        _keySchedule.DeriveAppSecrets(_serverFinishedHash);
        LogAppSecrets();

        // 19. Install client handshake read cipher
        var (cKey2, cIv2) = _keySchedule.DeriveKeyAndIv(_keySchedule.ClientHandshakeTrafficSecret!);
        _record.SetReadCipher(new AeadCipher(cKey2, cIv2, _keySchedule.Aead, _keySchedule.Suite));

        // 20. If mTLS: receive client Certificate [+ CertificateVerify]
        if (_requireClientCert)
        {
            var (clientCertMsg, clientCertType) = await NextHandshakeAnyAsync(ct).ConfigureAwait(false);
            if (clientCertType != HandshakeType.Certificate && clientCertType != HandshakeType.CompressedCertificate)
                AlertAndThrow(AlertDescription.UnexpectedMessage, $"Expected client Certificate, got {clientCertType}");
            _transcript.Update(clientCertMsg);
            var (_, clientCertRaw) = HandshakeMessages.Unframe(clientCertMsg);
            if (clientCertType == HandshakeType.CompressedCertificate)
            {
                if (clientCertRaw.Length < 2)
                    AlertAndThrow(AlertDescription.DecodeError, "CompressedCertificate missing algorithm");
                ushort clientCompAlg = BinaryHelper.ReadUInt16(clientCertRaw.AsSpan(0));
                if (!_useCertCompression || Array.IndexOf(CertCompAdvertise, clientCompAlg) < 0)
                    AlertAndThrow(AlertDescription.BadCertificate,
                        $"Client used an unadvertised certificate compression algorithm: {clientCompAlg}");
            }
            byte[] clientCertBody = clientCertType == HandshakeType.CompressedCertificate
                ? HandshakeMessages.ParseCompressedCertificate(clientCertRaw)
                : clientCertRaw;
            var (clientCertContext, clientCertEntries) = HandshakeMessages.ParseCertificateEx(clientCertBody);
            ValidateCertificateContext(clientCertContext, Array.Empty<byte>(),
                "Initial client Certificate certificate_request_context must be empty");

            if (clientCertEntries.Count > 0)
            {
                byte[] clientCertDer = clientCertEntries[0].CertDer;
                PeerCertificateData = clientCertDer;

                if (_caCertificate != null)
                {
                    var clientCertObj = new TlsCertificate
                    {
                        DerData = clientCertDer,
                        PrivateKey = Array.Empty<byte>(),
                        PublicKey = Array.Empty<byte>(),
                        SignatureAlgorithm = SignatureScheme.EcdsaSecp256r1Sha256
                    };
                    byte[][] clientIntermediates = new byte[clientCertEntries.Count - 1][];
                    for (int ci = 1; ci < clientCertEntries.Count; ci++)
                        clientIntermediates[ci - 1] = clientCertEntries[ci].CertDer;
                    if (!CertificateUtils.VerifyChain(clientCertObj, clientIntermediates, _caCertificate))
                        AlertAndThrow(AlertDescription.BadCertificate,
                            "Client certificate not signed by trusted CA");
                }

                byte[] preCvHash = _transcript.GetHash();
                byte[] clientCvMsg = await NextHandshakeAsync(HandshakeType.CertificateVerify, ct).ConfigureAwait(false);
                var (_, clientCvBody) = HandshakeMessages.Unframe(clientCvMsg);
                var (clientSigScheme, clientSig) = HandshakeMessages.ParseCertificateVerify(clientCvBody);
                ValidateSignatureScheme(clientSigScheme);

                var (clientPubKey, _) = CertificateUtils.ParseCertificatePublicKey(clientCertDer);
                byte[] clientCvContent = HandshakeMessages.BuildCertVerifyContent(
                    "TLS 1.3, client CertificateVerify", preCvHash);
                if (!CertificateUtils.Verify(clientCvContent, clientSig, clientPubKey, clientSigScheme))
                    AlertAndThrow(AlertDescription.DecryptError, "Client CertificateVerify failed");

                _transcript.Update(clientCvMsg);
            }
            else
            {
                AlertAndThrow(AlertDescription.CertificateRequired,
                    "Client certificate required but not provided");
            }
        }

        // 21. Receive client Finished
        byte[] cfMsg2 = await NextHandshakeAsync(HandshakeType.Finished, ct).ConfigureAwait(false);
        var (_, cfBody2) = HandshakeMessages.Unframe(cfMsg2);

        byte[] expectedCF2 = _keySchedule.ComputeFinishedVerifyData(
            _keySchedule.ClientHandshakeTrafficSecret!, _transcript.GetHash());
        if (!CryptographicOperations.FixedTimeEquals(cfBody2, expectedCF2))
            AlertAndThrow(AlertDescription.DecryptError, "Client Finished verification failed");

        _transcript.Update(cfMsg2);

        // 22. Derive resumption master secret + switch to app keys
        byte[] fullHashFull = _transcript.GetHash();
        _keySchedule.DeriveResumptionMasterSecret(fullHashFull);
        InstallAppKeys();
        IsHandshakeComplete = true;

        { int ticketCount = EffectiveTicketCount(ch); if (ticketCount > 0) await SendNewSessionTicketAsync((ushort)ticketCount, ct).ConfigureAwait(false); }
    }
}
