namespace TLS;

using System.Security.Cryptography;

/// <summary>TLS 1.3 handshake message construction and parsing.</summary>
public static class HandshakeMessages
{
    // HelloRetryRequest sentinel: SHA-256("HelloRetryRequest")
    private static readonly byte[] HrrSentinel =
    {
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
    };

    // ================================================================
    //  Generic framing
    // ================================================================

    public static byte[] Frame(HandshakeType type, byte[] body)
    {
        byte[] msg = new byte[4 + body.Length];
        msg[0] = (byte)type;
        BinaryHelper.WriteUInt24(msg.AsSpan(1), (uint)body.Length);
        Buffer.BlockCopy(body, 0, msg, 4, body.Length);
        return msg;
    }

    public static (HandshakeType type, byte[] body) Unframe(byte[] data)
    {
        if (data.Length < 4)
            throw new TlsException(AlertDescription.DecodeError, "Handshake message too short to unframe");
        var type = (HandshakeType)data[0];
        uint len = BinaryHelper.ReadUInt24(data.AsSpan(1));
        if (4 + len > (uint)data.Length)
            throw new TlsException(AlertDescription.DecodeError, $"Handshake body length {len} exceeds data");
        return (type, data[4..(4 + (int)len)]);
    }

    // ================================================================
    //  ClientHello
    // ================================================================

    public static byte[] BuildClientHello(byte[] clientRandom, byte[] sessionId,
        CipherSuite[] suites, (NamedGroup group, byte[] pubKey)[] keyShares,
        string? serverName = null, byte[]? cookie = null, string[]? alpnProtocols = null,
        bool requestOcspStapling = false, ushort ticketRequestCount = 0)
    {
        return BuildClientHelloInner(clientRandom, sessionId, suites, keyShares,
            serverName, cookie, null, false, alpnProtocols, requestOcspStapling, ticketRequestCount);
    }

    /// <summary>Build ClientHello with PSK and optional early_data extension.</summary>
    public static byte[] BuildClientHelloWithPsk(byte[] clientRandom, byte[] sessionId,
        CipherSuite[] suites, (NamedGroup group, byte[] pubKey)[] keyShares,
        byte[] pskIdentity, uint obfuscatedAge, byte[] binderPlaceholder,
        bool offerEarlyData, string? serverName = null, byte[]? cookie = null,
        string[]? alpnProtocols = null, bool requestOcspStapling = false,
        ushort ticketRequestCount = 0)
    {
        return BuildClientHelloInner(clientRandom, sessionId, suites, keyShares,
            serverName, cookie, (pskIdentity, obfuscatedAge, binderPlaceholder), offerEarlyData,
            alpnProtocols, requestOcspStapling, ticketRequestCount);
    }

    /// <summary>
    /// Patch the PSK binder in an already-built ClientHello message.
    /// The binder sits at the very end of the message.
    /// </summary>
    public static void PatchPskBinder(byte[] chMsg, byte[] binder)
    {
        // Binder is the last N bytes of the message (preceded by its 1-byte length)
        Buffer.BlockCopy(binder, 0, chMsg, chMsg.Length - binder.Length, binder.Length);
    }

    /// <summary>
    /// Compute the length of the binders list at the end of a ClientHello.
    /// For a single binder: 2 (binders list length) + 1 (binder entry length) + binderLen
    /// </summary>
    public static int PskBindersTailLength(int binderLen)
    {
        return 2 + 1 + binderLen; // list_len(2) + entry_len(1) + binder
    }

    public static byte[] BuildClientHelloInner(byte[] clientRandom, byte[] sessionId,
        CipherSuite[] suites, (NamedGroup group, byte[] pubKey)[] keyShares,
        string? serverName, byte[]? cookie,
        (byte[] identity, uint age, byte[] binder)? psk, bool offerEarlyData,
        string[]? alpnProtocols, bool requestOcspStapling, ushort ticketRequestCount = 0)
    {
        using var ms = new MemoryStream();

        BinaryHelper.WriteUInt16(ms, TlsConst.LegacyVersion); // legacy_version
        ms.Write(clientRandom);                                 // random (32)

        ms.WriteByte((byte)sessionId.Length);                   // session_id
        ms.Write(sessionId);

        // cipher_suites — prepend a GREASE value (RFC 8701); the peer MUST ignore it
        BinaryHelper.WriteUInt16(ms, (ushort)((suites.Length + 1) * 2));
        BinaryHelper.WriteUInt16(ms, Grease.CipherSuite);
        foreach (var s in suites) BinaryHelper.WriteUInt16(ms, (ushort)s);

        ms.WriteByte(1); ms.WriteByte(0);                       // compression_methods = {null}

        byte[] ext = BuildClientHelloExtensions(keyShares, serverName, cookie,
            psk, offerEarlyData, alpnProtocols, requestOcspStapling, ticketRequestCount, null);
        BinaryHelper.WriteUInt16(ms, (ushort)ext.Length);       // extensions length
        ms.Write(ext);

        return Frame(HandshakeType.ClientHello, ms.ToArray());
    }

    public static ParsedClientHello ParseClientHello(byte[] body)
    {
        int p = 0;
        EnsureRemaining(body, p, 2 + 32 + 1, "ClientHello fixed header");
        p += 2; // legacy_version
        byte[] clientRandom = body[p..(p + 32)]; p += 32;

        int sidLen = body[p++];
        EnsureRemaining(body, p, sidLen + 2, "ClientHello session_id");
        byte[] sessionId = body[p..(p + sidLen)]; p += sidLen;

        ushort suitesLen = BinaryHelper.ReadUInt16(body.AsSpan(p)); p += 2;
        if ((suitesLen & 1) != 0)
            throw new TlsException(AlertDescription.DecodeError, "ClientHello cipher_suites length must be even");
        EnsureRemaining(body, p, suitesLen + 1, "ClientHello cipher_suites");
        var suites = new List<CipherSuite>();
        for (int i = 0; i < suitesLen / 2; i++)
        { suites.Add((CipherSuite)BinaryHelper.ReadUInt16(body.AsSpan(p))); p += 2; }

        int compLen = body[p++];
        EnsureRemaining(body, p, compLen, "ClientHello compression_methods");
        p += compLen; // skip compression

        var keyShares = new List<(NamedGroup, byte[])>();
        var supportedGroups = new List<NamedGroup>();
        string? sni = null;
        byte[]? pskData = null;
        bool offersEarlyData = false;
        bool requestsOcspStapling = false;
        string[]? alpnProtocols = null;
        ushort[]? certCompAlgorithms = null;
        ushort ticketRequestCount = 0;
        ushort recordSizeLimit = 0;
        SignatureScheme[]? sigAlgsCert = null;
        byte[]? echData = null;
        bool isOuterCH = false;

        if (p < body.Length)
        {
            EnsureRemaining(body, p, 2, "ClientHello extensions length");
            ushort extLen = BinaryHelper.ReadUInt16(body.AsSpan(p)); p += 2;
            EnsureRemaining(body, p, extLen, "ClientHello extensions block");
            int extEnd = p + extLen;
            while (p < extEnd)
            {
                var (et, ed, np) = ReadExtension(body, p); p = np;
                if (et == ExtensionType.KeyShare)
                {
                    EnsureRemaining(ed, 0, 2, "key_share list length");
                    ushort listLen = BinaryHelper.ReadUInt16(ed.AsSpan(0));
                    EnsureRemaining(ed, 2, listLen, "key_share list");
                    int kp = 2;
                    int kEnd = 2 + listLen;
                    while (kp < kEnd)
                    {
                        EnsureRemaining(ed, kp, 4, "key_share entry header");
                        var group = (NamedGroup)BinaryHelper.ReadUInt16(ed.AsSpan(kp)); kp += 2;
                        ushort kl = BinaryHelper.ReadUInt16(ed.AsSpan(kp)); kp += 2;
                        EnsureRemaining(ed, kp, kl, "key_share key bytes");
                        keyShares.Add((group, ed[kp..(kp + kl)]));
                        kp += kl;
                    }
                }
                else if (et == ExtensionType.SupportedGroups)
                {
                    EnsureRemaining(ed, 0, 2, "supported_groups length");
                    ushort groupsLen = BinaryHelper.ReadUInt16(ed.AsSpan(0));
                    if ((groupsLen & 1) != 0)
                        throw new TlsException(AlertDescription.DecodeError, "supported_groups length must be even");
                    EnsureRemaining(ed, 2, groupsLen, "supported_groups list");
                    int gp = 2;
                    int gEnd = 2 + groupsLen;
                    while (gp < gEnd)
                    {
                        supportedGroups.Add((NamedGroup)BinaryHelper.ReadUInt16(ed.AsSpan(gp)));
                        gp += 2;
                    }
                }
                else if (et == ExtensionType.ServerName)
                {
                    EnsureRemaining(ed, 0, 5, "server_name header");
                    int sp = 2; // skip list length
                    sp++;       // skip name type
                    ushort nl = BinaryHelper.ReadUInt16(ed.AsSpan(sp)); sp += 2;
                    EnsureRemaining(ed, sp, nl, "server_name host_name");
                    sni = System.Text.Encoding.ASCII.GetString(ed, sp, nl);
                }
                else if (et == ExtensionType.PreSharedKey)
                {
                    pskData = ed;
                }
                else if (et == ExtensionType.EarlyData)
                {
                    offersEarlyData = true;
                }
                else if (et == ExtensionType.StatusRequest)
                {
                    requestsOcspStapling = true;
                }
                else if (et == ExtensionType.Alpn)
                {
                    var protos = new List<string>();
                    EnsureRemaining(ed, 0, 2, "ALPN list length");
                    ushort listLen = BinaryHelper.ReadUInt16(ed.AsSpan(0));
                    EnsureRemaining(ed, 2, listLen, "ALPN protocol list");
                    int ap = 2;
                    int apEnd = 2 + listLen;
                    while (ap < apEnd)
                    {
                        EnsureRemaining(ed, ap, 1, "ALPN proto length byte");
                        int pLen = ed[ap++];
                        EnsureRemaining(ed, ap, pLen, "ALPN proto name");
                        protos.Add(System.Text.Encoding.ASCII.GetString(ed, ap, pLen));
                        ap += pLen;
                    }
                    alpnProtocols = protos.ToArray();
                }
                else if (et == ExtensionType.CertificateCompression)
                {
                    EnsureRemaining(ed, 0, 1, "compress_certificate length byte");
                    int algBytes = ed[0];
                    if ((algBytes & 1) != 0)
                        throw new TlsException(AlertDescription.DecodeError, "compress_certificate list length must be even");
                    EnsureRemaining(ed, 1, algBytes, "compress_certificate algorithm list");
                    int numAlgs = algBytes / 2;
                    certCompAlgorithms = new ushort[numAlgs];
                    for (int a = 0; a < numAlgs; a++)
                        certCompAlgorithms[a] = BinaryHelper.ReadUInt16(ed.AsSpan(1 + a * 2));
                }
                else if (et == ExtensionType.TicketRequest)
                {
                    // RFC 9149 §3: ticket_request_count is a uint16
                    if (ed.Length >= 2)
                        ticketRequestCount = BinaryHelper.ReadUInt16(ed.AsSpan(0));
                }
                else if (et == ExtensionType.SignatureAlgorithmsCert)
                {
                    // RFC 8446 §4.2.3: signature_algorithms_cert extension
                    if (ed.Length >= 2)
                    {
                        ushort algLen = BinaryHelper.ReadUInt16(ed.AsSpan(0));
                        var certSigAlgs = new List<SignatureScheme>();
                        for (int i = 0; i < algLen / 2; i++)
                            certSigAlgs.Add((SignatureScheme)BinaryHelper.ReadUInt16(ed.AsSpan(2 + i * 2)));
                        sigAlgsCert = certSigAlgs.ToArray();
                    }
                }
                else if (et == ExtensionType.EncryptedClientHello)
                {
                    // RFC 9849: encrypted_client_hello extension
                    echData = ed.ToArray();
                    isOuterCH = true; // Presence of ECH extension indicates this is an outer ClientHello
                }
                else if (et == ExtensionType.RecordSizeLimit && ed.Length >= 2)
                {
                    recordSizeLimit = BinaryHelper.ReadUInt16(ed.AsSpan()); // RFC 8449
                }
            }
        }

        return new ParsedClientHello
        {
            ClientRandom = clientRandom,
            SessionId = sessionId,
            CipherSuites = suites.ToArray(),
            KeyShares = keyShares.ToArray(),
            SupportedGroups = supportedGroups.Count > 0 ? supportedGroups.ToArray() : null,
            ServerName = sni,
            PreSharedKeyData = pskData,
            OffersEarlyData = offersEarlyData,
            RequestsOcspStapling = requestsOcspStapling,
            AlpnProtocols = alpnProtocols,
            CertCompressionAlgorithms = certCompAlgorithms,
            TicketRequestCount = ticketRequestCount,
            RecordSizeLimit = recordSizeLimit,
            SignatureAlgorithmsCert = sigAlgsCert,
            EncryptedClientHelloData = echData,
            IsOuterClientHello = isOuterCH
        };
    }

    // ================================================================
    //  ServerHello / HelloRetryRequest
    // ================================================================

    public static byte[] BuildServerHello(byte[] serverRandom, byte[] sessionId,
        CipherSuite suite, NamedGroup group, byte[] pubKey)
    {
        using var ms = new MemoryStream();

        BinaryHelper.WriteUInt16(ms, TlsConst.LegacyVersion);
        ms.Write(serverRandom);

        ms.WriteByte((byte)sessionId.Length);
        ms.Write(sessionId);

        BinaryHelper.WriteUInt16(ms, (ushort)suite);
        ms.WriteByte(0); // compression = null

        // Extensions
        using var ems = new MemoryStream();
        // supported_versions → TLS 1.3
        WriteExtension(ems, ExtensionType.SupportedVersions, UInt16Bytes(TlsConst.Tls13Version));
        // key_share: group + key
        {
            using var ks = new MemoryStream();
            BinaryHelper.WriteUInt16(ks, (ushort)group);
            BinaryHelper.WriteUInt16(ks, (ushort)pubKey.Length);
            ks.Write(pubKey);
            WriteExtension(ems, ExtensionType.KeyShare, ks.ToArray());
        }

        byte[] extBytes = ems.ToArray();
        BinaryHelper.WriteUInt16(ms, (ushort)extBytes.Length);
        ms.Write(extBytes);

        return Frame(HandshakeType.ServerHello, ms.ToArray());
    }

    /// <summary>Build a HelloRetryRequest (encoded as ServerHello with sentinel random).</summary>
    public static byte[] BuildHelloRetryRequest(byte[] sessionId, CipherSuite suite, NamedGroup requestedGroup)
    {
        using var ms = new MemoryStream();

        BinaryHelper.WriteUInt16(ms, TlsConst.LegacyVersion);
        ms.Write(HrrSentinel); // sentinel random

        ms.WriteByte((byte)sessionId.Length);
        ms.Write(sessionId);

        BinaryHelper.WriteUInt16(ms, (ushort)suite);
        ms.WriteByte(0); // compression = null

        // Extensions
        using var ems = new MemoryStream();
        WriteExtension(ems, ExtensionType.SupportedVersions, UInt16Bytes(TlsConst.Tls13Version));
        // key_share for HRR: just the selected group (2 bytes)
        WriteExtension(ems, ExtensionType.KeyShare, UInt16Bytes((ushort)requestedGroup));

        byte[] extBytes = ems.ToArray();
        BinaryHelper.WriteUInt16(ms, (ushort)extBytes.Length);
        ms.Write(extBytes);

        return Frame(HandshakeType.ServerHello, ms.ToArray());
    }

    public static ParsedServerHello ParseServerHello(byte[] body)
    {
        int p = 0;
        EnsureRemaining(body, p, 2 + 32 + 1, "ServerHello fixed header");
        p += 2; // legacy_version
        byte[] serverRandom = body[p..(p + 32)]; p += 32;

        bool isHrr = serverRandom.AsSpan().SequenceEqual(HrrSentinel);

        int sidLen = body[p++];
        EnsureRemaining(body, p, sidLen + 2 + 1 + 2, "ServerHello session_id + suite + compression + ext_len");
        byte[] sessionId = body[p..(p + sidLen)]; p += sidLen;

        var suite = (CipherSuite)BinaryHelper.ReadUInt16(body.AsSpan(p)); p += 2;
        p++; // compression

        NamedGroup keyShareGroup = 0;
        byte[]? keyShare = null;
        byte[]? cookie = null;
        int selectedPsk = -1;

        ushort extLen = BinaryHelper.ReadUInt16(body.AsSpan(p)); p += 2;
        EnsureRemaining(body, p, extLen, "ServerHello extensions block");
        int extEnd = p + extLen;
        while (p < extEnd)
        {
            var (et, ed, np) = ReadExtension(body, p); p = np;
            if (et == ExtensionType.KeyShare)
            {
                EnsureRemaining(ed, 0, 2, "ServerHello key_share group");
                keyShareGroup = (NamedGroup)BinaryHelper.ReadUInt16(ed.AsSpan(0));
                if (!isHrr)
                {
                    // Normal SH: group(2) + key_len(2) + key(...)
                    EnsureRemaining(ed, 2, 2, "ServerHello key_share length");
                    int kp = 2;
                    ushort kl = BinaryHelper.ReadUInt16(ed.AsSpan(kp)); kp += 2;
                    EnsureRemaining(ed, kp, kl, "ServerHello key_share key bytes");
                    keyShare = ed[kp..(kp + kl)];
                }
                // HRR: just the group (2 bytes), keyShare stays null
            }
            else if (et == ExtensionType.Cookie)
            {
                EnsureRemaining(ed, 0, 2, "cookie length");
                ushort cookieLen = BinaryHelper.ReadUInt16(ed.AsSpan(0));
                EnsureRemaining(ed, 2, cookieLen, "cookie data");
                cookie = ed[2..(2 + cookieLen)];
            }
            else if (et == ExtensionType.PreSharedKey)
            {
                EnsureRemaining(ed, 0, 2, "PSK selected_identity");
                selectedPsk = BinaryHelper.ReadUInt16(ed.AsSpan(0));
            }
        }

        if (!isHrr && keyShare == null && selectedPsk < 0)
            throw new TlsException(AlertDescription.MissingExtension, "ServerHello missing KeyShare extension");

        return new ParsedServerHello
        {
            ServerRandom = serverRandom,
            SessionId = sessionId,
            CipherSuite = suite,
            KeyShareGroup = keyShareGroup,
            KeyShare = keyShare,
            IsHelloRetryRequest = isHrr,
            Cookie = cookie,
            SelectedPskIndex = selectedPsk
        };
    }

    // ================================================================
    //  EncryptedExtensions
    // ================================================================

    public static byte[] BuildEncryptedExtensions(bool acceptEarlyData = false,
        string? alpnProtocol = null, ushort certCompressionAlgorithm = 0,
        ushort recordSizeLimit = 0)
    {
        using var ms = new MemoryStream();
        using var ext = new MemoryStream();

        if (acceptEarlyData)
            WriteExtension(ext, ExtensionType.EarlyData, Array.Empty<byte>());

        if (recordSizeLimit > 0)
        {
            byte[] rsl = new byte[2];
            BinaryHelper.WriteUInt16(rsl.AsSpan(), recordSizeLimit);
            WriteExtension(ext, ExtensionType.RecordSizeLimit, rsl);
        }

        if (alpnProtocol != null)
        {
            byte[] proto = System.Text.Encoding.ASCII.GetBytes(alpnProtocol);
            using var alpnBody = new MemoryStream();
            ushort listLen = (ushort)(1 + proto.Length);
            BinaryHelper.WriteUInt16(alpnBody, listLen);
            alpnBody.WriteByte((byte)proto.Length);
            alpnBody.Write(proto);
            WriteExtension(ext, ExtensionType.Alpn, alpnBody.ToArray());
        }

        if (certCompressionAlgorithm != 0)
        {
            byte[] ccBody = new byte[3];
            ccBody[0] = 2; // byte length of algorithms list (one 2-byte entry)
            BinaryHelper.WriteUInt16(ccBody.AsSpan(1), certCompressionAlgorithm);
            WriteExtension(ext, ExtensionType.CertificateCompression, ccBody);
        }

        byte[] extBytes = ext.ToArray();
        BinaryHelper.WriteUInt16(ms, (ushort)extBytes.Length);
        if (extBytes.Length > 0) ms.Write(extBytes);
        return Frame(HandshakeType.EncryptedExtensions, ms.ToArray());
    }

    /// <summary>Parse EncryptedExtensions. Returns early_data accepted, negotiated ALPN, cert compression alg.</summary>
    public static ParsedEncryptedExtensions ParseEncryptedExtensionsEx(byte[] body)
    {
        bool earlyData = false;
        string? alpn = null;
        ushort certComp = 0;
        ushort recordSizeLimit = 0;

        int p = 0;
        if (body.Length < 2) return new ParsedEncryptedExtensions();
        ushort extLen = BinaryHelper.ReadUInt16(body.AsSpan(p)); p += 2;
        int extEnd = p + extLen;
        while (p < extEnd)
        {
            var (et, ed, np) = ReadExtension(body, p); p = np;
            if (et == ExtensionType.EarlyData)
                earlyData = true;
            else if (et == ExtensionType.Alpn && ed.Length >= 4)
            {
                int ap = 2; // skip list length
                int pLen = ed[ap++];
                alpn = System.Text.Encoding.ASCII.GetString(ed, ap, pLen);
            }
            else if (et == ExtensionType.CertificateCompression && ed.Length >= 3)
            {
                certComp = BinaryHelper.ReadUInt16(ed.AsSpan(1));
            }
            else if (et == ExtensionType.RecordSizeLimit && ed.Length >= 2)
            {
                recordSizeLimit = BinaryHelper.ReadUInt16(ed.AsSpan());
            }
        }

        return new ParsedEncryptedExtensions
        {
            AcceptEarlyData = earlyData,
            AlpnProtocol = alpn,
            CertCompressionAlgorithm = certComp,
            RecordSizeLimit = recordSizeLimit
        };
    }

    /// <summary>Parse EncryptedExtensions and return whether early_data was accepted.</summary>
    public static bool ParseEncryptedExtensions(byte[] body) =>
        ParseEncryptedExtensionsEx(body).AcceptEarlyData;

    /// <summary>Build ServerHello with pre_shared_key extension (for PSK resumption).</summary>
    public static byte[] BuildServerHelloWithPsk(byte[] serverRandom, byte[] sessionId,
        CipherSuite suite, NamedGroup group, byte[] pubKey, ushort selectedPskIndex)
    {
        using var ms = new MemoryStream();

        BinaryHelper.WriteUInt16(ms, TlsConst.LegacyVersion);
        ms.Write(serverRandom);

        ms.WriteByte((byte)sessionId.Length);
        ms.Write(sessionId);

        BinaryHelper.WriteUInt16(ms, (ushort)suite);
        ms.WriteByte(0); // compression = null

        // Extensions
        using var ems = new MemoryStream();
        WriteExtension(ems, ExtensionType.SupportedVersions, UInt16Bytes(TlsConst.Tls13Version));
        // key_share
        {
            using var ks = new MemoryStream();
            BinaryHelper.WriteUInt16(ks, (ushort)group);
            BinaryHelper.WriteUInt16(ks, (ushort)pubKey.Length);
            ks.Write(pubKey);
            WriteExtension(ems, ExtensionType.KeyShare, ks.ToArray());
        }
        // pre_shared_key (selected index)
        WriteExtension(ems, ExtensionType.PreSharedKey, BuildPreSharedKeyServerExtension(selectedPskIndex));

        byte[] extBytes = ems.ToArray();
        BinaryHelper.WriteUInt16(ms, (ushort)extBytes.Length);
        ms.Write(extBytes);

        return Frame(HandshakeType.ServerHello, ms.ToArray());
    }

    // ================================================================
    //  CertificateRequest (mTLS)
    // ================================================================

    /// <summary>Build a CertificateRequest message (server → client, mTLS).</summary>
    public static byte[] BuildCertificateRequest(byte[] context, SignatureScheme[] sigAlgorithms,
        SignatureScheme[]? certSigAlgorithms = null)
    {
        using var ms = new MemoryStream();
        ms.WriteByte((byte)context.Length);
        ms.Write(context);

        // Extensions — signature_algorithms is mandatory
        using var ext = new MemoryStream();
        using var sigBody = new MemoryStream();
        BinaryHelper.WriteUInt16(sigBody, (ushort)(sigAlgorithms.Length * 2));
        foreach (var s in sigAlgorithms) BinaryHelper.WriteUInt16(sigBody, (ushort)s);
        WriteExtension(ext, ExtensionType.SignatureAlgorithms, sigBody.ToArray());

        // RFC 8446 §4.2.3 + RFC 9963 §3: signature_algorithms_cert extension (optional)
        if (certSigAlgorithms != null && certSigAlgorithms.Length > 0)
        {
            using var certSigBody = new MemoryStream();
            BinaryHelper.WriteUInt16(certSigBody, (ushort)(certSigAlgorithms.Length * 2));
            foreach (var s in certSigAlgorithms) BinaryHelper.WriteUInt16(certSigBody, (ushort)s);
            WriteExtension(ext, ExtensionType.SignatureAlgorithmsCert, certSigBody.ToArray());
        }

        byte[] extBytes = ext.ToArray();
        BinaryHelper.WriteUInt16(ms, (ushort)extBytes.Length);
        ms.Write(extBytes);

        return Frame(HandshakeType.CertificateRequest, ms.ToArray());
    }

    /// <summary>Parse a CertificateRequest message body.</summary>
    public static (byte[] context, SignatureScheme[] sigAlgorithms, SignatureScheme[]? certSigAlgorithms) ParseCertificateRequest(byte[] body)
    {
        int p = 0;
        EnsureRemaining(body, p, 1, "CertificateRequest context length");
        int ctxLen = body[p++];
        EnsureRemaining(body, p, ctxLen + 2, "CertificateRequest context + ext_len");
        byte[] context = body[p..(p + ctxLen)]; p += ctxLen;

        ushort extLen = BinaryHelper.ReadUInt16(body.AsSpan(p)); p += 2;
        EnsureRemaining(body, p, extLen, "CertificateRequest extensions block");
        int extEnd = p + extLen;

        var sigAlgs = new List<SignatureScheme>();
        var certSigAlgs = new List<SignatureScheme>();
        while (p < extEnd)
        {
            var (et, ed, np) = ReadExtension(body, p); p = np;
            if (et == ExtensionType.SignatureAlgorithms)
            {
                EnsureRemaining(ed, 0, 2, "signature_algorithms length");
                ushort algLen = BinaryHelper.ReadUInt16(ed.AsSpan(0));
                if ((algLen & 1) != 0)
                    throw new TlsException(AlertDescription.DecodeError, "signature_algorithms length must be even");
                EnsureRemaining(ed, 2, algLen, "signature_algorithms list");
                for (int i = 0; i < algLen / 2; i++)
                    sigAlgs.Add((SignatureScheme)BinaryHelper.ReadUInt16(ed.AsSpan(2 + i * 2)));
            }
            else if (et == ExtensionType.SignatureAlgorithmsCert)
            {
                EnsureRemaining(ed, 0, 2, "signature_algorithms_cert length");
                ushort algLen = BinaryHelper.ReadUInt16(ed.AsSpan(0));
                if ((algLen & 1) != 0)
                    throw new TlsException(AlertDescription.DecodeError, "signature_algorithms_cert length must be even");
                EnsureRemaining(ed, 2, algLen, "signature_algorithms_cert list");
                for (int i = 0; i < algLen / 2; i++)
                    certSigAlgs.Add((SignatureScheme)BinaryHelper.ReadUInt16(ed.AsSpan(2 + i * 2)));
            }
        }

        return (context, sigAlgs.ToArray(), certSigAlgs.Count > 0 ? certSigAlgs.ToArray() : null);
    }

    // ================================================================
    //  Certificate
    // ================================================================

    /// <summary>Build a Certificate message with empty context (server). Optionally includes chain certs and OCSP response.</summary>
    public static byte[] BuildCertificate(byte[] certDer, byte[][]? chainCerts = null, byte[]? ocspResponse = null)
    {
        using var ms = new MemoryStream();
        ms.WriteByte(0); // certificate_request_context (empty for server)

        using var list = new MemoryStream();
        // Leaf cert
        BinaryHelper.WriteUInt24(list, (uint)certDer.Length);
        list.Write(certDer);
        WritePerCertExtensions(list, ocspResponse); // OCSP staple on leaf only

        // Chain certs (CA, intermediates)
        if (chainCerts != null)
        {
            foreach (var cc in chainCerts)
            {
                BinaryHelper.WriteUInt24(list, (uint)cc.Length);
                list.Write(cc);
                BinaryHelper.WriteUInt16(list, 0); // no per-cert extensions
            }
        }

        byte[] listBytes = list.ToArray();
        BinaryHelper.WriteUInt24(ms, (uint)listBytes.Length);
        ms.Write(listBytes);

        return Frame(HandshakeType.Certificate, ms.ToArray());
    }

    /// <summary>Build a Certificate message with context (client mTLS). Null certDer = empty list.</summary>
    public static byte[] BuildCertificateMsg(byte[]? certDer, byte[] context, byte[][]? chainCerts = null)
    {
        using var ms = new MemoryStream();
        ms.WriteByte((byte)context.Length);
        ms.Write(context);

        if (certDer != null)
        {
            using var list = new MemoryStream();
            BinaryHelper.WriteUInt24(list, (uint)certDer.Length);
            list.Write(certDer);
            BinaryHelper.WriteUInt16(list, 0); // per-cert extensions

            if (chainCerts != null)
            {
                foreach (var cc in chainCerts)
                {
                    BinaryHelper.WriteUInt24(list, (uint)cc.Length);
                    list.Write(cc);
                    BinaryHelper.WriteUInt16(list, 0);
                }
            }

            byte[] listBytes = list.ToArray();
            BinaryHelper.WriteUInt24(ms, (uint)listBytes.Length);
            ms.Write(listBytes);
        }
        else
        {
            BinaryHelper.WriteUInt24(ms, 0); // empty certificate list
        }

        return Frame(HandshakeType.Certificate, ms.ToArray());
    }

    /// <summary>Returns the first certificate DER bytes from a Certificate message body.</summary>
    public static byte[] ParseCertificateMessage(byte[] body)
    {
        int p = 0;
        EnsureRemaining(body, p, 1, "Certificate context length");
        int ctxLen = body[p++];
        EnsureRemaining(body, p, ctxLen + 3, "Certificate context + list_len");
        p += ctxLen;
        p += 3; // certificate_list length
        EnsureRemaining(body, p, 3, "Certificate entry length");
        uint certLen = BinaryHelper.ReadUInt24(body.AsSpan(p)); p += 3;
        EnsureRemaining(body, p, (int)certLen, "Certificate entry data");
        return body[p..(p + (int)certLen)];
    }

    /// <summary>Parse a Certificate message body, returning context and all cert entries (leaf first) with per-cert extensions.</summary>
    public static (byte[] context, List<CertEntry> entries) ParseCertificateEx(byte[] body)
    {
        int p = 0;
        EnsureRemaining(body, p, 1, "Certificate context length");
        int ctxLen = body[p++];
        EnsureRemaining(body, p, ctxLen + 3, "Certificate context + list_len");
        byte[] context = body[p..(p + ctxLen)]; p += ctxLen;

        uint listLen = BinaryHelper.ReadUInt24(body.AsSpan(p)); p += 3;
        EnsureRemaining(body, p, (int)listLen, "Certificate list");
        int listEnd = p + (int)listLen;

        var entries = new List<CertEntry>();
        while (p < listEnd)
        {
            EnsureRemaining(body, p, 3, "Certificate entry length");
            uint certLen = BinaryHelper.ReadUInt24(body.AsSpan(p)); p += 3;
            EnsureRemaining(body, p, (int)certLen + 2, "Certificate entry data + ext_len");
            byte[] certDer = body[p..(p + (int)certLen)]; p += (int)certLen;

            byte[]? ocspResponse = null;
            ushort extLen = BinaryHelper.ReadUInt16(body.AsSpan(p)); p += 2;
            EnsureRemaining(body, p, extLen, "Certificate entry extensions");
            int extEnd = p + extLen;
            while (p < extEnd)
            {
                EnsureRemaining(body, p, 4, "Certificate per-cert ext header");
                var extType = (ExtensionType)BinaryHelper.ReadUInt16(body.AsSpan(p)); p += 2;
                ushort extDataLen = BinaryHelper.ReadUInt16(body.AsSpan(p)); p += 2;
                EnsureRemaining(body, p, extDataLen, "Certificate per-cert ext data");
                if (extType == ExtensionType.StatusRequest)
                    ocspResponse = UnwrapCertificateStatus(body[p..(p + extDataLen)]);
                p += extDataLen;
            }

            entries.Add(new CertEntry { CertDer = certDer, OcspResponse = ocspResponse });
        }

        return (context, entries);
    }

    // ================================================================
    //  CertificateVerify
    // ================================================================

    public static byte[] BuildCertificateVerify(SignatureScheme scheme, byte[] signature)
    {
        using var ms = new MemoryStream();
        BinaryHelper.WriteUInt16(ms, (ushort)scheme);
        BinaryHelper.WriteUInt16(ms, (ushort)signature.Length);
        ms.Write(signature);
        return Frame(HandshakeType.CertificateVerify, ms.ToArray());
    }

    public static (SignatureScheme scheme, byte[] signature) ParseCertificateVerify(byte[] body)
    {
        EnsureRemaining(body, 0, 4, "CertificateVerify header");
        var scheme = (SignatureScheme)BinaryHelper.ReadUInt16(body.AsSpan(0));
        ushort sigLen = BinaryHelper.ReadUInt16(body.AsSpan(2));
        EnsureRemaining(body, 4, sigLen, "CertificateVerify signature");
        return (scheme, body[4..(4 + sigLen)]);
    }

    // ================================================================
    //  Finished
    // ================================================================

    public static byte[] BuildFinished(byte[] verifyData) =>
        Frame(HandshakeType.Finished, verifyData);

    // ================================================================
    //  KeyUpdate (post-handshake, RFC 8446 §4.6.3)
    // ================================================================

    public static byte[] BuildKeyUpdate(bool requestUpdate)
    {
        return Frame(HandshakeType.KeyUpdate, new byte[] { (byte)(requestUpdate ? 1 : 0) });
    }

    public static bool ParseKeyUpdate(byte[] body)
    {
        return body.Length > 0 && body[0] == 1; // update_requested
    }

    // ================================================================
    //  NewSessionTicket (RFC 8446 §4.6.1)
    // ================================================================

    public static byte[] BuildNewSessionTicket(uint lifetime, uint ageAdd, byte[] nonce,
        byte[] ticket, uint maxEarlyDataSize)
    {
        using var ms = new MemoryStream();
        BinaryHelper.WriteUInt32(ms, lifetime);
        BinaryHelper.WriteUInt32(ms, ageAdd);
        ms.WriteByte((byte)nonce.Length);
        ms.Write(nonce);
        BinaryHelper.WriteUInt16(ms, (ushort)ticket.Length);
        ms.Write(ticket);

        // Extensions: early_data (max_early_data_size)
        using var ext = new MemoryStream();
        if (maxEarlyDataSize > 0)
        {
            using var edBody = new MemoryStream();
            BinaryHelper.WriteUInt32(edBody, maxEarlyDataSize);
            WriteExtension(ext, ExtensionType.EarlyData, edBody.ToArray());
        }
        BinaryHelper.WriteUInt16(ms, (ushort)ext.Length);
        if (ext.Length > 0) ms.Write(ext.ToArray());

        return Frame(HandshakeType.NewSessionTicket, ms.ToArray());
    }

    public static ParsedNewSessionTicket ParseNewSessionTicket(byte[] body)
    {
        int p = 0;
        EnsureRemaining(body, p, 4 + 4 + 1, "NewSessionTicket fixed header");
        uint lifetime = BinaryHelper.ReadUInt32(body.AsSpan(p)); p += 4;
        uint ageAdd = BinaryHelper.ReadUInt32(body.AsSpan(p)); p += 4;
        int nonceLen = body[p++];
        EnsureRemaining(body, p, nonceLen + 2, "NewSessionTicket nonce + ticket_len");
        byte[] nonce = body[p..(p + nonceLen)]; p += nonceLen;
        ushort ticketLen = BinaryHelper.ReadUInt16(body.AsSpan(p)); p += 2;
        EnsureRemaining(body, p, ticketLen, "NewSessionTicket ticket");
        byte[] ticket = body[p..(p + ticketLen)]; p += ticketLen;

        uint maxEarlyData = 0;
        if (p + 2 <= body.Length)
        {
            ushort extLen = BinaryHelper.ReadUInt16(body.AsSpan(p)); p += 2;
            EnsureRemaining(body, p, extLen, "NewSessionTicket extensions");
            int extEnd = p + extLen;
            while (p < extEnd)
            {
                var (et, ed, np) = ReadExtension(body, p); p = np;
                if (et == ExtensionType.EarlyData && ed.Length >= 4)
                    maxEarlyData = BinaryHelper.ReadUInt32(ed.AsSpan(0));
            }
        }

        return new ParsedNewSessionTicket
        {
            Lifetime = lifetime,
            AgeAdd = ageAdd,
            Nonce = nonce,
            Ticket = ticket,
            MaxEarlyDataSize = maxEarlyData
        };
    }

    // ================================================================
    //  PSK Extension (RFC 8446 §4.2.11)
    // ================================================================

    /// <summary>Build pre_shared_key extension data for ClientHello (identities + binders).</summary>
    public static byte[] BuildPreSharedKeyExtension(byte[] identity, uint obfuscatedAge, byte[] binder)
    {
        using var ms = new MemoryStream();
        // Identities list
        ushort identityEntryLen = (ushort)(2 + identity.Length + 4); // len(2) + identity + age(4)
        BinaryHelper.WriteUInt16(ms, identityEntryLen);
        BinaryHelper.WriteUInt16(ms, (ushort)identity.Length);
        ms.Write(identity);
        BinaryHelper.WriteUInt32(ms, obfuscatedAge);
        // Binders list
        ushort bindersLen = (ushort)(1 + binder.Length); // len(1) + binder
        BinaryHelper.WriteUInt16(ms, bindersLen);
        ms.WriteByte((byte)binder.Length);
        ms.Write(binder);
        return ms.ToArray();
    }

    /// <summary>Compute the PSK binder HMAC value.</summary>
    public static byte[] ComputePskBinder(byte[] binderKey, byte[] transcriptHashTruncated,
        System.Security.Cryptography.HashAlgorithmName hash)
    {
        int hashLen = Hkdf.HashLen(hash);
        byte[] finishedKey = Hkdf.ExpandLabel(hash, binderKey, "finished", Array.Empty<byte>(), hashLen);
        if (hash == System.Security.Cryptography.HashAlgorithmName.SHA256)
            return Sha2Managed.HmacSha256(finishedKey, transcriptHashTruncated);
        if (hash == System.Security.Cryptography.HashAlgorithmName.SHA384)
            return Sha2Managed.HmacSha384(finishedKey, transcriptHashTruncated);
        if (hash == System.Security.Cryptography.HashAlgorithmName.SHA512)
            return Sha2Managed.HmacSha512(finishedKey, transcriptHashTruncated);
        // RFC 9367 (GOST PSK) and RFC 8998 (SM3 PSK) use custom HMAC primitives.
        if (GostKdf.IsStreebog(hash))
            return GostKdf.Hmac(finishedKey, transcriptHashTruncated);
        if (Sm3Kdf.IsSm3(hash))
            return Sm3Kdf.Hmac(finishedKey, transcriptHashTruncated);
        throw new ArgumentException($"Unsupported PSK binder hash: {hash}");
    }

    /// <summary>Parse pre_shared_key extension from ClientHello.</summary>
    public static (byte[][] identities, uint[] ages, byte[][] binders) ParsePreSharedKeyExtension(byte[] data)
    {
        int p = 0;
        EnsureRemaining(data, p, 2, "PSK identities length");
        ushort idsLen = BinaryHelper.ReadUInt16(data.AsSpan(p)); p += 2;
        EnsureRemaining(data, p, idsLen, "PSK identities block");
        int idsEnd = p + idsLen;

        var identities = new List<byte[]>();
        var ages = new List<uint>();
        while (p < idsEnd)
        {
            EnsureRemaining(data, p, 2, "PSK identity length");
            ushort idLen = BinaryHelper.ReadUInt16(data.AsSpan(p)); p += 2;
            EnsureRemaining(data, p, idLen + 4, "PSK identity + obfuscated_age");
            identities.Add(data[p..(p + idLen)]); p += idLen;
            ages.Add(BinaryHelper.ReadUInt32(data.AsSpan(p))); p += 4;
        }

        EnsureRemaining(data, p, 2, "PSK binders length");
        ushort bindersLen = BinaryHelper.ReadUInt16(data.AsSpan(p)); p += 2;
        EnsureRemaining(data, p, bindersLen, "PSK binders block");
        var binders = new List<byte[]>();
        int bindersEnd = p + bindersLen;
        while (p < bindersEnd)
        {
            EnsureRemaining(data, p, 1, "PSK binder length");
            int bLen = data[p++];
            EnsureRemaining(data, p, bLen, "PSK binder data");
            binders.Add(data[p..(p + bLen)]); p += bLen;
        }

        return (identities.ToArray(), ages.ToArray(), binders.ToArray());
    }

    /// <summary>Build pre_shared_key ServerHello extension (selected identity index).</summary>
    public static byte[] BuildPreSharedKeyServerExtension(ushort selectedIndex)
    {
        return UInt16Bytes(selectedIndex);
    }

    // ================================================================
    //  Early Data / EndOfEarlyData (RFC 8446 §4.2.10)
    // ================================================================

    public static byte[] BuildEndOfEarlyData()
    {
        return Frame(HandshakeType.EndOfEarlyData, Array.Empty<byte>());
    }

    // ================================================================
    //  CertificateVerify content (the data that is signed)
    // ================================================================

    /// <summary>
    /// Build the content signed/verified in CertificateVerify:
    /// 64 × 0x20 ‖ context_string ‖ 0x00 ‖ transcript_hash
    /// </summary>
    public static byte[] BuildCertVerifyContent(string context, byte[] transcriptHash)
    {
        byte[] spaces = new byte[64];
        Array.Fill(spaces, (byte)0x20);
        byte[] ctx = System.Text.Encoding.ASCII.GetBytes(context);
        byte[] result = new byte[64 + ctx.Length + 1 + transcriptHash.Length];
        Buffer.BlockCopy(spaces, 0, result, 0, 64);
        Buffer.BlockCopy(ctx, 0, result, 64, ctx.Length);
        result[64 + ctx.Length] = 0;
        Buffer.BlockCopy(transcriptHash, 0, result, 64 + ctx.Length + 1, transcriptHash.Length);
        return result;
    }

    // ================================================================
    //  Helpers — split / extension read-write
    // ================================================================

    /// <summary>Split a buffer that may contain multiple concatenated handshake messages.</summary>
    public static List<byte[]> SplitMessages(byte[] data)
    {
        var msgs = new List<byte[]>();
        int p = 0;
        while (p + 4 <= data.Length)
        {
            uint len = BinaryHelper.ReadUInt24(data.AsSpan(p + 1));
            int total = 4 + (int)len;
            if (p + total > data.Length) break;
            msgs.Add(data[p..(p + total)]);
            p += total;
        }
        return msgs;
    }

    // ----- Extension building -----

    private static byte[] BuildClientHelloExtensions(
        (NamedGroup group, byte[] pubKey)[] keyShares,
        string? serverName, byte[]? cookie,
        (byte[] identity, uint age, byte[] binder)? psk = null,
        bool offerEarlyData = false,
        string[]? alpnProtocols = null,
        bool requestOcspStapling = false,
        ushort ticketRequestCount = 0,
        byte[]? echExtensionData = null)
    {
        using var ms = new MemoryStream();

        // SNI
        if (serverName != null)
        {
            byte[] nameBytes = System.Text.Encoding.ASCII.GetBytes(serverName);
            using var body = new MemoryStream();
            ushort nameListLen = (ushort)(1 + 2 + nameBytes.Length);
            BinaryHelper.WriteUInt16(body, nameListLen);
            body.WriteByte(0x00); // host_name
            BinaryHelper.WriteUInt16(body, (ushort)nameBytes.Length);
            body.Write(nameBytes);
            WriteExtension(ms, ExtensionType.ServerName, body.ToArray());
        }

        // Status Request (OCSP stapling — RFC 6066 §8)
        if (requestOcspStapling)
        {
            // CertificateStatusRequest: status_type=ocsp(1), responder_id_list=empty, request_extensions=empty
            byte[] srBody = { 0x01, 0x00, 0x00, 0x00, 0x00 };
            WriteExtension(ms, ExtensionType.StatusRequest, srBody);
        }

        // ALPN
        if (alpnProtocols != null && alpnProtocols.Length > 0)
        {
            using var body = new MemoryStream();
            using var list = new MemoryStream();
            foreach (var proto in alpnProtocols)
            {
                byte[] pb = System.Text.Encoding.ASCII.GetBytes(proto);
                list.WriteByte((byte)pb.Length);
                list.Write(pb);
            }
            BinaryHelper.WriteUInt16(body, (ushort)list.Length);
            body.Write(list.ToArray());
            WriteExtension(ms, ExtensionType.Alpn, body.ToArray());
        }

        // Certificate Compression (advertise brotli = 0x0002, zstd = 0x0003)
        {
            byte[] ccBody = new byte[5];
            ccBody[0] = 4; // byte length of algorithms list (two 2-byte entries)
            BinaryHelper.WriteUInt16(ccBody.AsSpan(1), 0x0002); // brotli
            BinaryHelper.WriteUInt16(ccBody.AsSpan(3), 0x0003); // zstd
            WriteExtension(ms, ExtensionType.CertificateCompression, ccBody);
        }

        // Supported Groups
        {
            NamedGroup[] groups = { NamedGroup.X25519MLKEM768, NamedGroup.X25519, NamedGroup.X448,
                NamedGroup.Secp256r1, NamedGroup.Secp384r1 };
            using var body = new MemoryStream();
            BinaryHelper.WriteUInt16(body, (ushort)((groups.Length + 1) * 2));
            BinaryHelper.WriteUInt16(body, Grease.Group); // RFC 8701
            foreach (var g in groups)
                BinaryHelper.WriteUInt16(body, (ushort)g);
            WriteExtension(ms, ExtensionType.SupportedGroups, body.ToArray());
        }

        // Signature Algorithms (for handshake signatures)
        {
            SignatureScheme[] sigAlgs = {
                SignatureScheme.EcdsaSecp256r1Sha256,
                SignatureScheme.EcdsaSecp384r1Sha384,
                SignatureScheme.Ed25519,
                SignatureScheme.RsaPssRsaeSha256,
                SignatureScheme.RsaPssRsaeSha384
            };
            using var body = new MemoryStream();
            BinaryHelper.WriteUInt16(body, (ushort)((sigAlgs.Length + 1) * 2));
            BinaryHelper.WriteUInt16(body, Grease.SignatureAlgorithm); // RFC 8701
            foreach (var s in sigAlgs)
                BinaryHelper.WriteUInt16(body, (ushort)s);
            WriteExtension(ms, ExtensionType.SignatureAlgorithms, body.ToArray());
        }

        // Signature Algorithms Cert (RFC 8446 §4.2.3 + RFC 9963 §3 - for certificate verification)
        {
            SignatureScheme[] certSigAlgs = {
                SignatureScheme.EcdsaSecp256r1Sha256,
                SignatureScheme.EcdsaSecp384r1Sha384,
                SignatureScheme.Ed25519,
                SignatureScheme.RsaPssRsaeSha256,
                SignatureScheme.RsaPssRsaeSha384,
                // RFC 9963 §3: Legacy RSASSA-PKCS1-v1_5 for certificate verification
                SignatureScheme.RsaPkcs1Sha256,
                SignatureScheme.RsaPkcs1Sha384,
                SignatureScheme.RsaPkcs1Sha512
            };
            using var body = new MemoryStream();
            BinaryHelper.WriteUInt16(body, (ushort)(certSigAlgs.Length * 2));
            foreach (var s in certSigAlgs)
                BinaryHelper.WriteUInt16(body, (ushort)s);
            WriteExtension(ms, ExtensionType.SignatureAlgorithmsCert, body.ToArray());
        }

        // Cookie (from HRR, if present)
        if (cookie != null)
        {
            using var body = new MemoryStream();
            BinaryHelper.WriteUInt16(body, (ushort)cookie.Length);
            body.Write(cookie);
            WriteExtension(ms, ExtensionType.Cookie, body.ToArray());
        }

        // Supported Versions (GREASE value first, then TLS 1.3 — RFC 8701)
        {
            using var body = new MemoryStream();
            body.WriteByte(4); // list length (two 2-byte versions)
            BinaryHelper.WriteUInt16(body, Grease.Version);
            BinaryHelper.WriteUInt16(body, TlsConst.Tls13Version);
            WriteExtension(ms, ExtensionType.SupportedVersions, body.ToArray());
        }

        // record_size_limit (RFC 8449): advertise our maximum receivable record plaintext size
        {
            byte[] rsl = new byte[2];
            BinaryHelper.WriteUInt16(rsl.AsSpan(), (ushort)TlsConst.MaxPlaintextLength);
            WriteExtension(ms, ExtensionType.RecordSizeLimit, rsl);
        }

        // GREASE extension (RFC 8701): a reserved extension type with empty body
        WriteExtension(ms, (ExtensionType)Grease.Extension, Array.Empty<byte>());

        // PSK Key Exchange Modes
        {
            using var body = new MemoryStream();
            body.WriteByte(1);
            body.WriteByte(0x01); // psk_dhe_ke
            WriteExtension(ms, ExtensionType.PskKeyExchangeModes, body.ToArray());
        }

        // Key Share (all offered groups)
        {
            using var body = new MemoryStream();
            int totalLen = 2 + 2 + 1; // GREASE entry: group(2) + len(2) + 1-byte key (RFC 8701)
            foreach (var (_, pubKey) in keyShares)
                totalLen += 2 + 2 + pubKey.Length; // group(2) + len(2) + key

            BinaryHelper.WriteUInt16(body, (ushort)totalLen);
            // GREASE key_share entry (single zero byte), placed first
            BinaryHelper.WriteUInt16(body, Grease.Group);
            BinaryHelper.WriteUInt16(body, 1);
            body.WriteByte(0x00);
            foreach (var (group, pubKey) in keyShares)
            {
                BinaryHelper.WriteUInt16(body, (ushort)group);
                BinaryHelper.WriteUInt16(body, (ushort)pubKey.Length);
                body.Write(pubKey);
            }
            WriteExtension(ms, ExtensionType.KeyShare, body.ToArray());
        }

        // Early Data (must come before pre_shared_key)
        if (offerEarlyData)
        {
            WriteExtension(ms, ExtensionType.EarlyData, Array.Empty<byte>());
        }

        // Ticket Request (RFC 9149 §3)
        if (ticketRequestCount > 0)
        {
            byte[] trBody = new byte[2];
            BinaryHelper.WriteUInt16(trBody.AsSpan(), ticketRequestCount);
            WriteExtension(ms, ExtensionType.TicketRequest, trBody);
        }

        // Encrypted Client Hello (RFC 9849 §7)
        if (echExtensionData != null)
        {
            WriteExtension(ms, ExtensionType.EncryptedClientHello, echExtensionData);
        }

        // Pre-Shared Key (MUST be the last extension — RFC 8446 §4.2.11)
        if (psk != null)
        {
            var (identity, age, binder) = psk.Value;
            byte[] pskData = BuildPreSharedKeyExtension(identity, age, binder);
            WriteExtension(ms, ExtensionType.PreSharedKey, pskData);
        }

        return ms.ToArray();
    }

    private static void WriteExtension(MemoryStream ms, ExtensionType type, byte[] data)
    {
        BinaryHelper.WriteUInt16(ms, (ushort)type);
        BinaryHelper.WriteUInt16(ms, (ushort)data.Length);
        ms.Write(data);
    }

    /// <summary>Write per-certificate extensions (RFC 8446 §4.4.2.1). If ocspResponse is provided, writes status_request extension wrapping the response in a CertificateStatus struct.</summary>
    private static void WritePerCertExtensions(MemoryStream list, byte[]? ocspResponse)
    {
        if (ocspResponse != null)
        {
            // RFC 8446 §4.4.2.1 / RFC 6066 §8: extension body is a CertificateStatus struct:
            //   struct {
            //       CertificateStatusType status_type;  // uint8 = 1 (ocsp)
            //       opaque OCSPResponse<1..2^24-1>;
            //   } CertificateStatus;
            using var certStatus = new MemoryStream();
            certStatus.WriteByte(0x01); // status_type = ocsp(1)
            BinaryHelper.WriteUInt24(certStatus, (uint)ocspResponse.Length);
            certStatus.Write(ocspResponse);
            byte[] certStatusBody = certStatus.ToArray();

            using var extMs = new MemoryStream();
            BinaryHelper.WriteUInt16(extMs, (ushort)ExtensionType.StatusRequest);
            BinaryHelper.WriteUInt16(extMs, (ushort)certStatusBody.Length);
            extMs.Write(certStatusBody);
            byte[] extData = extMs.ToArray();

            // extensions<0..2^16-1> list length prefix
            BinaryHelper.WriteUInt16(list, (ushort)extData.Length);
            list.Write(extData);
        }
        else
        {
            BinaryHelper.WriteUInt16(list, 0); // no extensions
        }
    }

    /// <summary>Unwrap a CertificateStatus struct (RFC 8446 §4.4.2.1 / RFC 6066 §8) returning the OCSP DER, or null if malformed/unsupported.</summary>
    private static byte[]? UnwrapCertificateStatus(byte[] body)
    {
        if (body.Length < 4) return null;
        if (body[0] != 0x01) return null; // only ocsp(1) defined
        uint respLen = BinaryHelper.ReadUInt24(body.AsSpan(1));
        if (respLen == 0 || 4 + respLen > (uint)body.Length) return null;
        return body[4..(4 + (int)respLen)];
    }

    private static (ExtensionType type, byte[] data, int newPos) ReadExtension(byte[] buf, int pos)
    {
        EnsureRemaining(buf, pos, 4, "extension header");
        var type = (ExtensionType)BinaryHelper.ReadUInt16(buf.AsSpan(pos)); pos += 2;
        ushort len = BinaryHelper.ReadUInt16(buf.AsSpan(pos)); pos += 2;
        EnsureRemaining(buf, pos, len, "extension data");
        return (type, buf[pos..(pos + len)], pos + len);
    }

    // Raise DecodeError instead of letting the runtime throw IndexOutOfRange/ArgumentOutOfRange
    // when a peer sends a length-prefix that runs past the message body.
    private static void EnsureRemaining(byte[] buf, int pos, int needed, string what)
    {
        if (pos < 0 || needed < 0 || (long)pos + needed > buf.Length)
            throw new TlsException(AlertDescription.DecodeError,
                $"Malformed handshake message: truncated {what} (pos={pos}, need={needed}, have={buf.Length})");
    }

    // ================================================================
    //  CompressedCertificate (RFC 8879)
    // ================================================================

    /// <summary>Build a CompressedCertificate message wrapping a Certificate message.</summary>
    public static byte[] BuildCompressedCertificate(byte[] certMsg, ushort algorithm)
    {
        // certMsg is the framed Certificate message (type + length + body)
        var (_, certBody) = Unframe(certMsg);
        byte[] compressed = CertificateCompression.Compress(certBody, algorithm);

        using var ms = new MemoryStream();
        BinaryHelper.WriteUInt16(ms, algorithm);
        BinaryHelper.WriteUInt24(ms, (uint)certBody.Length); // uncompressed_length
        BinaryHelper.WriteUInt24(ms, (uint)compressed.Length);
        ms.Write(compressed);
        return Frame(HandshakeType.CompressedCertificate, ms.ToArray());
    }

    /// <summary>Parse a CompressedCertificate message body, decompress and return as Certificate body.</summary>
    public static byte[] ParseCompressedCertificate(byte[] body)
    {
        int p = 0;
        EnsureRemaining(body, p, 2 + 3 + 3, "CompressedCertificate header");
        ushort algorithm = BinaryHelper.ReadUInt16(body.AsSpan(p)); p += 2;
        uint uncompressedLen = BinaryHelper.ReadUInt24(body.AsSpan(p)); p += 3;
        uint compressedLen = BinaryHelper.ReadUInt24(body.AsSpan(p)); p += 3;
        EnsureRemaining(body, p, (int)compressedLen, "CompressedCertificate payload");
        byte[] compressed = body[p..(p + (int)compressedLen)];
        return CertificateCompression.Decompress(compressed, algorithm, (int)uncompressedLen);
    }

    private static byte[] UInt16Bytes(ushort v) => new[] { (byte)(v >> 8), (byte)v };
}

// ================================================================
//  Parsed message DTOs
// ================================================================

public sealed class ParsedClientHello
{
    public byte[] ClientRandom { get; init; } = null!;
    public byte[] SessionId { get; init; } = null!;
    public CipherSuite[] CipherSuites { get; init; } = null!;
    public (NamedGroup group, byte[] key)[] KeyShares { get; init; } = null!;
    public NamedGroup[]? SupportedGroups { get; init; }
    public string? ServerName { get; init; }
    public byte[]? PreSharedKeyData { get; init; }
    public bool OffersEarlyData { get; init; }
    public bool RequestsOcspStapling { get; init; }
    public string[]? AlpnProtocols { get; init; }
    public ushort[]? CertCompressionAlgorithms { get; init; }
    public ushort TicketRequestCount { get; init; }
    public ushort RecordSizeLimit { get; init; } // RFC 8449; 0 = not negotiated
    public SignatureScheme[]? SignatureAlgorithmsCert { get; init; }
    public byte[]? EncryptedClientHelloData { get; init; }  // ECH extension payload
    public bool IsOuterClientHello { get; init; }           // True if this is an ECH outer ClientHello
}

/// <summary>A certificate entry from a TLS Certificate message, with optional per-cert extensions.</summary>
public sealed class CertEntry
{
    public byte[] CertDer { get; init; } = null!;
    public byte[]? OcspResponse { get; init; }
}

public sealed class ParsedServerHello
{
    public byte[] ServerRandom { get; init; } = null!;
    public byte[] SessionId { get; init; } = null!;
    public CipherSuite CipherSuite { get; init; }
    public NamedGroup KeyShareGroup { get; init; }
    public byte[]? KeyShare { get; init; } // null for HRR
    public bool IsHelloRetryRequest { get; init; }
    public byte[]? Cookie { get; init; }
    public int SelectedPskIndex { get; init; } = -1; // -1 = no PSK
}

public sealed class ParsedNewSessionTicket
{
    public uint Lifetime { get; init; }
    public uint AgeAdd { get; init; }
    public byte[] Nonce { get; init; } = null!;
    public byte[] Ticket { get; init; } = null!;
    public uint MaxEarlyDataSize { get; init; }
}

public sealed class ParsedEncryptedExtensions
{
    public bool AcceptEarlyData { get; init; }
    public string? AlpnProtocol { get; init; }
    public ushort CertCompressionAlgorithm { get; init; }
    public ushort RecordSizeLimit { get; init; } // RFC 8449; 0 = not negotiated
}
