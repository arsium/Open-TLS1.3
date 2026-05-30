namespace TLS;

using System.Buffers;
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
        string[]? alpnProtocols, bool requestOcspStapling, ushort ticketRequestCount = 0,
        byte[]? echExtensionData = null)
    {
        // ClientHello body fits comfortably in 1-2 KB without PSK; pre-size to avoid
        // most internal regrowths inside ArrayBufferWriter.
        var bw = new ArrayBufferWriter<byte>(1024);

        BinaryHelper.WriteUInt16(bw, TlsConst.LegacyVersion); // legacy_version
        BinaryHelper.WriteBytes(bw, clientRandom);              // random (32)

        BinaryHelper.WriteByte(bw, (byte)sessionId.Length);    // session_id
        BinaryHelper.WriteBytes(bw, sessionId);

        // cipher_suites — prepend a GREASE value (RFC 8701); the peer MUST ignore it
        BinaryHelper.WriteUInt16(bw, (ushort)((suites.Length + 1) * 2));
        BinaryHelper.WriteUInt16(bw, Grease.CipherSuite);
        foreach (var s in suites) BinaryHelper.WriteUInt16(bw, (ushort)s);

        BinaryHelper.WriteByte(bw, 1); BinaryHelper.WriteByte(bw, 0); // compression_methods = {null}

        byte[] ext = BuildClientHelloExtensions(keyShares, serverName, cookie,
            psk, offerEarlyData, alpnProtocols, requestOcspStapling, ticketRequestCount, echExtensionData);
        BinaryHelper.WriteUInt16(bw, (ushort)ext.Length);       // extensions length
        BinaryHelper.WriteBytes(bw, ext);

        return Frame(HandshakeType.ClientHello, bw.WrittenSpan.ToArray());
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
        bool offersPskDheKe = false;

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
                else if (et == ExtensionType.PskKeyExchangeModes)
                {
                    // RFC 8446 §4.2.9: ke_modes<1..255> — list-length byte then 1 byte per mode.
                    // We only do psk_dhe_ke (0x01); record whether the client advertised it so the
                    // server can (a) gate PSK selection on it and (b) decide to issue tickets.
                    if (ed.Length >= 1)
                    {
                        int modesLen = ed[0];
                        EnsureRemaining(ed, 1, modesLen, "psk_key_exchange_modes list");
                        for (int m = 0; m < modesLen; m++)
                            if (ed[1 + m] == 0x01) offersPskDheKe = true; // psk_dhe_ke
                    }
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
            IsOuterClientHello = isOuterCH,
            OffersPskDheKe = offersPskDheKe
        };
    }

    // ================================================================
    //  ServerHello / HelloRetryRequest
    // ================================================================

    public static byte[] BuildServerHello(byte[] serverRandom, byte[] sessionId,
        CipherSuite suite, NamedGroup group, byte[] pubKey)
    {
        var bw = new ArrayBufferWriter<byte>(256);

        BinaryHelper.WriteUInt16(bw, TlsConst.LegacyVersion);
        BinaryHelper.WriteBytes(bw, serverRandom);

        BinaryHelper.WriteByte(bw, (byte)sessionId.Length);
        BinaryHelper.WriteBytes(bw, sessionId);

        BinaryHelper.WriteUInt16(bw, (ushort)suite);
        BinaryHelper.WriteByte(bw, 0); // compression = null

        // Extensions
        var ebw = new ArrayBufferWriter<byte>(128);
        // supported_versions → TLS 1.3
        WriteExtension(ebw, ExtensionType.SupportedVersions, UInt16Bytes(TlsConst.Tls13Version));
        // key_share: group + key
        {
            var ks = new ArrayBufferWriter<byte>(4 + pubKey.Length);
            BinaryHelper.WriteUInt16(ks, (ushort)group);
            BinaryHelper.WriteUInt16(ks, (ushort)pubKey.Length);
            BinaryHelper.WriteBytes(ks, pubKey);
            WriteExtension(ebw, ExtensionType.KeyShare, ks.WrittenSpan);
        }

        BinaryHelper.WriteUInt16(bw, (ushort)ebw.WrittenCount);
        BinaryHelper.WriteBytes(bw, ebw.WrittenSpan);

        return Frame(HandshakeType.ServerHello, bw.WrittenSpan.ToArray());
    }

    /// <summary>Build a HelloRetryRequest (encoded as ServerHello with sentinel random).</summary>
    public static byte[] BuildHelloRetryRequest(byte[] sessionId, CipherSuite suite, NamedGroup requestedGroup,
        bool withEch = false)
    {
        var bw = new ArrayBufferWriter<byte>(128);

        BinaryHelper.WriteUInt16(bw, TlsConst.LegacyVersion);
        BinaryHelper.WriteBytes(bw, HrrSentinel); // sentinel random

        BinaryHelper.WriteByte(bw, (byte)sessionId.Length);
        BinaryHelper.WriteBytes(bw, sessionId);

        BinaryHelper.WriteUInt16(bw, (ushort)suite);
        BinaryHelper.WriteByte(bw, 0); // compression = null

        // Extensions
        var ebw = new ArrayBufferWriter<byte>(32);
        WriteExtension(ebw, ExtensionType.SupportedVersions, UInt16Bytes(TlsConst.Tls13Version));
        // key_share for HRR: just the selected group (2 bytes)
        WriteExtension(ebw, ExtensionType.KeyShare, UInt16Bytes((ushort)requestedGroup));
        // ECH HRR accept-confirmation (draft §7.2.1): 8 bytes, written last so the framed message's
        // tail-8 bytes are the confirmation (the caller computes + patches them).
        if (withEch)
            WriteExtension(ebw, ExtensionType.EncryptedClientHello, new byte[8]);

        BinaryHelper.WriteUInt16(bw, (ushort)ebw.WrittenCount);
        BinaryHelper.WriteBytes(bw, ebw.WrittenSpan);

        return Frame(HandshakeType.ServerHello, bw.WrittenSpan.ToArray());
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
        ushort recordSizeLimit = 0, byte[]? echRetryConfigs = null)
    {
        var bw = new ArrayBufferWriter<byte>(64);
        var ext = new ArrayBufferWriter<byte>(48);

        if (acceptEarlyData)
            WriteExtension(ext, ExtensionType.EarlyData, ReadOnlySpan<byte>.Empty);

        if (recordSizeLimit > 0)
        {
            Span<byte> rsl = stackalloc byte[2];
            BinaryHelper.WriteUInt16(rsl, recordSizeLimit);
            WriteExtension(ext, ExtensionType.RecordSizeLimit, rsl);
        }

        if (alpnProtocol != null)
        {
            byte[] proto = System.Text.Encoding.ASCII.GetBytes(alpnProtocol);
            var alpnBody = new ArrayBufferWriter<byte>(3 + proto.Length);
            ushort listLen = (ushort)(1 + proto.Length);
            BinaryHelper.WriteUInt16(alpnBody, listLen);
            BinaryHelper.WriteByte(alpnBody, (byte)proto.Length);
            BinaryHelper.WriteBytes(alpnBody, proto);
            WriteExtension(ext, ExtensionType.Alpn, alpnBody.WrittenSpan);
        }

        if (certCompressionAlgorithm != 0)
        {
            Span<byte> ccBody = stackalloc byte[3];
            ccBody[0] = 2; // byte length of algorithms list (one 2-byte entry)
            BinaryHelper.WriteUInt16(ccBody.Slice(1), certCompressionAlgorithm);
            WriteExtension(ext, ExtensionType.CertificateCompression, ccBody);
        }

        // ECH retry_configs (draft §7.1): on ECH reject, hand the client a fresh ECHConfigList.
        if (echRetryConfigs != null)
            WriteExtension(ext, ExtensionType.EncryptedClientHello, echRetryConfigs);

        BinaryHelper.WriteUInt16(bw, (ushort)ext.WrittenCount);
        if (ext.WrittenCount > 0) BinaryHelper.WriteBytes(bw, ext.WrittenSpan);
        return Frame(HandshakeType.EncryptedExtensions, bw.WrittenSpan.ToArray());
    }

    /// <summary>Parse EncryptedExtensions. Returns early_data accepted, negotiated ALPN, cert compression alg.</summary>
    public static ParsedEncryptedExtensions ParseEncryptedExtensionsEx(byte[] body)
    {
        bool earlyData = false;
        string? alpn = null;
        ushort certComp = 0;
        ushort recordSizeLimit = 0;
        byte[]? echRetryConfigs = null;

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
            else if (et == ExtensionType.EncryptedClientHello)
            {
                echRetryConfigs = ed.ToArray(); // ECH retry_configs = an ECHConfigList
            }
        }

        return new ParsedEncryptedExtensions
        {
            AcceptEarlyData = earlyData,
            AlpnProtocol = alpn,
            CertCompressionAlgorithm = certComp,
            RecordSizeLimit = recordSizeLimit,
            EchRetryConfigs = echRetryConfigs
        };
    }

    /// <summary>Parse EncryptedExtensions and return whether early_data was accepted.</summary>
    public static bool ParseEncryptedExtensions(byte[] body) =>
        ParseEncryptedExtensionsEx(body).AcceptEarlyData;

    /// <summary>Build ServerHello with pre_shared_key extension (for PSK resumption).</summary>
    public static byte[] BuildServerHelloWithPsk(byte[] serverRandom, byte[] sessionId,
        CipherSuite suite, NamedGroup group, byte[] pubKey, ushort selectedPskIndex)
    {
        var bw = new ArrayBufferWriter<byte>(256);

        BinaryHelper.WriteUInt16(bw, TlsConst.LegacyVersion);
        BinaryHelper.WriteBytes(bw, serverRandom);

        BinaryHelper.WriteByte(bw, (byte)sessionId.Length);
        BinaryHelper.WriteBytes(bw, sessionId);

        BinaryHelper.WriteUInt16(bw, (ushort)suite);
        BinaryHelper.WriteByte(bw, 0); // compression = null

        // Extensions
        var ebw = new ArrayBufferWriter<byte>(128);
        WriteExtension(ebw, ExtensionType.SupportedVersions, UInt16Bytes(TlsConst.Tls13Version));
        // key_share
        {
            var ks = new ArrayBufferWriter<byte>(4 + pubKey.Length);
            BinaryHelper.WriteUInt16(ks, (ushort)group);
            BinaryHelper.WriteUInt16(ks, (ushort)pubKey.Length);
            BinaryHelper.WriteBytes(ks, pubKey);
            WriteExtension(ebw, ExtensionType.KeyShare, ks.WrittenSpan);
        }
        // pre_shared_key (selected index)
        WriteExtension(ebw, ExtensionType.PreSharedKey, BuildPreSharedKeyServerExtension(selectedPskIndex));

        BinaryHelper.WriteUInt16(bw, (ushort)ebw.WrittenCount);
        BinaryHelper.WriteBytes(bw, ebw.WrittenSpan);

        return Frame(HandshakeType.ServerHello, bw.WrittenSpan.ToArray());
    }

    // ================================================================
    //  CertificateRequest (mTLS)
    // ================================================================

    /// <summary>Build a CertificateRequest message (server → client, mTLS).</summary>
    public static byte[] BuildCertificateRequest(byte[] context, SignatureScheme[] sigAlgorithms,
        SignatureScheme[]? certSigAlgorithms = null, ushort[]? certCompAlgs = null)
    {
        var bw = new ArrayBufferWriter<byte>(128);
        BinaryHelper.WriteByte(bw, (byte)context.Length);
        BinaryHelper.WriteBytes(bw, context);

        // Extensions — signature_algorithms is mandatory
        var ext = new ArrayBufferWriter<byte>(64);
        var sigBody = new ArrayBufferWriter<byte>(2 + sigAlgorithms.Length * 2);
        BinaryHelper.WriteUInt16(sigBody, (ushort)(sigAlgorithms.Length * 2));
        foreach (var s in sigAlgorithms) BinaryHelper.WriteUInt16(sigBody, (ushort)s);
        WriteExtension(ext, ExtensionType.SignatureAlgorithms, sigBody.WrittenSpan);

        // RFC 8446 §4.2.3 + RFC 9963 §3: signature_algorithms_cert extension (optional)
        if (certSigAlgorithms != null && certSigAlgorithms.Length > 0)
        {
            var certSigBody = new ArrayBufferWriter<byte>(2 + certSigAlgorithms.Length * 2);
            BinaryHelper.WriteUInt16(certSigBody, (ushort)(certSigAlgorithms.Length * 2));
            foreach (var s in certSigAlgorithms) BinaryHelper.WriteUInt16(certSigBody, (ushort)s);
            WriteExtension(ext, ExtensionType.SignatureAlgorithmsCert, certSigBody.WrittenSpan);
        }

        // RFC 8879: compress_certificate in CertificateRequest advertises the algorithms the SERVER
        // can decompress, letting the client compress its own (mTLS) certificate.
        if (certCompAlgs != null && certCompAlgs.Length > 0)
        {
            var ccBody = new ArrayBufferWriter<byte>(1 + certCompAlgs.Length * 2);
            BinaryHelper.WriteByte(ccBody, (byte)(certCompAlgs.Length * 2));
            foreach (var a in certCompAlgs) BinaryHelper.WriteUInt16(ccBody, a);
            WriteExtension(ext, ExtensionType.CertificateCompression, ccBody.WrittenSpan);
        }

        BinaryHelper.WriteUInt16(bw, (ushort)ext.WrittenCount);
        BinaryHelper.WriteBytes(bw, ext.WrittenSpan);

        return Frame(HandshakeType.CertificateRequest, bw.WrittenSpan.ToArray());
    }

    /// <summary>Extract the compress_certificate algorithms advertised in a CertificateRequest body
    /// (RFC 8879), or null if absent/malformed. Standalone so the existing ParseCertificateRequest
    /// callers don't need to change.</summary>
    public static ushort[]? ParseCertReqCertCompression(byte[] body)
    {
        try
        {
            int p = 0;
            if (body.Length < 1) return null;
            int ctxLen = body[p++];
            if (p + ctxLen + 2 > body.Length) return null;
            p += ctxLen;
            ushort extLen = BinaryHelper.ReadUInt16(body.AsSpan(p)); p += 2;
            int extEnd = Math.Min(p + extLen, body.Length);
            while (p < extEnd)
            {
                var (et, ed, np) = ReadExtension(body, p); p = np;
                if (et == ExtensionType.CertificateCompression && ed.Length >= 1)
                {
                    int n = ed[0];
                    if ((n & 1) != 0 || 1 + n > ed.Length) return null;
                    var algs = new ushort[n / 2];
                    for (int i = 0; i < algs.Length; i++) algs[i] = BinaryHelper.ReadUInt16(ed.AsSpan(1 + i * 2));
                    return algs;
                }
            }
        }
        catch (TlsException) { /* malformed — treat as not advertised */ }
        return null;
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
        // Estimate: 1 (ctx) + 3 (list_len) + leaf + chain + a generous ocsp slot
        int estimate = 4 + certDer.Length + (ocspResponse?.Length ?? 0) + 32;
        if (chainCerts != null) foreach (var cc in chainCerts) estimate += cc.Length + 5;
        var bw = new ArrayBufferWriter<byte>(estimate);
        BinaryHelper.WriteByte(bw, 0); // certificate_request_context (empty for server)

        var list = new ArrayBufferWriter<byte>(estimate);
        // Leaf cert
        BinaryHelper.WriteUInt24(list, (uint)certDer.Length);
        BinaryHelper.WriteBytes(list, certDer);
        WritePerCertExtensions(list, ocspResponse); // OCSP staple on leaf only

        // Chain certs (CA, intermediates)
        if (chainCerts != null)
        {
            foreach (var cc in chainCerts)
            {
                BinaryHelper.WriteUInt24(list, (uint)cc.Length);
                BinaryHelper.WriteBytes(list, cc);
                BinaryHelper.WriteUInt16(list, 0); // no per-cert extensions
            }
        }

        BinaryHelper.WriteUInt24(bw, (uint)list.WrittenCount);
        BinaryHelper.WriteBytes(bw, list.WrittenSpan);

        return Frame(HandshakeType.Certificate, bw.WrittenSpan.ToArray());
    }

    /// <summary>Build a Certificate message with context (client mTLS). Null certDer = empty list.</summary>
    public static byte[] BuildCertificateMsg(byte[]? certDer, byte[] context, byte[][]? chainCerts = null)
    {
        int estimate = 4 + context.Length + (certDer?.Length ?? 0);
        if (chainCerts != null) foreach (var cc in chainCerts) estimate += cc.Length + 5;
        var bw = new ArrayBufferWriter<byte>(estimate);
        BinaryHelper.WriteByte(bw, (byte)context.Length);
        BinaryHelper.WriteBytes(bw, context);

        if (certDer != null)
        {
            var list = new ArrayBufferWriter<byte>(estimate);
            BinaryHelper.WriteUInt24(list, (uint)certDer.Length);
            BinaryHelper.WriteBytes(list, certDer);
            BinaryHelper.WriteUInt16(list, 0); // per-cert extensions

            if (chainCerts != null)
            {
                foreach (var cc in chainCerts)
                {
                    BinaryHelper.WriteUInt24(list, (uint)cc.Length);
                    BinaryHelper.WriteBytes(list, cc);
                    BinaryHelper.WriteUInt16(list, 0);
                }
            }

            BinaryHelper.WriteUInt24(bw, (uint)list.WrittenCount);
            BinaryHelper.WriteBytes(bw, list.WrittenSpan);
        }
        else
        {
            BinaryHelper.WriteUInt24(bw, 0); // empty certificate list
        }

        return Frame(HandshakeType.Certificate, bw.WrittenSpan.ToArray());
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
        var bw = new ArrayBufferWriter<byte>(4 + signature.Length);
        BinaryHelper.WriteUInt16(bw, (ushort)scheme);
        BinaryHelper.WriteUInt16(bw, (ushort)signature.Length);
        BinaryHelper.WriteBytes(bw, signature);
        return Frame(HandshakeType.CertificateVerify, bw.WrittenSpan.ToArray());
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
        var bw = new ArrayBufferWriter<byte>(16 + nonce.Length + ticket.Length + 16);
        BinaryHelper.WriteUInt32(bw, lifetime);
        BinaryHelper.WriteUInt32(bw, ageAdd);
        BinaryHelper.WriteByte(bw, (byte)nonce.Length);
        BinaryHelper.WriteBytes(bw, nonce);
        BinaryHelper.WriteUInt16(bw, (ushort)ticket.Length);
        BinaryHelper.WriteBytes(bw, ticket);

        // Extensions: early_data (max_early_data_size)
        var ext = new ArrayBufferWriter<byte>(16);
        if (maxEarlyDataSize > 0)
        {
            Span<byte> edBody = stackalloc byte[4];
            BinaryHelper.WriteUInt32(edBody, maxEarlyDataSize);
            WriteExtension(ext, ExtensionType.EarlyData, edBody);
        }
        BinaryHelper.WriteUInt16(bw, (ushort)ext.WrittenCount);
        if (ext.WrittenCount > 0) BinaryHelper.WriteBytes(bw, ext.WrittenSpan);

        return Frame(HandshakeType.NewSessionTicket, bw.WrittenSpan.ToArray());
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
        // Fixed-shape: 2 + 2 + identity + 4 + 2 + 1 + binder
        int size = 2 + 2 + identity.Length + 4 + 2 + 1 + binder.Length;
        var bw = new ArrayBufferWriter<byte>(size);
        // Identities list
        ushort identityEntryLen = (ushort)(2 + identity.Length + 4); // len(2) + identity + age(4)
        BinaryHelper.WriteUInt16(bw, identityEntryLen);
        BinaryHelper.WriteUInt16(bw, (ushort)identity.Length);
        BinaryHelper.WriteBytes(bw, identity);
        BinaryHelper.WriteUInt32(bw, obfuscatedAge);
        // Binders list
        ushort bindersLen = (ushort)(1 + binder.Length); // len(1) + binder
        BinaryHelper.WriteUInt16(bw, bindersLen);
        BinaryHelper.WriteByte(bw, (byte)binder.Length);
        BinaryHelper.WriteBytes(bw, binder);
        return bw.WrittenSpan.ToArray();
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
        // 768 B fits a typical ClientHello extensions block (a few hundred bytes of
        // groups/sigalgs + key_shares of various sizes). The writer grows if needed.
        var bw = new ArrayBufferWriter<byte>(768);

        // SNI
        if (serverName != null)
        {
            byte[] nameBytes = System.Text.Encoding.ASCII.GetBytes(serverName);
            // body layout: nameListLen(2) + nameType(1) + nameLen(2) + nameBytes
            var body = new ArrayBufferWriter<byte>(5 + nameBytes.Length);
            ushort nameListLen = (ushort)(1 + 2 + nameBytes.Length);
            BinaryHelper.WriteUInt16(body, nameListLen);
            BinaryHelper.WriteByte(body, 0x00); // host_name
            BinaryHelper.WriteUInt16(body, (ushort)nameBytes.Length);
            BinaryHelper.WriteBytes(body, nameBytes);
            WriteExtension(bw, ExtensionType.ServerName, body.WrittenSpan);
        }

        // Status Request (OCSP stapling — RFC 6066 §8)
        if (requestOcspStapling)
        {
            // CertificateStatusRequest: status_type=ocsp(1), responder_id_list=empty, request_extensions=empty
            ReadOnlySpan<byte> srBody = stackalloc byte[] { 0x01, 0x00, 0x00, 0x00, 0x00 };
            WriteExtension(bw, ExtensionType.StatusRequest, srBody);
        }

        // ALPN
        if (alpnProtocols != null && alpnProtocols.Length > 0)
        {
            // Compute exact size: list_len(2) + Σ(1 + proto.Length)
            int totalProtoBytes = 0;
            foreach (var p in alpnProtocols)
                totalProtoBytes += 1 + System.Text.Encoding.ASCII.GetByteCount(p);
            var body = new ArrayBufferWriter<byte>(2 + totalProtoBytes);
            BinaryHelper.WriteUInt16(body, (ushort)totalProtoBytes);
            foreach (var proto in alpnProtocols)
            {
                byte[] pb = System.Text.Encoding.ASCII.GetBytes(proto);
                BinaryHelper.WriteByte(body, (byte)pb.Length);
                BinaryHelper.WriteBytes(body, pb);
            }
            WriteExtension(bw, ExtensionType.Alpn, body.WrittenSpan);
        }

        // Certificate Compression (advertise brotli = 0x0002, zstd = 0x0003, zlib = 0x0001).
        // Order = preference; the server picks the first it supports. zlib last (lowest ratio) —
        // it's the RFC 8879 baseline some peers only offer.
        {
            Span<byte> ccBody = stackalloc byte[7];
            ccBody[0] = 6; // byte length of algorithms list (three 2-byte entries)
            BinaryHelper.WriteUInt16(ccBody.Slice(1), 0x0002); // brotli
            BinaryHelper.WriteUInt16(ccBody.Slice(3), 0x0003); // zstd
            BinaryHelper.WriteUInt16(ccBody.Slice(5), 0x0001); // zlib
            WriteExtension(bw, ExtensionType.CertificateCompression, ccBody);
        }

        // Supported Groups
        {
            ReadOnlySpan<NamedGroup> groups = stackalloc NamedGroup[] {
                NamedGroup.X25519MLKEM768, NamedGroup.SecP256r1MLKEM768, NamedGroup.SecP384r1MLKEM1024,
                NamedGroup.X25519, NamedGroup.X448, NamedGroup.Secp256r1, NamedGroup.Secp384r1
            };
            int bodyLen = 2 + (groups.Length + 1) * 2; // listLen + GREASE + groups
            Span<byte> body = stackalloc byte[bodyLen];
            BinaryHelper.WriteUInt16(body, (ushort)((groups.Length + 1) * 2));
            BinaryHelper.WriteUInt16(body.Slice(2), Grease.Group); // RFC 8701
            int off = 4;
            foreach (var g in groups)
            {
                BinaryHelper.WriteUInt16(body.Slice(off), (ushort)g);
                off += 2;
            }
            WriteExtension(bw, ExtensionType.SupportedGroups, body);
        }

        // Signature Algorithms (for handshake signatures)
        {
            ReadOnlySpan<SignatureScheme> sigAlgs = stackalloc SignatureScheme[] {
                SignatureScheme.EcdsaSecp256r1Sha256,
                SignatureScheme.EcdsaSecp384r1Sha384,
                SignatureScheme.Ed25519,
                SignatureScheme.RsaPssRsaeSha256,
                SignatureScheme.RsaPssRsaeSha384
            };
            int bodyLen = 2 + (sigAlgs.Length + 1) * 2;
            Span<byte> body = stackalloc byte[bodyLen];
            BinaryHelper.WriteUInt16(body, (ushort)((sigAlgs.Length + 1) * 2));
            BinaryHelper.WriteUInt16(body.Slice(2), Grease.SignatureAlgorithm); // RFC 8701
            int off = 4;
            foreach (var s in sigAlgs)
            {
                BinaryHelper.WriteUInt16(body.Slice(off), (ushort)s);
                off += 2;
            }
            WriteExtension(bw, ExtensionType.SignatureAlgorithms, body);
        }

        // Signature Algorithms Cert (RFC 8446 §4.2.3 + RFC 9963 §3 - for certificate verification)
        {
            ReadOnlySpan<SignatureScheme> certSigAlgs = stackalloc SignatureScheme[] {
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
            int bodyLen = 2 + certSigAlgs.Length * 2;
            Span<byte> body = stackalloc byte[bodyLen];
            BinaryHelper.WriteUInt16(body, (ushort)(certSigAlgs.Length * 2));
            int off = 2;
            foreach (var s in certSigAlgs)
            {
                BinaryHelper.WriteUInt16(body.Slice(off), (ushort)s);
                off += 2;
            }
            WriteExtension(bw, ExtensionType.SignatureAlgorithmsCert, body);
        }

        // Cookie (from HRR, if present)
        if (cookie != null)
        {
            // length-prefixed cookie: 2 + cookie.Length
            int bodyLen = 2 + cookie.Length;
            Span<byte> body = bodyLen <= 256 ? stackalloc byte[bodyLen] : new byte[bodyLen];
            BinaryHelper.WriteUInt16(body, (ushort)cookie.Length);
            cookie.AsSpan().CopyTo(body.Slice(2));
            WriteExtension(bw, ExtensionType.Cookie, body);
        }

        // Supported Versions (GREASE value first, then TLS 1.3 — RFC 8701)
        {
            Span<byte> body = stackalloc byte[5];
            body[0] = 4; // list length (two 2-byte versions)
            BinaryHelper.WriteUInt16(body.Slice(1), Grease.Version);
            BinaryHelper.WriteUInt16(body.Slice(3), TlsConst.Tls13Version);
            WriteExtension(bw, ExtensionType.SupportedVersions, body);
        }

        // record_size_limit (RFC 8449): advertise our maximum receivable record plaintext size
        {
            Span<byte> rsl = stackalloc byte[2];
            BinaryHelper.WriteUInt16(rsl, (ushort)TlsConst.MaxPlaintextLength);
            WriteExtension(bw, ExtensionType.RecordSizeLimit, rsl);
        }

        // GREASE extension (RFC 8701): a reserved extension type with empty body
        WriteExtension(bw, (ExtensionType)Grease.Extension, ReadOnlySpan<byte>.Empty);

        // PSK Key Exchange Modes
        {
            ReadOnlySpan<byte> body = stackalloc byte[] { 1, 0x01 }; // length=1, psk_dhe_ke
            WriteExtension(bw, ExtensionType.PskKeyExchangeModes, body);
        }

        // Key Share (all offered groups)
        {
            int totalLen = 2 + 2 + 1; // GREASE entry: group(2) + len(2) + 1-byte key (RFC 8701)
            foreach (var (_, pubKey) in keyShares)
                totalLen += 2 + 2 + pubKey.Length; // group(2) + len(2) + key

            // body = listLen(2) + GREASE entry(5) + real entries
            int bodyLen = 2 + totalLen;
            // ML-KEM-768 key_share is ~1.2 KB; can exceed stack budget — guard.
            Span<byte> body = bodyLen <= 256 ? stackalloc byte[bodyLen] : new byte[bodyLen];
            BinaryHelper.WriteUInt16(body, (ushort)totalLen);
            // GREASE key_share entry (single zero byte), placed first
            BinaryHelper.WriteUInt16(body.Slice(2), Grease.Group);
            BinaryHelper.WriteUInt16(body.Slice(4), 1);
            body[6] = 0x00;
            int off = 7;
            foreach (var (group, pubKey) in keyShares)
            {
                BinaryHelper.WriteUInt16(body.Slice(off), (ushort)group); off += 2;
                BinaryHelper.WriteUInt16(body.Slice(off), (ushort)pubKey.Length); off += 2;
                pubKey.AsSpan().CopyTo(body.Slice(off));
                off += pubKey.Length;
            }
            WriteExtension(bw, ExtensionType.KeyShare, body);
        }

        // Early Data (must come before pre_shared_key)
        if (offerEarlyData)
        {
            WriteExtension(bw, ExtensionType.EarlyData, ReadOnlySpan<byte>.Empty);
        }

        // Ticket Request (RFC 9149 §3)
        if (ticketRequestCount > 0)
        {
            Span<byte> trBody = stackalloc byte[2];
            BinaryHelper.WriteUInt16(trBody, ticketRequestCount);
            WriteExtension(bw, ExtensionType.TicketRequest, trBody);
        }

        // Encrypted Client Hello (RFC 9849 §7)
        if (echExtensionData != null)
        {
            WriteExtension(bw, ExtensionType.EncryptedClientHello, echExtensionData);
        }

        // Pre-Shared Key (MUST be the last extension — RFC 8446 §4.2.11)
        if (psk != null)
        {
            var (identity, age, binder) = psk.Value;
            byte[] pskData = BuildPreSharedKeyExtension(identity, age, binder);
            WriteExtension(bw, ExtensionType.PreSharedKey, pskData);
        }

        return bw.WrittenSpan.ToArray();
    }

    private static void WriteExtension(IBufferWriter<byte> w, ExtensionType type, ReadOnlySpan<byte> data)
    {
        BinaryHelper.WriteUInt16(w, (ushort)type);
        BinaryHelper.WriteUInt16(w, (ushort)data.Length);
        BinaryHelper.WriteBytes(w, data);
    }

    /// <summary>Write per-certificate extensions (RFC 8446 §4.4.2.1). If ocspResponse is provided, writes status_request extension wrapping the response in a CertificateStatus struct.</summary>
    private static void WritePerCertExtensions(IBufferWriter<byte> list, byte[]? ocspResponse)
    {
        if (ocspResponse != null)
        {
            // RFC 8446 §4.4.2.1 / RFC 6066 §8: extension body is a CertificateStatus struct:
            //   struct {
            //       CertificateStatusType status_type;  // uint8 = 1 (ocsp)
            //       opaque OCSPResponse<1..2^24-1>;
            //   } CertificateStatus;
            // certStatus layout: 1B status_type + 3B uint24 length + N bytes response
            int certStatusLen = 1 + 3 + ocspResponse.Length;
            // ext header (4B: type + length) + body
            int extDataLen = 4 + certStatusLen;

            // extensions<0..2^16-1> list length prefix
            BinaryHelper.WriteUInt16(list, (ushort)extDataLen);
            // extension header
            BinaryHelper.WriteUInt16(list, (ushort)ExtensionType.StatusRequest);
            BinaryHelper.WriteUInt16(list, (ushort)certStatusLen);
            // CertificateStatus body
            BinaryHelper.WriteByte(list, 0x01); // status_type = ocsp(1)
            BinaryHelper.WriteUInt24(list, (uint)ocspResponse.Length);
            BinaryHelper.WriteBytes(list, ocspResponse);
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

        var bw = new ArrayBufferWriter<byte>(8 + compressed.Length);
        BinaryHelper.WriteUInt16(bw, algorithm);
        BinaryHelper.WriteUInt24(bw, (uint)certBody.Length); // uncompressed_length
        BinaryHelper.WriteUInt24(bw, (uint)compressed.Length);
        BinaryHelper.WriteBytes(bw, compressed);
        return Frame(HandshakeType.CompressedCertificate, bw.WrittenSpan.ToArray());
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
    public bool OffersPskDheKe { get; init; }               // RFC 8446 §4.2.9: client advertised psk_dhe_ke
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
    public byte[]? EchRetryConfigs { get; init; } // ECH retry_configs (draft §7.1), an ECHConfigList
}
