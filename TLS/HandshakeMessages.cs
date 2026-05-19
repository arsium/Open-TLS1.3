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
        string? serverName = null, byte[]? cookie = null, string[]? alpnProtocols = null)
    {
        return BuildClientHelloInner(clientRandom, sessionId, suites, keyShares,
            serverName, cookie, null, false, alpnProtocols);
    }

    /// <summary>Build ClientHello with PSK and optional early_data extension.</summary>
    public static byte[] BuildClientHelloWithPsk(byte[] clientRandom, byte[] sessionId,
        CipherSuite[] suites, (NamedGroup group, byte[] pubKey)[] keyShares,
        byte[] pskIdentity, uint obfuscatedAge, byte[] binderPlaceholder,
        bool offerEarlyData, string? serverName = null, byte[]? cookie = null,
        string[]? alpnProtocols = null)
    {
        return BuildClientHelloInner(clientRandom, sessionId, suites, keyShares,
            serverName, cookie, (pskIdentity, obfuscatedAge, binderPlaceholder), offerEarlyData, alpnProtocols);
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

    private static byte[] BuildClientHelloInner(byte[] clientRandom, byte[] sessionId,
        CipherSuite[] suites, (NamedGroup group, byte[] pubKey)[] keyShares,
        string? serverName, byte[]? cookie,
        (byte[] identity, uint age, byte[] binder)? psk, bool offerEarlyData,
        string[]? alpnProtocols)
    {
        using var ms = new MemoryStream();

        BinaryHelper.WriteUInt16(ms, TlsConst.LegacyVersion); // legacy_version
        ms.Write(clientRandom);                                 // random (32)

        ms.WriteByte((byte)sessionId.Length);                   // session_id
        ms.Write(sessionId);

        BinaryHelper.WriteUInt16(ms, (ushort)(suites.Length * 2)); // cipher_suites
        foreach (var s in suites) BinaryHelper.WriteUInt16(ms, (ushort)s);

        ms.WriteByte(1); ms.WriteByte(0);                       // compression_methods = {null}

        byte[] ext = BuildClientHelloExtensions(keyShares, serverName, cookie,
            psk, offerEarlyData, alpnProtocols);
        BinaryHelper.WriteUInt16(ms, (ushort)ext.Length);       // extensions length
        ms.Write(ext);

        return Frame(HandshakeType.ClientHello, ms.ToArray());
    }

    public static ParsedClientHello ParseClientHello(byte[] body)
    {
        int p = 0;
        p += 2; // legacy_version
        byte[] clientRandom = body[p..(p + 32)]; p += 32;

        int sidLen = body[p++];
        byte[] sessionId = body[p..(p + sidLen)]; p += sidLen;

        ushort suitesLen = BinaryHelper.ReadUInt16(body.AsSpan(p)); p += 2;
        var suites = new List<CipherSuite>();
        for (int i = 0; i < suitesLen / 2; i++)
        { suites.Add((CipherSuite)BinaryHelper.ReadUInt16(body.AsSpan(p))); p += 2; }

        int compLen = body[p++]; p += compLen; // skip compression

        var keyShares = new List<(NamedGroup, byte[])>();
        var supportedGroups = new List<NamedGroup>();
        string? sni = null;
        byte[]? pskData = null;
        bool offersEarlyData = false;
        string[]? alpnProtocols = null;
        ushort[]? certCompAlgorithms = null;

        if (p < body.Length)
        {
            ushort extLen = BinaryHelper.ReadUInt16(body.AsSpan(p)); p += 2;
            int extEnd = p + extLen;
            while (p < extEnd)
            {
                var (et, ed, np) = ReadExtension(body, p); p = np;
                if (et == ExtensionType.KeyShare)
                {
                    ushort listLen = BinaryHelper.ReadUInt16(ed.AsSpan(0));
                    int kp = 2;
                    int kEnd = 2 + listLen;
                    while (kp < kEnd)
                    {
                        var group = (NamedGroup)BinaryHelper.ReadUInt16(ed.AsSpan(kp)); kp += 2;
                        ushort kl = BinaryHelper.ReadUInt16(ed.AsSpan(kp)); kp += 2;
                        keyShares.Add((group, ed[kp..(kp + kl)]));
                        kp += kl;
                    }
                }
                else if (et == ExtensionType.SupportedGroups)
                {
                    ushort groupsLen = BinaryHelper.ReadUInt16(ed.AsSpan(0));
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
                    int sp = 2; // skip list length
                    sp++;       // skip name type
                    ushort nl = BinaryHelper.ReadUInt16(ed.AsSpan(sp)); sp += 2;
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
                else if (et == ExtensionType.Alpn)
                {
                    var protos = new List<string>();
                    ushort listLen = BinaryHelper.ReadUInt16(ed.AsSpan(0));
                    int ap = 2;
                    int apEnd = 2 + listLen;
                    while (ap < apEnd)
                    {
                        int pLen = ed[ap++];
                        protos.Add(System.Text.Encoding.ASCII.GetString(ed, ap, pLen));
                        ap += pLen;
                    }
                    alpnProtocols = protos.ToArray();
                }
                else if (et == ExtensionType.CertificateCompression)
                {
                    int numAlgs = ed[0] / 2; // byte length to algorithm count
                    certCompAlgorithms = new ushort[numAlgs];
                    for (int a = 0; a < numAlgs; a++)
                        certCompAlgorithms[a] = BinaryHelper.ReadUInt16(ed.AsSpan(1 + a * 2));
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
            AlpnProtocols = alpnProtocols,
            CertCompressionAlgorithms = certCompAlgorithms
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
        p += 2; // legacy_version
        byte[] serverRandom = body[p..(p + 32)]; p += 32;

        bool isHrr = serverRandom.AsSpan().SequenceEqual(HrrSentinel);

        int sidLen = body[p++];
        byte[] sessionId = body[p..(p + sidLen)]; p += sidLen;

        var suite = (CipherSuite)BinaryHelper.ReadUInt16(body.AsSpan(p)); p += 2;
        p++; // compression

        NamedGroup keyShareGroup = 0;
        byte[]? keyShare = null;
        byte[]? cookie = null;
        int selectedPsk = -1;

        ushort extLen = BinaryHelper.ReadUInt16(body.AsSpan(p)); p += 2;
        int extEnd = p + extLen;
        while (p < extEnd)
        {
            var (et, ed, np) = ReadExtension(body, p); p = np;
            if (et == ExtensionType.KeyShare)
            {
                keyShareGroup = (NamedGroup)BinaryHelper.ReadUInt16(ed.AsSpan(0));
                if (!isHrr)
                {
                    // Normal SH: group(2) + key_len(2) + key(...)
                    int kp = 2;
                    ushort kl = BinaryHelper.ReadUInt16(ed.AsSpan(kp)); kp += 2;
                    keyShare = ed[kp..(kp + kl)];
                }
                // HRR: just the group (2 bytes), keyShare stays null
            }
            else if (et == ExtensionType.Cookie)
            {
                ushort cookieLen = BinaryHelper.ReadUInt16(ed.AsSpan(0));
                cookie = ed[2..(2 + cookieLen)];
            }
            else if (et == ExtensionType.PreSharedKey)
            {
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
        string? alpnProtocol = null, ushort certCompressionAlgorithm = 0)
    {
        using var ms = new MemoryStream();
        using var ext = new MemoryStream();

        if (acceptEarlyData)
            WriteExtension(ext, ExtensionType.EarlyData, Array.Empty<byte>());

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
        }

        return new ParsedEncryptedExtensions
        {
            AcceptEarlyData = earlyData,
            AlpnProtocol = alpn,
            CertCompressionAlgorithm = certComp
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
    public static byte[] BuildCertificateRequest(byte[] context, SignatureScheme[] sigAlgorithms)
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

        byte[] extBytes = ext.ToArray();
        BinaryHelper.WriteUInt16(ms, (ushort)extBytes.Length);
        ms.Write(extBytes);

        return Frame(HandshakeType.CertificateRequest, ms.ToArray());
    }

    /// <summary>Parse a CertificateRequest message body.</summary>
    public static (byte[] context, SignatureScheme[] sigAlgorithms) ParseCertificateRequest(byte[] body)
    {
        int p = 0;
        int ctxLen = body[p++];
        byte[] context = body[p..(p + ctxLen)]; p += ctxLen;

        ushort extLen = BinaryHelper.ReadUInt16(body.AsSpan(p)); p += 2;
        int extEnd = p + extLen;

        var sigAlgs = new List<SignatureScheme>();
        while (p < extEnd)
        {
            var (et, ed, np) = ReadExtension(body, p); p = np;
            if (et == ExtensionType.SignatureAlgorithms)
            {
                ushort algLen = BinaryHelper.ReadUInt16(ed.AsSpan(0));
                for (int i = 0; i < algLen / 2; i++)
                    sigAlgs.Add((SignatureScheme)BinaryHelper.ReadUInt16(ed.AsSpan(2 + i * 2)));
            }
        }

        return (context, sigAlgs.ToArray());
    }

    // ================================================================
    //  Certificate
    // ================================================================

    /// <summary>Build a Certificate message with empty context (server). Optionally includes chain certs.</summary>
    public static byte[] BuildCertificate(byte[] certDer, byte[][]? chainCerts = null)
    {
        using var ms = new MemoryStream();
        ms.WriteByte(0); // certificate_request_context (empty for server)

        using var list = new MemoryStream();
        // Leaf cert
        BinaryHelper.WriteUInt24(list, (uint)certDer.Length);
        list.Write(certDer);
        BinaryHelper.WriteUInt16(list, 0); // per-cert extensions (none)

        // Chain certs (CA, intermediates)
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
        int ctxLen = body[p++]; p += ctxLen;
        p += 3; // certificate_list length
        uint certLen = BinaryHelper.ReadUInt24(body.AsSpan(p)); p += 3;
        return body[p..(p + (int)certLen)];
    }

    /// <summary>Parse a Certificate message body, returning context and all certs in order (leaf first).</summary>
    public static (byte[] context, List<byte[]> certs) ParseCertificateEx(byte[] body)
    {
        int p = 0;
        int ctxLen = body[p++];
        byte[] context = body[p..(p + ctxLen)]; p += ctxLen;

        uint listLen = BinaryHelper.ReadUInt24(body.AsSpan(p)); p += 3;
        int listEnd = p + (int)listLen;

        var certs = new List<byte[]>();
        while (p < listEnd)
        {
            uint certLen = BinaryHelper.ReadUInt24(body.AsSpan(p)); p += 3;
            certs.Add(body[p..(p + (int)certLen)]); p += (int)certLen;
            ushort extLen = BinaryHelper.ReadUInt16(body.AsSpan(p)); p += 2 + extLen; // skip per-cert extensions
        }

        return (context, certs);
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
        var scheme = (SignatureScheme)BinaryHelper.ReadUInt16(body.AsSpan(0));
        ushort sigLen = BinaryHelper.ReadUInt16(body.AsSpan(2));
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
        uint lifetime = BinaryHelper.ReadUInt32(body.AsSpan(p)); p += 4;
        uint ageAdd = BinaryHelper.ReadUInt32(body.AsSpan(p)); p += 4;
        int nonceLen = body[p++];
        byte[] nonce = body[p..(p + nonceLen)]; p += nonceLen;
        ushort ticketLen = BinaryHelper.ReadUInt16(body.AsSpan(p)); p += 2;
        byte[] ticket = body[p..(p + ticketLen)]; p += ticketLen;

        uint maxEarlyData = 0;
        if (p + 2 <= body.Length)
        {
            ushort extLen = BinaryHelper.ReadUInt16(body.AsSpan(p)); p += 2;
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
        using var hmac = System.Security.Cryptography.IncrementalHash.CreateHMAC(hash, finishedKey);
        hmac.AppendData(transcriptHashTruncated);
        return hmac.GetHashAndReset();
    }

    /// <summary>Parse pre_shared_key extension from ClientHello.</summary>
    public static (byte[][] identities, uint[] ages, byte[][] binders) ParsePreSharedKeyExtension(byte[] data)
    {
        int p = 0;
        ushort idsLen = BinaryHelper.ReadUInt16(data.AsSpan(p)); p += 2;
        int idsEnd = p + idsLen;

        var identities = new List<byte[]>();
        var ages = new List<uint>();
        while (p < idsEnd)
        {
            ushort idLen = BinaryHelper.ReadUInt16(data.AsSpan(p)); p += 2;
            identities.Add(data[p..(p + idLen)]); p += idLen;
            ages.Add(BinaryHelper.ReadUInt32(data.AsSpan(p))); p += 4;
        }

        ushort bindersLen = BinaryHelper.ReadUInt16(data.AsSpan(p)); p += 2;
        var binders = new List<byte[]>();
        int bindersEnd = p + bindersLen;
        while (p < bindersEnd)
        {
            int bLen = data[p++];
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
        string[]? alpnProtocols = null)
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
            BinaryHelper.WriteUInt16(body, (ushort)(groups.Length * 2));
            foreach (var g in groups)
                BinaryHelper.WriteUInt16(body, (ushort)g);
            WriteExtension(ms, ExtensionType.SupportedGroups, body.ToArray());
        }

        // Signature Algorithms
        {
            SignatureScheme[] sigAlgs = {
                SignatureScheme.EcdsaSecp256r1Sha256,
                SignatureScheme.EcdsaSecp384r1Sha384,
                SignatureScheme.Ed25519,
                SignatureScheme.RsaPssRsaeSha256,
                SignatureScheme.RsaPssRsaeSha384
            };
            using var body = new MemoryStream();
            BinaryHelper.WriteUInt16(body, (ushort)(sigAlgs.Length * 2));
            foreach (var s in sigAlgs)
                BinaryHelper.WriteUInt16(body, (ushort)s);
            WriteExtension(ms, ExtensionType.SignatureAlgorithms, body.ToArray());
        }

        // Cookie (from HRR, if present)
        if (cookie != null)
        {
            using var body = new MemoryStream();
            BinaryHelper.WriteUInt16(body, (ushort)cookie.Length);
            body.Write(cookie);
            WriteExtension(ms, ExtensionType.Cookie, body.ToArray());
        }

        // Supported Versions
        {
            using var body = new MemoryStream();
            body.WriteByte(2); // list length
            BinaryHelper.WriteUInt16(body, TlsConst.Tls13Version);
            WriteExtension(ms, ExtensionType.SupportedVersions, body.ToArray());
        }

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
            int totalLen = 0;
            foreach (var (_, pubKey) in keyShares)
                totalLen += 2 + 2 + pubKey.Length; // group(2) + len(2) + key

            BinaryHelper.WriteUInt16(body, (ushort)totalLen);
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

    private static (ExtensionType type, byte[] data, int newPos) ReadExtension(byte[] buf, int pos)
    {
        var type = (ExtensionType)BinaryHelper.ReadUInt16(buf.AsSpan(pos)); pos += 2;
        ushort len = BinaryHelper.ReadUInt16(buf.AsSpan(pos)); pos += 2;
        return (type, buf[pos..(pos + len)], pos + len);
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
        ushort algorithm = BinaryHelper.ReadUInt16(body.AsSpan(p)); p += 2;
        uint uncompressedLen = BinaryHelper.ReadUInt24(body.AsSpan(p)); p += 3;
        uint compressedLen = BinaryHelper.ReadUInt24(body.AsSpan(p)); p += 3;
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
    public string[]? AlpnProtocols { get; init; }
    public ushort[]? CertCompressionAlgorithms { get; init; }
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
}
