namespace TLS;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

/// <summary>
/// Encrypted Client Hello (ECH, draft-ietf-tls-esni-18). Encrypts the ClientHelloInner (incl. the
/// real SNI) under HPKE so a passive observer sees only the public_name — it does NOT hide the
/// destination IP (that's layer 3); ECH's value is that CDNs multiplex many names on one IP.
///
/// Scope of this implementation: DHKEM(X25519,HKDF-SHA256) + HKDF-SHA256 + {AES-128-GCM,
/// ChaCha20Poly1305}; the EncodedClientHelloInner carries ALL extensions inline (no
/// outer_extensions(0xfd00) compression — that's an optional size optimization); the §7.2
/// accept-confirmation signal is implemented (non-HRR). retry_configs + GREASE-ECH are surfaced
/// where cheap. Wired into the sync handshake path.
/// </summary>
public static class EncryptedClientHello
{
    public const ushort EchConfigVersion = 0xfe0d; // draft-18 ECHConfig.version

    public sealed class EchConfig
    {
        public byte ConfigId { get; init; }
        public ushort KemId { get; init; }
        public byte[] PublicKey { get; init; } = null!;
        public (ushort Kdf, ushort Aead)[] CipherSuites { get; init; } = null!;
        public byte MaxNameLen { get; init; }
        public byte[] PublicName { get; init; } = null!;   // ASCII
        public byte[] RawBytes { get; init; } = null!;     // full ECHConfig incl. version+length header (HPKE info input)
        public string PublicNameString => System.Text.Encoding.ASCII.GetString(PublicName);
    }

    /// <summary>Client-side marker that ECH was attempted; carries the inner CH + its random,
    /// needed to verify the server's accept-confirmation.</summary>
    public sealed class EchClientContext
    {
        public byte[] InnerChMsg { get; }
        public byte[] InnerRandom { get; }
        internal EchClientContext(byte[] innerChMsg, byte[] innerRandom)
        { InnerChMsg = innerChMsg; InnerRandom = innerRandom; }
    }

    // ================================================================
    //  ECHConfigList parse / build
    // ================================================================

    public static EchConfig[] ParseEchConfigList(byte[] list)
    {
        if (list.Length < 2) throw new ArgumentException("ECHConfigList too short");
        ushort total = BinaryHelper.ReadUInt16(list.AsSpan(0));
        if (total != list.Length - 2) throw new ArgumentException("ECHConfigList length mismatch");

        var configs = new List<EchConfig>();
        int pos = 2;
        while (pos < list.Length)
        {
            if (pos + 4 > list.Length) throw new ArgumentException("Truncated ECHConfig header");
            ushort version = BinaryHelper.ReadUInt16(list.AsSpan(pos));
            ushort len = BinaryHelper.ReadUInt16(list.AsSpan(pos + 2));
            int contentStart = pos + 4;
            if (contentStart + len > list.Length) throw new ArgumentException("Truncated ECHConfig");
            byte[] raw = list[pos..(contentStart + len)]; // version+length+contents
            if (version == EchConfigVersion)
            {
                var cfg = ParseEchConfigContents(list.AsSpan(contentStart, len), raw);
                if (cfg != null) configs.Add(cfg);
            }
            // else: unknown version → skip for forward compat
            pos = contentStart + len;
        }
        return configs.ToArray();
    }

    private static EchConfig? ParseEchConfigContents(ReadOnlySpan<byte> c, byte[] raw)
    {
        int p = 0;
        if (c.Length < 1) return null;
        byte configId = c[p++];
        if (p + 2 > c.Length) return null;
        ushort kemId = BinaryHelper.ReadUInt16(c.Slice(p)); p += 2;
        if (kemId != Hpke.KEM_DHKEM_X25519_HKDF_SHA256) return null;
        if (p + 2 > c.Length) return null;
        ushort pkLen = BinaryHelper.ReadUInt16(c.Slice(p)); p += 2;
        if (p + pkLen > c.Length) return null;
        byte[] pk = c.Slice(p, pkLen).ToArray(); p += pkLen;
        if (p + 2 > c.Length) return null;
        ushort csLen = BinaryHelper.ReadUInt16(c.Slice(p)); p += 2;
        if (csLen % 4 != 0 || p + csLen > c.Length) return null;
        var suites = new (ushort, ushort)[csLen / 4];
        for (int i = 0; i < suites.Length; i++)
            suites[i] = (BinaryHelper.ReadUInt16(c.Slice(p + i * 4)), BinaryHelper.ReadUInt16(c.Slice(p + i * 4 + 2)));
        p += csLen;
        if (p + 1 > c.Length) return null;
        byte maxNameLen = c[p++];
        if (p + 1 > c.Length) return null;
        byte pnLen = c[p++];
        if (p + pnLen > c.Length) return null;
        byte[] publicName = c.Slice(p, pnLen).ToArray(); p += pnLen;
        if (p + 2 > c.Length) return null;
        ushort extLen = BinaryHelper.ReadUInt16(c.Slice(p)); p += 2;
        if (p + extLen != c.Length) return null; // extensions ignored

        return new EchConfig
        {
            ConfigId = configId, KemId = kemId, PublicKey = pk, CipherSuites = suites,
            MaxNameLen = maxNameLen, PublicName = publicName, RawBytes = raw
        };
    }

    /// <summary>Build one ECHConfig (with version+length header) — for the server to publish / tests.</summary>
    public static byte[] BuildEchConfig(byte configId, byte[] publicKey,
        (ushort kdf, ushort aead)[] suites, byte maxNameLen, string publicName)
    {
        using var c = new MemoryStream();
        c.WriteByte(configId);
        BinaryHelper.WriteUInt16(c, Hpke.KEM_DHKEM_X25519_HKDF_SHA256);
        BinaryHelper.WriteUInt16(c, (ushort)publicKey.Length); c.Write(publicKey);
        BinaryHelper.WriteUInt16(c, (ushort)(suites.Length * 4));
        foreach (var (kdf, aead) in suites) { BinaryHelper.WriteUInt16(c, kdf); BinaryHelper.WriteUInt16(c, aead); }
        c.WriteByte(maxNameLen);
        byte[] pn = System.Text.Encoding.ASCII.GetBytes(publicName);
        c.WriteByte((byte)pn.Length); c.Write(pn);
        BinaryHelper.WriteUInt16(c, 0); // no extensions
        byte[] contents = c.ToArray();

        using var o = new MemoryStream();
        BinaryHelper.WriteUInt16(o, EchConfigVersion);
        BinaryHelper.WriteUInt16(o, (ushort)contents.Length);
        o.Write(contents);
        return o.ToArray();
    }

    public static byte[] BuildEchConfigList(params byte[][] configs)
    {
        int total = configs.Sum(c => c.Length);
        using var o = new MemoryStream();
        BinaryHelper.WriteUInt16(o, (ushort)total);
        foreach (var c in configs) o.Write(c);
        return o.ToArray();
    }

    // ================================================================
    //  HPKE info + AEAD suite selection
    // ================================================================

    /// <summary>HPKE info = "tls ech" ‖ 0x00 ‖ ECHConfig (draft §6.1).</summary>
    public static byte[] HpkeInfo(EchConfig config)
    {
        byte[] label = System.Text.Encoding.ASCII.GetBytes("tls ech");
        byte[] info = new byte[label.Length + 1 + config.RawBytes.Length];
        Buffer.BlockCopy(label, 0, info, 0, label.Length);
        info[label.Length] = 0x00;
        Buffer.BlockCopy(config.RawBytes, 0, info, label.Length + 1, config.RawBytes.Length);
        return info;
    }

    public static (ushort kdf, ushort aead) PickSuite(EchConfig config)
    {
        foreach (var (kdf, aead) in config.CipherSuites)
            if (kdf == Hpke.KDF_HKDF_SHA256 && (aead == Hpke.AEAD_AES_128_GCM || aead == Hpke.AEAD_CHACHA20_POLY1305))
                return (kdf, aead);
        throw new TlsException(AlertDescription.HandshakeFailure, "No supported HPKE suite in ECHConfig");
    }

    // ================================================================
    //  EncodedClientHelloInner (no outer_extensions compression)
    // ================================================================

    /// <summary>Inner CH message → EncodedClientHelloInner (draft §5.1): session_id emptied; the
    /// extensions after server_name (byte-identical to the outer's) are replaced by a single
    /// ech_outer_extensions(0xfd00) reference listing their types; zero-padding appended. The client
    /// still hashes the FULL inner — only the sealed payload is compressed.</summary>
    public static byte[] EncodeInner(byte[] innerChMsg, int maxNameLen)
    {
        var (_, body) = HandshakeMessages.Unframe(innerChMsg);
        int sidLen = body[34];
        int afterSid = 35 + sidLen;
        int csLen = BinaryHelper.ReadUInt16(body.AsSpan(afterSid));
        int afterCs = afterSid + 2 + csLen;
        int compLen = body[afterCs];
        int afterComp = afterCs + 1 + compLen;
        int extTotal = BinaryHelper.ReadUInt16(body.AsSpan(afterComp));
        int extStart = afterComp + 2;
        int extEnd = extStart + extTotal;

        // Keep server_name inline (it differs from the outer); collect the rest's types to compress.
        byte[]? serverNameExt = null;
        var compressedTypes = new List<ushort>();
        int q = extStart;
        while (q + 4 <= extEnd)
        {
            ushort et = BinaryHelper.ReadUInt16(body.AsSpan(q));
            ushort el = BinaryHelper.ReadUInt16(body.AsSpan(q + 2));
            int full = 4 + el;
            if (et == (ushort)ExtensionType.ServerName && serverNameExt == null)
                serverNameExt = body[q..(q + full)];
            else
                compressedTypes.Add(et);
            q += full;
        }

        using var exts = new MemoryStream();
        if (serverNameExt != null) exts.Write(serverNameExt);
        using (var oe = new MemoryStream())
        {
            oe.WriteByte((byte)(compressedTypes.Count * 2)); // OuterExtensions list length (bytes)
            foreach (var t in compressedTypes) BinaryHelper.WriteUInt16(oe, t);
            byte[] oeBody = oe.ToArray();
            BinaryHelper.WriteUInt16(exts, (ushort)ExtensionType.EchOuterExtensions);
            BinaryHelper.WriteUInt16(exts, (ushort)oeBody.Length);
            exts.Write(oeBody);
        }
        byte[] newExts = exts.ToArray();

        using var enc = new MemoryStream();
        enc.Write(body, 0, 34);                            // legacy_version + random
        enc.WriteByte(0x00);                               // empty session_id
        enc.Write(body, afterSid, afterComp - afterSid);   // cipher_suites + compression_methods
        BinaryHelper.WriteUInt16(enc, (ushort)newExts.Length);
        enc.Write(newExts);
        byte[] encodedNoPad = enc.ToArray();

        int padded = ((encodedNoPad.Length + Math.Max(0, maxNameLen)) + 31) & ~31; // pad to a 32-byte multiple
        byte[] result = new byte[padded];
        Buffer.BlockCopy(encodedNoPad, 0, result, 0, encodedNoPad.Length);
        return result; // trailing pad bytes already zero
    }

    /// <summary>EncodedClientHelloInner + the outer CH → the framed ClientHelloInner the client hashed.
    /// Restores session_id from the outer, expands ech_outer_extensions(0xfd00) by splicing the
    /// referenced extensions out of the outer CH, and strips trailing padding — byte-exact with the
    /// client's inner (the TLS 1.3 transcript depends on it). Also accepts an uncompressed encoding.</summary>
    public static byte[] DecodeInnerChMsg(byte[] encoded, byte[] outerChBody, byte[] outerSessionId)
    {
        int sidLen = encoded[34];
        int afterSid = 35 + sidLen;
        if (afterSid + 2 > encoded.Length) throw new TlsException(AlertDescription.DecodeError, "ECH inner truncated (cipher_suites)");
        int csLen = BinaryHelper.ReadUInt16(encoded.AsSpan(afterSid));
        int afterCs = afterSid + 2 + csLen;
        if (afterCs + 1 > encoded.Length) throw new TlsException(AlertDescription.DecodeError, "ECH inner truncated (compression)");
        int compLen = encoded[afterCs];
        int afterComp = afterCs + 1 + compLen;
        if (afterComp + 2 > encoded.Length) throw new TlsException(AlertDescription.DecodeError, "ECH inner truncated (extensions)");
        int extTotal = BinaryHelper.ReadUInt16(encoded.AsSpan(afterComp));
        int extStart = afterComp + 2;
        int extEnd = extStart + extTotal;
        if (extEnd > encoded.Length) throw new TlsException(AlertDescription.DecodeError, "ECH inner ext overruns");

        using var fullExts = new MemoryStream();
        int q = extStart;
        while (q + 4 <= extEnd)
        {
            ushort et = BinaryHelper.ReadUInt16(encoded.AsSpan(q));
            ushort el = BinaryHelper.ReadUInt16(encoded.AsSpan(q + 2));
            if (et == (ushort)ExtensionType.EchOuterExtensions)
            {
                int b = q + 4;
                int listLen = encoded[b]; b++;
                for (int i = 0; i + 2 <= listLen; i += 2)
                {
                    ushort refType = BinaryHelper.ReadUInt16(encoded.AsSpan(b + i));
                    if (refType == (ushort)ExtensionType.EchOuterExtensions)
                        throw new TlsException(AlertDescription.DecodeError, "ech_outer_extensions self-reference");
                    byte[]? extBytes = GetExtensionFullBytes(outerChBody, refType)
                        ?? throw new TlsException(AlertDescription.DecodeError, "ech_outer_extensions references a missing outer extension");
                    fullExts.Write(extBytes);
                }
            }
            else
            {
                fullExts.Write(encoded, q, 4 + el);
            }
            q += 4 + el;
        }
        byte[] extsBytes = fullExts.ToArray();

        using var outBody = new MemoryStream();
        outBody.Write(encoded, 0, 34);
        outBody.WriteByte((byte)outerSessionId.Length);
        outBody.Write(outerSessionId);
        outBody.Write(encoded, afterSid, afterComp - afterSid); // cipher_suites + compression_methods
        BinaryHelper.WriteUInt16(outBody, (ushort)extsBytes.Length);
        outBody.Write(extsBytes);
        return HandshakeMessages.Frame(HandshakeType.ClientHello, outBody.ToArray());
    }

    /// <summary>Full bytes (type‖len‖body) of the first extension of the given type in a CH body, or null.</summary>
    private static byte[]? GetExtensionFullBytes(byte[] chBody, ushort type)
    {
        int p = 34; int sidLen = chBody[p]; p = 35 + sidLen;
        int csLen = BinaryHelper.ReadUInt16(chBody.AsSpan(p)); p += 2 + csLen;
        int compLen = chBody[p]; p += 1 + compLen;
        int extTotal = BinaryHelper.ReadUInt16(chBody.AsSpan(p)); p += 2;
        int extEnd = p + extTotal;
        while (p + 4 <= extEnd)
        {
            ushort et = BinaryHelper.ReadUInt16(chBody.AsSpan(p));
            ushort el = BinaryHelper.ReadUInt16(chBody.AsSpan(p + 2));
            if (et == type) return chBody[p..(p + 4 + el)];
            p += 4 + el;
        }
        return null;
    }

    // ================================================================
    //  encrypted_client_hello extension (outer form)
    // ================================================================

    /// <summary>ECHClientHello (outer): type(0) ‖ kdf(2) ‖ aead(2) ‖ config_id(1) ‖ enc&lt;16&gt; ‖ payload&lt;16&gt;.</summary>
    public static byte[] BuildOuterEchExtBody(byte configId, ushort kdf, ushort aead, byte[] enc, byte[] payload)
    {
        using var ms = new MemoryStream();
        ms.WriteByte(0x00); // outer
        BinaryHelper.WriteUInt16(ms, kdf);
        BinaryHelper.WriteUInt16(ms, aead);
        ms.WriteByte(configId);
        BinaryHelper.WriteUInt16(ms, (ushort)enc.Length); ms.Write(enc);
        BinaryHelper.WriteUInt16(ms, (ushort)payload.Length); ms.Write(payload);
        return ms.ToArray();
    }

    public static (ushort kdf, ushort aead, byte configId, byte[] enc, byte[] payload)? ParseOuterEchExt(byte[] echBody)
    {
        int p = 0;
        if (echBody.Length < 1 || echBody[p++] != 0x00) return null; // must be outer (type 0)
        if (p + 5 > echBody.Length) return null;
        ushort kdf = BinaryHelper.ReadUInt16(echBody.AsSpan(p)); p += 2;
        ushort aead = BinaryHelper.ReadUInt16(echBody.AsSpan(p)); p += 2;
        byte configId = echBody[p++];
        if (p + 2 > echBody.Length) return null;
        ushort encLen = BinaryHelper.ReadUInt16(echBody.AsSpan(p)); p += 2;
        if (p + encLen + 2 > echBody.Length) return null;
        byte[] enc = echBody[p..(p + encLen)]; p += encLen;
        ushort payloadLen = BinaryHelper.ReadUInt16(echBody.AsSpan(p)); p += 2;
        if (p + payloadLen != echBody.Length) return null;
        byte[] payload = echBody[p..(p + payloadLen)];
        return (kdf, aead, configId, enc, payload);
    }

    /// <summary>Absolute offset+length of the ECH payload bytes within a FRAMED ClientHello (for patching).</summary>
    public static (int offset, int len)? LocateEchPayload(byte[] chMsg) => LocatePayload(chMsg, headerOffset: 4);

    private static (int offset, int len)? LocatePayload(byte[] buf, int headerOffset)
    {
        try
        {
            int p = headerOffset + 2 + 32; // [header] + legacy_version + random
            int sidLen = buf[p]; p += 1 + sidLen;
            int csLen = BinaryHelper.ReadUInt16(buf.AsSpan(p)); p += 2 + csLen;
            int compLen = buf[p]; p += 1 + compLen;
            int extTotal = BinaryHelper.ReadUInt16(buf.AsSpan(p)); p += 2;
            int extEnd = p + extTotal;
            while (p + 4 <= extEnd)
            {
                ushort et = BinaryHelper.ReadUInt16(buf.AsSpan(p));
                ushort el = BinaryHelper.ReadUInt16(buf.AsSpan(p + 2));
                int extBodyStart = p + 4;
                if (et == (ushort)ExtensionType.EncryptedClientHello)
                {
                    int q = extBodyStart + 1 + 2 + 2 + 1; // type+kdf+aead+config_id
                    ushort encLen = BinaryHelper.ReadUInt16(buf.AsSpan(q)); q += 2 + encLen;
                    ushort payloadLen = BinaryHelper.ReadUInt16(buf.AsSpan(q)); q += 2;
                    return (q, payloadLen);
                }
                p = extBodyStart + el;
            }
        }
        catch { }
        return null;
    }

    // ================================================================
    //  Client: encrypt — orchestration
    // ================================================================

    /// <summary>Build the ClientHelloOuter carrying the HPKE-sealed ClientHelloInner.
    /// <paramref name="buildOuterFramed"/> builds the outer CH given the ECH extension body (the caller
    /// supplies it because CH construction lives in HandshakeMessages). The AAD is the ClientHelloOuter
    /// body with the payload field zeroed (draft §5.2) — we build with a zero payload, seal, then patch
    /// the sealed bytes back in.</summary>
    public static (byte[] outerChMsg, EchClientContext ctx) EncryptClientHello(
        byte[] innerChMsg, byte[] innerRandom, EchConfig config, Func<byte[], byte[]> buildOuterFramed)
    {
        byte[] encoded = EncodeInner(innerChMsg, config.MaxNameLen);
        var (kdf, aead) = PickSuite(config);
        byte[] info = HpkeInfo(config);
        var (enc, hctx) = Hpke.KeySchedule.SetupBaseSender(config.PublicKey, info, aead);

        int payloadLen = encoded.Length + 16; // AEAD tag
        byte[] echExtZero = BuildOuterEchExtBody(config.ConfigId, kdf, aead, enc, new byte[payloadLen]);
        byte[] outerZero = buildOuterFramed(echExtZero);
        var loc = LocateEchPayload(outerZero)
                  ?? throw new TlsException(AlertDescription.InternalError, "ECH payload not located in outer CH");

        var (_, aad) = HandshakeMessages.Unframe(outerZero); // outer body with payload still zero = ClientHelloOuterAAD
        byte[] payload;
        using (hctx) payload = hctx.Seal(aad, encoded);

        byte[] outerFinal = (byte[])outerZero.Clone();
        Buffer.BlockCopy(payload, 0, outerFinal, loc.offset, loc.len);
        return (outerFinal, new EchClientContext(innerChMsg, innerRandom));
    }

    // ================================================================
    //  Server: decrypt outer → framed inner CH msg (null = reject)
    // ================================================================

    public static byte[]? DecryptClientHello(byte[] outerChBody, byte[] skR, EchConfig[] configs)
    {
        var parsed = HandshakeMessages.ParseClientHello(outerChBody);
        if (parsed.EncryptedClientHelloData == null) return null;
        var ext = ParseOuterEchExt(parsed.EncryptedClientHelloData);
        if (ext == null) return null;
        var (kdf, aead, configId, enc, payload) = ext.Value;
        if (kdf != Hpke.KDF_HKDF_SHA256) return null;

        // Trial-decrypt against every config whose id matches (draft allows id collisions).
        foreach (var config in configs)
        {
            if (config.ConfigId != configId) continue;
            byte[]? aad = ZeroEchPayloadInBody(outerChBody);
            if (aad == null) continue;
            try
            {
                byte[] info = HpkeInfo(config);
                using var ctx = Hpke.KeySchedule.SetupBaseReceiver(enc, skR, info, aead);
                byte[]? encoded = ctx.Open(aad, payload);
                if (encoded == null) continue;
                return DecodeInnerChMsg(encoded, outerChBody, parsed.SessionId);
            }
            catch { /* try next config */ }
        }
        return null;
    }

    /// <summary>Copy of a CH body with the ECH extension's payload bytes zeroed (the ClientHelloOuterAAD).</summary>
    private static byte[]? ZeroEchPayloadInBody(byte[] chBody)
    {
        var loc = LocatePayload(chBody, headerOffset: 0);
        if (loc == null) return null;
        byte[] copy = (byte[])chBody.Clone();
        Array.Clear(copy, loc.Value.offset, loc.Value.len);
        return copy;
    }
}
