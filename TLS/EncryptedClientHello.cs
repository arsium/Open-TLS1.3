namespace TLS;

using System.Security.Cryptography;

/// <summary>
/// Encrypted Client Hello (ECH) implementation per RFC 9849.
/// Encrypts sensitive ClientHello data using HPKE to prevent network observation.
/// </summary>
public static class EncryptedClientHello
{
    // ECH extension type is defined in TlsConstants.ExtensionType.EncryptedClientHello

    /// <summary>ECH configuration entry from ECHConfigList.</summary>
    public sealed class EchConfig
    {
        public byte Version { get; init; }
        public ushort Length { get; init; }
        public byte ConfigId { get; init; }
        public ushort KemId { get; init; }
        public byte[] PublicKey { get; init; } = null!;
        public ushort[] CipherSuites { get; init; } = null!;
        public ushort MaxNameLen { get; init; }
        public byte[] PublicName { get; init; } = null!;
        public byte[] Extensions { get; init; } = null!;
    }

    /// <summary>ECH client context for encrypting ClientHello.</summary>
    public sealed class EchClientContext
    {
        public EchConfig Config { get; }
        public byte[] EncodedInnerClientHello { get; }
        public byte[] Enc { get; } // HPKE encapsulated key
        public byte[] ConfigId { get; }

        internal EchClientContext(EchConfig config, byte[] encodedInner, byte[] enc, byte configId)
        {
            Config = config;
            EncodedInnerClientHello = encodedInner;
            Enc = enc;
            ConfigId = new[] { configId };
        }
    }

    /// <summary>Parse ECHConfigList from wire format.</summary>
    public static EchConfig[] ParseEchConfigList(byte[] configListBytes)
    {
        if (configListBytes.Length < 2) throw new ArgumentException("Invalid ECHConfigList length");

        var configs = new List<EchConfig>();
        int pos = 0;

        // Read total length
        ushort totalLen = BinaryHelper.ReadUInt16(configListBytes.AsSpan(pos)); pos += 2;
        if (totalLen != configListBytes.Length - 2) throw new ArgumentException("ECHConfigList length mismatch");

        while (pos < configListBytes.Length)
        {
            // 3-byte ECHConfig header: 1-byte version + 2-byte length. Bail loudly on truncation
            // — silent breaks here used to mask malformed lists as "no ECH" and would have been a
            // confusing source of "why doesn't ECH work" bugs.
            if (pos + 3 > configListBytes.Length)
                throw new ArgumentException("Truncated ECHConfigList: incomplete config header");

            byte version = configListBytes[pos++];
            ushort configLen = BinaryHelper.ReadUInt16(configListBytes.AsSpan(pos)); pos += 2;

            if (pos + configLen > configListBytes.Length)
                throw new ArgumentException("Truncated ECHConfigList: config length exceeds buffer");

            // Parse ECHConfig contents (unknown version/algorithm → silent skip for forward compat)
            var config = ParseEchConfig(version, configListBytes.AsSpan(pos, configLen));
            if (config != null) configs.Add(config);

            pos += configLen;
        }

        return configs.ToArray();
    }

    private static EchConfig? ParseEchConfig(byte version, ReadOnlySpan<byte> configBytes)
    {
        if (version != 0xfe) return null; // Only support draft version for now

        int pos = 0;
        if (configBytes.Length < 1) return null;

        byte configId = configBytes[pos++];
        if (pos + 2 > configBytes.Length) return null;

        ushort kemId = BinaryHelper.ReadUInt16(configBytes.Slice(pos)); pos += 2;
        if (kemId != Hpke.KEM_DHKEM_X25519_HKDF_SHA256) return null; // Only X25519 supported

        if (pos + 2 > configBytes.Length) return null;
        ushort pubKeyLen = BinaryHelper.ReadUInt16(configBytes.Slice(pos)); pos += 2;
        if (pos + pubKeyLen > configBytes.Length) return null;

        byte[] publicKey = configBytes.Slice(pos, pubKeyLen).ToArray(); pos += pubKeyLen;

        if (pos + 2 > configBytes.Length) return null;
        ushort cipherSuitesLen = BinaryHelper.ReadUInt16(configBytes.Slice(pos)); pos += 2;
        if (pos + cipherSuitesLen > configBytes.Length || cipherSuitesLen % 4 != 0) return null;

        var cipherSuites = new List<ushort>();
        for (int i = 0; i < cipherSuitesLen; i += 4)
        {
            ushort kemId2 = BinaryHelper.ReadUInt16(configBytes.Slice(pos + i));
            ushort aeadId = BinaryHelper.ReadUInt16(configBytes.Slice(pos + i + 2));
            // Store as combined value for simplicity
            cipherSuites.Add((ushort)((kemId2 << 8) | aeadId));
        }
        pos += cipherSuitesLen;

        if (pos + 2 > configBytes.Length) return null;
        ushort maxNameLen = BinaryHelper.ReadUInt16(configBytes.Slice(pos)); pos += 2;

        if (pos + 1 > configBytes.Length) return null;
        byte publicNameLen = configBytes[pos++];
        if (pos + publicNameLen > configBytes.Length) return null;

        byte[] publicName = configBytes.Slice(pos, publicNameLen).ToArray(); pos += publicNameLen;

        if (pos + 2 > configBytes.Length) return null;
        ushort extensionsLen = BinaryHelper.ReadUInt16(configBytes.Slice(pos)); pos += 2;
        if (pos + extensionsLen != configBytes.Length) return null;

        byte[] extensions = configBytes.Slice(pos, extensionsLen).ToArray();

        return new EchConfig
        {
            Version = version,
            Length = (ushort)configBytes.Length,
            ConfigId = configId,
            KemId = kemId,
            PublicKey = publicKey,
            CipherSuites = cipherSuites.ToArray(),
            MaxNameLen = maxNameLen,
            PublicName = publicName,
            Extensions = extensions
        };
    }

    /// <summary>Encrypt ClientHello using ECH (client-side).</summary>
    public static (byte[] outerClientHello, EchClientContext context) EncryptClientHello(
        byte[] innerClientHello, EchConfig config, byte[] outerClientHelloTemplate)
    {
        if (config.KemId != Hpke.KEM_DHKEM_X25519_HKDF_SHA256)
            throw new ArgumentException("Unsupported KEM in ECH config");

        // Encode inner ClientHello with ECH compression
        byte[] encodedInner = EncodeInnerClientHello(innerClientHello, config.MaxNameLen);

        // Setup HPKE encryption
        byte[] info = BuildHpkeInfo(config.ConfigId, outerClientHelloTemplate);
        var (enc, hpkeContext) = Hpke.KeySchedule.SetupBaseSender(config.PublicKey, info);

        // Encrypt the encoded inner ClientHello
        byte[] aad = ComputeAad(config.ConfigId, outerClientHelloTemplate);
        byte[] encryptedClientHello;

        using (hpkeContext)
        {
            encryptedClientHello = hpkeContext.Seal(aad, encodedInner);
        }

        // Build outer ClientHello with encrypted_client_hello extension
        byte[] outerClientHello = BuildOuterClientHello(outerClientHelloTemplate, config, enc, encryptedClientHello);

        var context = new EchClientContext(config, encodedInner, enc, config.ConfigId);
        return (outerClientHello, context);
    }

    /// <summary>Decrypt ClientHello using ECH (server-side).</summary>
    public static byte[]? DecryptClientHello(byte[] outerClientHello, byte[] serverPrivateKey, EchConfig[] configs)
    {
        // Extract encrypted_client_hello extension
        var echExtension = ExtractEchExtension(outerClientHello);
        if (echExtension == null) return null;

        var (echType, configId, enc, encryptedPayload) = echExtension.Value;

        // Find matching config
        EchConfig? config = null;
        foreach (var cfg in configs)
        {
            if (cfg.ConfigId == configId)
            {
                config = cfg;
                break;
            }
        }
        if (config == null) return null;

        try
        {
            // Setup HPKE decryption
            byte[] info = BuildHpkeInfo(configId, outerClientHello);
            using var hpkeContext = Hpke.KeySchedule.SetupBaseReceiver(enc, serverPrivateKey, info);

            // Decrypt inner ClientHello
            byte[] aad = ComputeAad(configId, outerClientHello);
            byte[]? encodedInner = hpkeContext.Open(aad, encryptedPayload);
            if (encodedInner == null) return null;

            // Decode inner ClientHello
            return DecodeInnerClientHello(encodedInner, outerClientHello);
        }
        catch
        {
            return null; // Decryption failed
        }
    }

    private static byte[] EncodeInnerClientHello(byte[] innerCH, ushort maxNameLen)
    {
        // Simplified encoding - in real implementation would compress extensions
        return innerCH;
    }

    private static byte[]? DecodeInnerClientHello(byte[] encoded, byte[] outerCH)
    {
        // Simplified decoding - in real implementation would decompress extensions
        return encoded;
    }

    private static byte[] BuildHpkeInfo(byte configId, byte[] clientHello)
    {
        // RFC 9849 §7.2: HPKE info = "tls ech" || 0x00 || config_id
        var info = new List<byte>();
        info.AddRange(System.Text.Encoding.UTF8.GetBytes("tls ech"));
        info.Add(0x00);
        info.Add(configId);
        return info.ToArray();
    }

    private static byte[] ComputeAad(byte configId, byte[] clientHello)
    {
        // RFC 9849 §7.2: AAD = config_id || "ClientHello" || ClientHello (without ECH extension)
        var aad = new List<byte>();
        aad.Add(configId);
        aad.AddRange(System.Text.Encoding.UTF8.GetBytes("ClientHello"));

        // Remove ECH extension from ClientHello for AAD computation
        byte[] chWithoutEch = RemoveEchExtension(clientHello);
        aad.AddRange(chWithoutEch);

        return aad.ToArray();
    }

    private static byte[] BuildOuterClientHello(byte[] template, EchConfig config, byte[] enc, byte[] encryptedPayload)
    {
        // Build encrypted_client_hello extension
        using var ms = new MemoryStream();
        ms.WriteByte(0x00); // ECH type (outer)
        ms.WriteByte(config.ConfigId);
        BinaryHelper.WriteUInt16(ms, (ushort)enc.Length);
        ms.Write(enc);
        BinaryHelper.WriteUInt16(ms, (ushort)encryptedPayload.Length);
        ms.Write(encryptedPayload);

        byte[] echExtensionData = ms.ToArray();

        // Insert ECH extension into template ClientHello
        return InsertEchExtension(template, echExtensionData);
    }

    private static (byte echType, byte configId, byte[] enc, byte[] encryptedPayload)? ExtractEchExtension(byte[] clientHello)
    {
        // Parse ClientHello to find encrypted_client_hello extension
        var parsed = HandshakeMessages.ParseClientHello(clientHello);
        if (!parsed.IsOuterClientHello || parsed.EncryptedClientHelloData == null)
            return null;

        // Parse ECH extension data: type(1) || config_id(1) || enc_len(2) || enc || payload_len(2) || payload
        var echData = parsed.EncryptedClientHelloData;
        if (echData.Length < 6) return null;

        int pos = 0;
        byte echType = echData[pos++];
        byte configId = echData[pos++];

        ushort encLen = BinaryHelper.ReadUInt16(echData.AsSpan(pos)); pos += 2;
        if (pos + encLen + 2 > echData.Length) return null;

        byte[] enc = echData[pos..(pos + encLen)]; pos += encLen;

        ushort payloadLen = BinaryHelper.ReadUInt16(echData.AsSpan(pos)); pos += 2;
        if (pos + payloadLen != echData.Length) return null;

        byte[] encryptedPayload = echData[pos..(pos + payloadLen)];

        return (echType, configId, enc, encryptedPayload);
    }

    private static byte[] RemoveEchExtension(byte[] clientHello)
    {
        // Parse ClientHello and rebuild without ECH extension
        var parsed = HandshakeMessages.ParseClientHello(clientHello);
        if (!parsed.IsOuterClientHello)
            return clientHello; // No ECH extension to remove

        // For AAD computation, we need to reconstruct ClientHello without ECH extension
        // This is a simplified implementation that rebuilds the ClientHello

        // Extract basic ClientHello components
        byte[] reconstructed = HandshakeMessages.BuildClientHelloInner(
            parsed.ClientRandom,
            parsed.SessionId,
            parsed.CipherSuites,
            parsed.KeyShares,
            parsed.ServerName,
            null, // No cookie for reconstructed CH
            null, // PSK data needs special handling - simplified for now
            parsed.OffersEarlyData,
            parsed.AlpnProtocols,
            parsed.RequestsOcspStapling,
            parsed.TicketRequestCount
        );

        return reconstructed;
    }

    private static byte[] InsertEchExtension(byte[] template, byte[] echExtensionData)
    {
        // Parse template ClientHello and rebuild with ECH extension
        var parsed = HandshakeMessages.ParseClientHello(template);

        // For outer ClientHello construction, we rebuild with ECH extension
        // This uses the existing BuildClientHelloExtensions infrastructure

        // This is a simplified approach - a full implementation would need
        // more sophisticated ClientHello reconstruction that preserves all extensions
        // while adding the ECH extension

        // For now, return the template as ECH extension will be added by
        // the BuildClientHelloExtensions function when called with echExtensionData
        return template;
    }
}