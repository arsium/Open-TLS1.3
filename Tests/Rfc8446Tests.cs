namespace Tests;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TLS;
using static Tests.T;

/// <summary>Targeted unit tests for the 2026-06-08 RFC 8446 hardening pass (the negative/parse paths
/// that the end-to-end loopback suite doesn't reach). The positive paths for the handshake-internal
/// fixes (HRR selected_group ∈ supported_groups, post-handshake reassembly, ticket-lifetime clamp,
/// missing_extension on a cert handshake without signature_algorithms) are exercised by the existing
/// loopback / HRR / resumption / post-handshake-auth tests, which must stay green.</summary>
public static class Rfc8446Tests
{
    public static void Run()
    {
        Section("RFC 8446 hardening (2026-06-08 audit fixes)");
        CompressionMethodMustBeNull();
        ProtectedRecordsMustUseApplicationDataOuterType();
        ServerHelloCompressionMethodMustBeNull();
        ServerHelloRejectsUnsolicitedExtension();
        CertificateRequestRequiresSignatureAlgorithms();
        ClientHelloSignatureAlgorithmsMustBeExact();
        RsaPssCaChainVerifies();
        HelloRetryCh2Consistency();
    }

    // §4.1.4 — the second ClientHello (after HelloRetryRequest) must keep its invariant fields; the
    // server's EnforceHelloRetryConsistency check (default on) rejects a CH2 that changes them. The
    // conformant accept-path is covered end-to-end by the forced-HRR loopback tests; here we pin the
    // exact invariant set via the pure predicate.
    private static void HelloRetryCh2Consistency()
    {
        var ch1 = MakeCh(new[] { CipherSuite.TLS_AES_128_GCM_SHA256 }, "localhost", null);

        Check("HRR CH2 unchanged invariants → accepted",
            TlsConnection.HelloRetryConsistent(ch1, MakeCh(new[] { CipherSuite.TLS_AES_128_GCM_SHA256 }, "localhost", null)));
        Check("HRR CH2 changed cipher_suites → rejected",
            !TlsConnection.HelloRetryConsistent(ch1, MakeCh(new[] { CipherSuite.TLS_AES_256_GCM_SHA384 }, "localhost", null)));
        Check("HRR CH2 changed server_name → rejected",
            !TlsConnection.HelloRetryConsistent(ch1, MakeCh(new[] { CipherSuite.TLS_AES_128_GCM_SHA256 }, "evil.example", null)));
        byte[] otherRandom = new byte[32]; Array.Fill(otherRandom, (byte)0x9a);
        Check("HRR CH2 changed client_random → rejected",
            !TlsConnection.HelloRetryConsistent(ch1, MakeCh(new[] { CipherSuite.TLS_AES_128_GCM_SHA256 }, "localhost", otherRandom)));
    }

    private static ParsedClientHello MakeCh(CipherSuite[] suites, string sni, byte[]? random) => new ParsedClientHello
    {
        ClientRandom = random ?? new byte[32],
        SessionId = new byte[32],
        CipherSuites = suites,
        KeyShares = Array.Empty<(NamedGroup, byte[])>(),
        SupportedGroups = new[] { NamedGroup.X25519 },
        SignatureAlgorithms = null,
        ServerName = sni,
    };

    // #6 — RFC 8446 §4.1.2/§4.2.1: a TLS 1.3 ClientHello's legacy_compression_methods MUST be exactly
    // the single null method (0x00). A length != 1 or a non-zero method is illegal_parameter.
    private static void CompressionMethodMustBeNull()
    {
        Check("CH with a non-null compression method rejected",
            Throws(() => HandshakeMessages.ParseClientHello(ClientHelloHead(new byte[] { 0x00, 0x01 }))));
        Check("CH with empty compression_methods rejected",
            Throws(() => HandshakeMessages.ParseClientHello(ClientHelloHead(Array.Empty<byte>()))));
        // The single-null-method (valid) path is exercised by every loopback handshake below, which all
        // build a conformant ClientHello; a minimal head here would instead trip the §9.2 mandatory-
        // extension check (no supported_versions), so it isn't a clean isolated control.
    }

    private static void ProtectedRecordsMustUseApplicationDataOuterType()
    {
        byte[] plaintextHandshakeRecord =
        {
            (byte)ContentType.Handshake, 0x03, 0x03, 0x00, 0x01, 0x00
        };
        using var ms = new MemoryStream(plaintextHandshakeRecord);
        using var record = new RecordLayer(ms);
        record.SetReadCipher(new AeadCipher(new byte[16], new byte[12], AeadAlgorithm.AesGcm));
        Check("record layer rejects plaintext handshake records after read keys are installed",
            Throws(() => record.ReadRecord()));
    }

    private static void ServerHelloCompressionMethodMustBeNull()
    {
        Check("ServerHello with non-null legacy_compression_method rejected",
            Throws(() => HandshakeMessages.ParseServerHello(ServerHelloBody(includeServerName: false, compression: 0x01))));
    }

    private static void CertificateRequestRequiresSignatureAlgorithms()
    {
        Check("CertificateRequest missing mandatory signature_algorithms rejected",
            Throws(() => HandshakeMessages.ParseCertificateRequest(new byte[] { 0x00, 0x00, 0x00 })));
    }

    private static void ClientHelloSignatureAlgorithmsMustBeExact()
    {
        var exts = new List<byte>();
        AddExtension(exts, ExtensionType.SupportedVersions, new byte[] { 0x02, 0x03, 0x04 });
        AddExtension(exts, ExtensionType.SignatureAlgorithms, new byte[] { 0x00, 0x01, 0x04 });
        Check("ClientHello with malformed signature_algorithms vector rejected",
            Throws(() => HandshakeMessages.ParseClientHello(ClientHelloHead(new byte[] { 0x00 }, exts.ToArray()))));
    }

    // Minimal ClientHello body: ...legacy_version, random, session_id, cipher_suites, compression,
    // then an empty extensions block. Enough to reach (and exercise) the compression-method check.
    private static byte[] ClientHelloHead(byte[] compMethods, byte[]? extensions = null)
    {
        var b = new List<byte>();
        b.AddRange(new byte[] { 0x03, 0x03 });               // legacy_version
        b.AddRange(new byte[32]);                            // random
        b.Add(0x00);                                         // session_id length 0
        b.AddRange(new byte[] { 0x00, 0x02, 0x13, 0x01 });   // cipher_suites: TLS_AES_128_GCM_SHA256
        b.Add((byte)compMethods.Length);                     // compression_methods length
        b.AddRange(compMethods);
        extensions ??= Array.Empty<byte>();
        b.Add((byte)(extensions.Length >> 8)); b.Add((byte)extensions.Length);
        b.AddRange(extensions);
        return b.ToArray();
    }

    // #2 — RFC 8446 §4.1.3/§4.2: a ServerHello may carry only key_share / pre_shared_key /
    // supported_versions; a server MUST NOT inject any other (unsolicited) extension.
    private static void ServerHelloRejectsUnsolicitedExtension()
    {
        Check("clean ServerHello (supported_versions + key_share) parses",
            !Throws(() => HandshakeMessages.ParseServerHello(ServerHelloBody(includeServerName: false))));
        Check("ServerHello carrying an unsolicited server_name rejected",
            Throws(() => HandshakeMessages.ParseServerHello(ServerHelloBody(includeServerName: true))));
    }

    private static byte[] ServerHelloBody(bool includeServerName, byte compression = 0x00)
    {
        var exts = new List<byte>();
        exts.AddRange(new byte[] { 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 });             // supported_versions = 0x0304
        exts.AddRange(new byte[] { 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20 }); // key_share: X25519 + 32B key
        exts.AddRange(new byte[32]);
        if (includeServerName)
            exts.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 });                     // server_name — not permitted in SH

        var b = new List<byte>();
        b.AddRange(new byte[] { 0x03, 0x03 });        // legacy_version
        b.AddRange(new byte[32]);                     // random (all-zero → not the HRR sentinel)
        b.Add(0x00);                                  // session_id length 0
        b.AddRange(new byte[] { 0x13, 0x01 });        // cipher_suite
        b.Add(compression);                           // compression
        b.Add((byte)(exts.Count >> 8)); b.Add((byte)exts.Count);
        b.AddRange(exts);
        return b.ToArray();
    }

    private static void AddExtension(List<byte> dst, ExtensionType type, byte[] body)
    {
        dst.Add((byte)((ushort)type >> 8));
        dst.Add((byte)(ushort)type);
        dst.Add((byte)(body.Length >> 8));
        dst.Add((byte)body.Length);
        dst.AddRange(body);
    }

    // #1 — RFC 4055 / RFC 8446 §4.4.2.4: a CA that signs with RSA-PSS (id-RSASSA-PSS, as most modern
    // PKIs now do) MUST verify in VerifyChain. Previously the chain was hard-coded to PKCS#1 v1.5 padding,
    // so a PSS-signed issuer was rejected as a bad signature (un-pinnable via CaCertificate). We mint a
    // real PSS chain with the .NET BCL — i.e. exactly the interop case this fix targets.
    private static void RsaPssCaChainVerifies()
    {
        using var caRsa = RSA.Create(2048);
        var caReq = new CertificateRequest("CN=PSS Test CA", caRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var caCert = caReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        using var leafRsa = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=localhost", leafRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        byte[] serial = new byte[8]; RandomNumberGenerator.Fill(serial);
        using var leafCert = leafReq.Create(caCert, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30), serial);

        var caTls = new TlsCertificate
        {
            DerData = caCert.RawData,
            PublicKey = caRsa.ExportRSAPublicKey(),
            PrivateKey = Array.Empty<byte>(),
            SignatureAlgorithm = SignatureScheme.RsaPssRsaeSha256,
        };
        var leafTls = new TlsCertificate
        {
            DerData = leafCert.RawData,
            PublicKey = leafRsa.ExportRSAPublicKey(),
            PrivateKey = Array.Empty<byte>(),
            SignatureAlgorithm = SignatureScheme.RsaPssRsaeSha256,
        };

        Check("RSA-PSS-signed leaf verifies against its RSA-PSS CA", CertificateUtils.VerifyChain(leafTls, caTls));

        // No regression: a PKCS#1 v1.5 chain (the stack's own issuance) still verifies.
        var ca = CertificateUtils.GenerateCARsa("PKCS1 Test CA");
        var leaf = CertificateUtils.IssueCertificateRsa("localhost", ca, CertificateProfile.Server);
        Check("PKCS#1 v1.5 CA chain still verifies", CertificateUtils.VerifyChain(leaf, ca));
    }

    private static bool Throws(Action a)
    {
        try { a(); return false; } catch { return true; }
    }
}
