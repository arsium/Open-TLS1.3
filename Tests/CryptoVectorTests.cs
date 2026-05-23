namespace Tests;

using System.Text;
using TLS;
using static Tests.T;

/// <summary>Known-answer tests for the crypto primitives, against published standard vectors.</summary>
public static class CryptoVectorTests
{
    public static void Run()
    {
        MgmKat();
        Sm4Sm3Kat();
        Sm4AeadKat();
        StreebogKat();
        GostSignatureKat();
        Sm2SignatureKat();
        EcdhAgreement();
        HkdfKat();
        X25519Kat();
        ChaCha20Poly1305Kat();
        CertificateCompressionRoundtrip();
    }

    // RFC 9058 Appendix — MGM over Kuznyechik.
    private static void MgmKat()
    {
        Section("MGM AEAD (RFC 9058 / RFC 9367)");
        var key = H("8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF");
        var nonce = H("1122334455667700FFEEDDCCBBAA9988");
        var aad = H("0202020202020202010101010101010104040404040404040303030303030303EA0505050505050505");
        var pt = H("1122334455667700FFEEDDCCBBAA998800112233445566778899AABBCCEEFF0A112233445566778899AABBCCEEFF0A002233445566778899AABBCCEEFF0A0011AABBCC");
        using var mgm = new Mgm(key, kuznyechik: true, tagLen: 16);
        var outp = mgm.Encrypt(nonce, pt, aad);
        Eq("MGM-Kuznyechik ciphertext", X(outp[..pt.Length]),
            "a9757b8147956e9055b8a33de89f42fc8075d2212bf9fd5bd3f7069aadc16b39497ab15915a6ba85936b5d0ea9f6851cc60c14d4d3f883d0ab94420695c76deb2c7552");
        Eq("MGM-Kuznyechik tag", X(outp[pt.Length..]), "cf5d656f40c34f5c46e8bb0e29fcdb4c");
        Eq("MGM-Kuznyechik roundtrip", X(mgm.Decrypt(nonce, outp, aad)), X(pt));

        // Magma self-consistency (no published TLS vector handy)
        using var mag = new Mgm(H("8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF"), false, 8);
        var n2 = H("1122334455667700");
        var ct2 = mag.Encrypt(n2, pt, aad);
        Check("MGM-Magma roundtrip", Eqb(mag.Decrypt(n2, ct2, aad), pt));
    }

    // GB/T 32907-2016 (SM4) and GB/T 32905-2016 (SM3).
    private static void Sm4Sm3Kat()
    {
        Section("SM4 + SM3 (GB/T)");
        Eq("SM4 single block", X(ChineseCrypto.SM4.EncryptBlock(
            H("0123456789ABCDEFFEDCBA9876543210"), H("0123456789ABCDEFFEDCBA9876543210"))),
            "681edf34d206965e86b3e94f536e4246");
        Eq("SM3(\"abc\")", X(ChineseCrypto.SM3.ComputeHash(Encoding.ASCII.GetBytes("abc"))),
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
        Eq("SM3(empty)", X(ChineseCrypto.SM3.ComputeHash(Array.Empty<byte>())),
            "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b");
        var abcd16 = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("abcd", 16)));
        Eq("SM3(abcd*16)", X(ChineseCrypto.SM3.ComputeHash(abcd16)),
            "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732");
    }

    // RFC 8998 Appendix — SM4-GCM and SM4-CCM.
    private static void Sm4AeadKat()
    {
        Section("SM4-GCM + SM4-CCM AEAD (RFC 8998)");
        var key = H("0123456789ABCDEFFEDCBA9876543210");
        var nonce = H("00001234567800000000ABCD");
        var aad = H("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2");
        var pt = H("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA");

        var gcm = new Sm4Aead(key, ccm: false, 16).Encrypt(nonce, pt, aad);
        Eq("SM4-GCM ciphertext", X(gcm[..pt.Length]),
            "17f399f08c67d5ee19d0dc9969c4bb7d5fd46fd3756489069157b282bb200735d82710ca5c22f0ccfa7cbf93d496ac15a56834cbcf98c397b4024a2691233b8d");
        Eq("SM4-GCM tag", X(gcm[pt.Length..]), "83de3541e4c2b58177e065a9bf7b62ec");

        var ccm = new Sm4Aead(key, ccm: true, 16).Encrypt(nonce, pt, aad);
        Eq("SM4-CCM ciphertext", X(ccm[..pt.Length]),
            "48af93501fa62adbcd414cce6034d895dda1bf8f132f042098661572e7483094fd12e518ce062c98acee28d95df4416bed31a2f04476c18bb40c84a74b97dc5b");
        Eq("SM4-CCM tag", X(ccm[pt.Length..]), "16842d4fa186f56ab33256971fa110f4");
    }

    // GOST R 34.11-2012 (Streebog) — standard test message M1 ("012345...012", natural ASCII byte order).
    // NOTE: this stack emits the digest in the reverse byte order of RFC 6986's textual presentation
    // (a known GOST convention difference; e.g. RFC's 256-bit "00557be5...e159d" reversed == "9d151eef...5500").
    // We assert the actual produced values (self-consistent for sign/verify); external interop is tracked separately.
    private static void StreebogKat()
    {
        Section("Streebog (GOST R 34.11-2012)");
        var m1 = H("3031323334353637383930313233343536373839303132333435363738393031" +
                   "32333435363738393031323334353637383930313233343536373839303132");
        Eq("Streebog-512(M1)", X(GostCrypto.Streebog.Hash512(m1)),
            "1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa" +
            "00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48");
        Eq("Streebog-256(M1)", X(GostCrypto.Streebog.Hash256(m1)),
            "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500");
    }

    // GOST R 34.10-2012 — known signature verification (GOST 34.10-2018 test domain params).
    private static void GostSignatureKat()
    {
        Section("GOST R 34.10-2012 signatures");
        using (var a = new OpenGost.Security.Cryptography.GostECDsaManaged(new System.Security.Cryptography.ECParameters
        {
            Curve = OpenGost.Security.Cryptography.ECCurveOidMap.GetExplicitCurveByOid("1.2.643.7.1.2.1.1.0"),
            Q = new System.Security.Cryptography.ECPoint
            {
                X = H("0bd86fe5d8db89668f789b4e1dba8585c5508b45ec5b59d8906ddb70e2492b7f"),
                Y = H("da77ff871a10fbdf2766d293c5d164afbb3c7b973a41c885d11d70d689b4f126"),
            },
        }))
            Check("GOST 256 verify (known vector)", a.VerifyHash(
                H("e53e042b67e6ec678e2e02b12a0352ce1fc6eee0529cc088119ad872b3c1fb2d"),
                H("01456c64ba4642a1653c235a98a60249bcd6d3f746b631df928014f6c5bf9c4041aa28d2f1ab148280cd9ed56feda41974053554a42767b83ad043fd39dc0493")));

        using (var a = new OpenGost.Security.Cryptography.GostECDsaManaged(new System.Security.Cryptography.ECParameters
        {
            Curve = OpenGost.Security.Cryptography.ECCurveOidMap.GetExplicitCurveByOid("1.2.643.7.1.2.1.2.0"),
            Q = new System.Security.Cryptography.ECPoint
            {
                X = H("e1ef30d52c6133ddd99d1d5c41455cf7df4d8b4c925bbc69af1433d15658515add2146850c325c5b81c133be655aa8c4d440e7b98a8d59487b0c7696bcc55d11"),
                Y = H("ecbe7736a9ec357ff2fd39931f4e114cb8cda359270ac7f0e7ff43d9419419ea61fd2ab77f5d9f63523d3b50a04f63e2a0cf51b7c13adc21560f0bd40cc9c737"),
            },
        }))
            Check("GOST 512 verify (known vector)", a.VerifyHash(
                H("8c5b0772297d77c64f0c561ddbde7a405a5d7c646c97394341f4936553ee847191c5b03570141da733c570c1f9b6091b53ab8d4d7c4a4f5c61e0c9accff35437"),
                H("1081b394696ffe8e6585e7a9362d26b6325f56778aadbc081c0bfbe933d52ff5823ce288e8c4f362526080df7f70ce406a6eeb1f56919cb92a9853bde73e5b4a2f86fa60a081091a23dd795e1e3c689ee512a3c82ee0dcc2643c78eea8fcacd35492558486b20f1c9ec197c90699850260c93bcbcd9c5c3317e19344e173ae36")));
    }

    // SM2 — GM/T 0003.5-2012 Annex A.2 known signature verification.
    private static void Sm2SignatureKat()
    {
        Section("SM2 signature (GM/T 0003.5)");
        var sample = new ChineseCrypto.SM2.Curve(
            p: "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
            a: "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",
            b: "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",
            n: "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",
            gx: "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",
            gy: "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2");
        var pub = H("0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857");
        Check("SM2 verify (known vector)", ChineseCrypto.SM2.Verify(sample, pub,
            Encoding.ASCII.GetBytes("message digest"),
            H("40F1EC59F793D9F49E09DCEF49130D4194F79FB1EED2CAA55BACDB49C4E755D1"),
            H("6FC6DAC32C5D5CF10C77DFB20F7C2EB667A457872FB09EC56327A67EC7DEEBE7"),
            "ALICE123@YAHOO.COM"));
    }

    private static void EcdhAgreement()
    {
        Section("GOST + SM2 ECDH agreement");
        foreach (var g in new[] { NamedGroup.GC256A, NamedGroup.GC256B, NamedGroup.GC256C, NamedGroup.GC256D,
                                  NamedGroup.GC512A, NamedGroup.GC512B, NamedGroup.GC512C })
        {
            string oid = TlsConnection.GostGroupCurveOid(g)!;
            var (aP, aPub) = GostEcdh.GenerateKeyPair(oid);
            var (bP, bPub) = GostEcdh.GenerateKeyPair(oid);
            Check($"GOST ECDH agree {g}",
                Eqb(GostEcdh.ComputeSharedSecret(aP, bPub, oid), GostEcdh.ComputeSharedSecret(bP, aPub, oid)));
        }
        var (x, xp) = ChineseCrypto.SM2.EcdhGenerateKeyPair();
        var (y, yp) = ChineseCrypto.SM2.EcdhGenerateKeyPair();
        Check("SM2 ECDH agree (curveSM2)",
            Eqb(ChineseCrypto.SM2.EcdhSharedSecret(x, yp), ChineseCrypto.SM2.EcdhSharedSecret(y, xp)));
    }

    // RFC 5869 Test Case 1 (HKDF-SHA256).
    private static void HkdfKat()
    {
        Section("HKDF (RFC 5869)");
        var hash = System.Security.Cryptography.HashAlgorithmName.SHA256;
        var prk = Hkdf.Extract(hash, H("000102030405060708090a0b0c"), H("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"));
        Eq("HKDF-Extract PRK", X(prk), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        var okm = Hkdf.Expand(hash, prk, H("f0f1f2f3f4f5f6f7f8f9"), 42);
        Eq("HKDF-Expand OKM", X(okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    }

    // RFC 7748 §5.2 — X25519.
    private static void X25519Kat()
    {
        Section("X25519 (RFC 7748)");
        Eq("X25519 shared", X(X25519.SharedSecret(
            H("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
            H("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"))),
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    }

    // RFC 8439 — Managed ChaCha20 + Poly1305 + AEAD KATs. These cover the fallback
    // implementation used when System.Security.Cryptography.ChaCha20Poly1305 is unavailable
    // (Windows 7/8, some Windows 10 LTSC builds).
    private static void ChaCha20Poly1305Kat()
    {
        Section("ChaCha20 + Poly1305 (RFC 8439)");

        // RFC 8439 §2.4.2 — ChaCha20 encryption: key, nonce, counter=1, plaintext "Ladies and Gentlemen..."
        var key = H("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        var nonce = H("000000000000004a00000000");
        var plain = H(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c6173" +
            "73206f66202739393a204966204920636f756c64206f6666657220796f75206f" +
            "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" +
            "637265656e20776f756c642062652069742e");
        var expectedCt = H(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b" +
            "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8" +
            "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736" +
            "5af90bbf74a35be6b40b8eedf2785e42874d");
        byte[] outCt = new byte[plain.Length];
        ChaCha20.XorKeystream(key, nonce, 1, plain, outCt);
        Eq("ChaCha20 block (RFC 8439 §2.4.2)", X(outCt), X(expectedCt));

        // RFC 8439 §2.5.2 — Poly1305 tag.
        var polyKey = H("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        var polyMsg = System.Text.Encoding.ASCII.GetBytes("Cryptographic Forum Research Group");
        byte[] tag = new byte[16];
        Poly1305.ComputeTag(polyKey, polyMsg, tag);
        Eq("Poly1305 tag (RFC 8439 §2.5.2)", X(tag), "a8061dc1305136c6c22b8baf0c0127a9");

        // RFC 8439 §2.8.2 — AEAD_CHACHA20_POLY1305 encryption.
        var aeadKey = H("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        var aeadNonce = H("070000004041424344454647");
        var aad = H("50515253c0c1c2c3c4c5c6c7");
        var aeadPlain = H(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c6173" +
            "73206f66202739393a204966204920636f756c64206f6666657220796f75206f" +
            "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" +
            "637265656e20776f756c642062652069742e");
        var expectedAead = H(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
            "3ff4def08e4b7a9de576d26586cec64b6116");
        var expectedTag = H("1ae10b594f09e26a7e902ecbd0600691");
        using (var aead = new ChaCha20Poly1305Managed(aeadKey))
        {
            byte[] ct = new byte[aeadPlain.Length];
            byte[] gotTag = new byte[16];
            aead.Encrypt(aeadNonce, aeadPlain, ct, gotTag, aad);
            Eq("AEAD-ChaCha20-Poly1305 ciphertext (RFC 8439 §2.8.2)", X(ct), X(expectedAead));
            Eq("AEAD-ChaCha20-Poly1305 tag (RFC 8439 §2.8.2)", X(gotTag), X(expectedTag));

            // Round-trip: decrypt produces the original plaintext, and a flipped tag is rejected.
            byte[] pt = new byte[ct.Length];
            aead.Decrypt(aeadNonce, ct, gotTag, pt, aad);
            Check("AEAD-ChaCha20-Poly1305 decrypt roundtrip", Eqb(pt, aeadPlain));

            byte[] badTag = (byte[])gotTag.Clone(); badTag[0] ^= 1;
            bool rejected = false;
            try { aead.Decrypt(aeadNonce, ct, badTag, pt, aad); }
            catch (System.Security.Cryptography.AuthenticationTagMismatchException) { rejected = true; }
            Check("AEAD-ChaCha20-Poly1305 rejects bad tag", rejected);
        }
    }

    // RFC 8879 cert compression — both backends are vendored pure-managed ports
    // (BrotliSharpLib for Brotli, ZstdSharp for Zstd). Verifies round-trip and that the
    // compressed form is actually smaller than the input.
    private static void CertificateCompressionRoundtrip()
    {
        Section("Cert compression (RFC 8879) — managed backends");

        // Use a real DER-ish payload (cert chain sized): a CA + two leaf certs, ~6 KB total.
        var ca = CertificateUtils.GenerateCA("Compression Test CA");
        var cert1 = CertificateUtils.IssueCertificate("a.example.test", ca, CertificateProfile.Server);
        var cert2 = CertificateUtils.IssueCertificate("b.example.test", ca, CertificateProfile.Server);
        byte[] data = new byte[ca.DerData.Length + cert1.DerData.Length + cert2.DerData.Length];
        Buffer.BlockCopy(ca.DerData, 0, data, 0, ca.DerData.Length);
        Buffer.BlockCopy(cert1.DerData, 0, data, ca.DerData.Length, cert1.DerData.Length);
        Buffer.BlockCopy(cert2.DerData, 0, data, ca.DerData.Length + cert1.DerData.Length, cert2.DerData.Length);

        foreach (var (alg, name) in new[] {
            (CertificateCompression.AlgorithmBrotli, "Brotli (BrotliSharpLib)"),
            (CertificateCompression.AlgorithmZstd,   "Zstd (ZstdSharp)") })
        {
            byte[] compressed = CertificateCompression.Compress(data, alg);
            byte[] roundTrip = CertificateCompression.Decompress(compressed, alg, data.Length);
            bool roundOk = roundTrip.AsSpan().SequenceEqual(data);
            Check($"{name} round-trip ({data.Length} → {compressed.Length} bytes)", roundOk);
            Check($"{name} compressed smaller than input", compressed.Length < data.Length);
        }

        // Decompression bomb rejection — a peer-supplied uncompressedLength above the cap
        // must hit the BadCertificate alert before any allocation happens.
        byte[] anyCompressed = CertificateCompression.Compress(data, CertificateCompression.AlgorithmBrotli);
        bool bombRejected = false;
        try
        {
            CertificateCompression.Decompress(anyCompressed, CertificateCompression.AlgorithmBrotli, 16 * 1024 * 1024);
        }
        catch (TlsException e) when (e.Alert == AlertDescription.BadCertificate)
        {
            bombRejected = true;
        }
        Check("Decompression bomb rejected at 16 MB uncompressedLength", bombRejected);
    }
}
