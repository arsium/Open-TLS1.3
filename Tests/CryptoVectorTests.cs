namespace Tests;

using System.Runtime.Intrinsics;
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
        MlKem768DeterministicKat();
        HpkeRoundTrip();
        HpkeKnownAnswer();
        AegisKat();
        MlDsaRoundTrip();
        TlsTreeKat();
        Release21Regressions();
    }

    // RFC 9367 §4.1.2 TLSTREE known-answer test, from RFC 9367 Appendix A (Kuznyechik_MGM_S, whose
    // C_3 = 0x..fff8 puts seqnums 0-7 in one leaf and 8 in the next). Validates the KDF framing,
    // STR_8 endianness, and the per-leaf re-keying that the GOST loopback (same impl both ends)
    // cannot prove on its own.
    private static void TlsTreeKat()
    {
        Section("TLSTREE (RFC 9367 §4.1.2 / Appendix A)");
        byte[] k = H("475E4C514CC6318C3A5F000F1265BD1AB5F0DE1AF357ED0079EC5FF0AFBD030C");
        const ulong c1 = 0xffffffffe0000000UL, c2 = 0xffffffffffff0000UL, c3 = 0xfffffffffffffff8UL;
        Eq("TLSTREE(K,0) Kuznyechik_S", X(GostKdf.TlsTree(k, 0, c1, c2, c3)),
            "c8fc93d7c586f2b0a3101baa6a979e4e3886706551e81187e97880409c7e8ee9");
        Eq("TLSTREE(K,8) crosses C_3 leaf", X(GostKdf.TlsTree(k, 8, c1, c2, c3)),
            "d3cd87d5687407823978344c06b928a85898b739a31d3de5ff2b788ef39196ed");
        Check("TLSTREE 0..7 share a leaf", Eqb(GostKdf.TlsTree(k, 0, c1, c2, c3), GostKdf.TlsTree(k, 7, c1, c2, c3)));
        Check("TLSTREE re-keys at 8", !Eqb(GostKdf.TlsTree(k, 0, c1, c2, c3), GostKdf.TlsTree(k, 8, c1, c2, c3)));
    }

    // Regression coverage for the 2.1.0 security fixes (chain validation, national-ECDH point
    // validation, DER depth bound). The happy paths are already exercised by the loopback suite;
    // these lock in the negative cases the fixes introduced.
    private static void Release21Regressions()
    {
        Section("2.1.0 regression fixes");

        // C-01: chain walk + RFC 5280 §6.1.4 issuer checks.
        var root = CertificateUtils.GenerateCA("Test Root", 365);
        var other = CertificateUtils.GenerateCA("Other Root", 365);
        var leafA = CertificateUtils.IssueCertificate("a.example.com", root, CertificateProfile.Server, 365);
        var leafB = CertificateUtils.IssueCertificate("b.example.com", root, CertificateProfile.Server, 365);
        Check("C-01 leaf signed by anchor verifies", CertificateUtils.VerifyChain(leafA, root));
        Check("C-01 wrong anchor rejected", !CertificateUtils.VerifyChain(leafA, other));
        // A CA:FALSE leaf presented as an intermediate must be rejected (§6.1.4(k) cA=TRUE).
        Check("C-01 non-CA intermediate rejected",
            !CertificateUtils.VerifyChain(leafA, new[] { leafB.DerData }, root));

        // NAT-06: SM2 ECDH rejects an off-curve peer point.
        var (privA, _) = ChineseCrypto.SM2.EcdhGenerateKeyPair();
        var (_, pubB) = ChineseCrypto.SM2.EcdhGenerateKeyPair();
        Check("NAT-06 valid SM2 point accepted", ChineseCrypto.SM2.EcdhSharedSecret(privA, pubB).Length == 32);
        byte[] offCurve = (byte[])pubB.Clone();
        offCurve[40] ^= 0x01; // perturb a Y byte → no longer on curveSM2
        bool sm2Rejected = false;
        try { ChineseCrypto.SM2.EcdhSharedSecret(privA, offCurve); }
        catch (TlsException) { sm2Rejected = true; }
        Check("NAT-06 off-curve SM2 point rejected", sm2Rejected);

        // C-05: ASN.1 depth bound rejects pathologically nested DER, accepts normal certs.
        byte[] nested = new byte[] { 0x05, 0x00 }; // NULL
        for (int i = 0; i < 100; i++) nested = Asn1.Wrap(0x30, nested);
        bool depthRejected = false;
        try { Asn1.CheckDepth(nested); } catch (TlsException) { depthRejected = true; }
        Check("C-05 over-deep DER rejected", depthRejected);
        bool shallowOk = true;
        try { Asn1.CheckDepth(root.DerData); } catch { shallowOk = false; }
        Check("C-05 normal certificate accepted", shallowOk);
    }

    // ML-DSA (FIPS 204) via the BouncyCastle-backed wrapper: fixed key/signature sizes per parameter
    // set, sign/verify round-trip, and rejection of tampered signature + tampered message. The BC
    // engine itself is ACVP-tested; this validates our wrapper + encoding round-trips.
    private static void MlDsaRoundTrip()
    {
        Section("ML-DSA (FIPS 204 / draft-ietf-tls-mldsa)");
        var sets = new[]
        {
            (SignatureScheme.MlDsa44, "ML-DSA-44", 1312, 2420),
            (SignatureScheme.MlDsa65, "ML-DSA-65", 1952, 3309),
            (SignatureScheme.MlDsa87, "ML-DSA-87", 2592, 4627),
        };
        byte[] msg = Encoding.ASCII.GetBytes("TLS 1.3, server CertificateVerify\0...ML-DSA handshake test");
        foreach (var (scheme, name, pkLen, sigLen) in sets)
        {
            var (priv, pub) = MlDsaManaged.GenerateKeyPair(scheme);
            Check($"{name} public-key size = {pkLen}", pub.Length == pkLen);
            byte[] sig = MlDsaManaged.Sign(msg, priv, scheme);
            Check($"{name} signature size = {sigLen}", sig.Length == sigLen);
            Check($"{name} verify", MlDsaManaged.Verify(msg, sig, pub, scheme));

            byte[] badSig = (byte[])sig.Clone(); badSig[sig.Length / 2] ^= 0xFF;
            Check($"{name} reject tampered signature", !MlDsaManaged.Verify(msg, badSig, pub, scheme));
            byte[] badMsg = (byte[])msg.Clone(); badMsg[0] ^= 0xFF;
            Check($"{name} reject tampered message", !MlDsaManaged.Verify(badMsg, sig, pub, scheme));
        }
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

    // AEGIS-128L / AEGIS-256 (draft-irtf-cfrg-aegis-aead-18 Appendix A), plus the A.1 AESRound vector.
    // Each AEAD vector runs twice — once on the AES-NI/ARM hardware round, once forced through the
    // software FIPS-197 round — so the portable fallback is KAT-validated even on AES-NI hardware.
    private static void AegisKat()
    {
        Section("AEGIS (draft-irtf-cfrg-aegis-aead-18)");

        byte[] inB = H("000102030405060708090a0b0c0d0e0f");
        byte[] rkB = H("101112131415161718191a1b1c1d1e1f");
        var outV = AegisAead.AesRound(Vector128.LoadUnsafe(ref inB[0]), Vector128.LoadUnsafe(ref rkB[0]));
        byte[] ob = new byte[16]; outV.StoreUnsafe(ref ob[0]);
        Eq("AESRound (A.1)", X(ob), "7a7b4e5638782546a8c0477a3b813f43");

        for (int pass = 0; pass < 2; pass++)
        {
            AegisAead.ForceSoftwareAes = pass == 1;
            string sfx = pass == 1 ? " [soft]" : " [hw]";

            AegisVec(sfx, "128L TV1", false, "10010000000000000000000000000000", "10000200000000000000000000000000",
                "", "00000000000000000000000000000000", "c1c0e58bd913006feba00f4b3cc3594e", "abe0ece80c24868a226a35d16bdae37a");
            AegisVec(sfx, "128L TV2 empty", false, "10010000000000000000000000000000", "10000200000000000000000000000000",
                "", "", "", "c2b879a67def9d74e6c14f708bbcc9b4");
            AegisVec(sfx, "128L TV3", false, "10010000000000000000000000000000", "10000200000000000000000000000000",
                "0001020304050607", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84", "cc6f3372f6aa1bb82388d695c3962d9a");
            AegisVec(sfx, "128L TV4 partial", false, "10010000000000000000000000000000", "10000200000000000000000000000000",
                "0001020304050607", "000102030405060708090a0b0c0d", "79d94593d8c2119d7e8fd9b8fc77", "5c04b3dba849b2701effbe32c7f0fab7");
            AegisVec(sfx, "128L TV5", false, "10010000000000000000000000000000", "10000200000000000000000000000000",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829",
                "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
                "b31052ad1cca4e291abcf2df3502e6bdb1bfd6db36798be3607b1f94d34478aa7ede7f7a990fec10", "7542a745733014f9474417b337399507");

            const string k256 = "1001000000000000000000000000000000000000000000000000000000000000";
            const string n256 = "1000020000000000000000000000000000000000000000000000000000000000";
            AegisVec(sfx, "256 TV1", true, k256, n256, "", "00000000000000000000000000000000",
                "754fc3d8c973246dcc6d741412a4b236", "3fe91994768b332ed7f570a19ec5896e");
            AegisVec(sfx, "256 TV3", true, k256, n256, "0001020304050607",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711", "8d86f91ee606e9ff26a01b64ccbdd91d");
            AegisVec(sfx, "256 TV4 partial", true, k256, n256, "0001020304050607",
                "000102030405060708090a0b0c0d", "f373079ed84b2709faee37358458", "c60b9c2d33ceb058f96e6dd03c215652");
        }
        AegisAead.ForceSoftwareAes = false;
    }

    private static void AegisVec(string sfx, string label, bool is256, string keyH, string nonceH,
        string adH, string msgH, string ctH, string tagH)
    {
        byte[] key = H(keyH), nonce = H(nonceH), ad = H(adH), msg = H(msgH);
        string name = $"AEGIS-{(is256 ? "256" : "128L")} {label}";
        using var a = new AegisAead(key, is256);

        byte[] outp = new byte[msg.Length + 16];
        a.EncryptInto(nonce, msg, outp, ad);
        Eq($"{name} ct{sfx}", X(outp[..msg.Length]), ctH);
        Eq($"{name} tag{sfx}", X(outp[msg.Length..]), tagH);

        byte[] dec = new byte[msg.Length];
        Check($"{name} decrypt{sfx}", a.TryDecryptInto(nonce, outp, dec, ad) && Eqb(dec, msg));

        byte[] bad = (byte[])outp.Clone(); bad[^1] ^= 0xFF;
        Check($"{name} reject-tamper{sfx}", !a.TryDecryptInto(nonce, bad, new byte[msg.Length], ad));
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
            // New API: single output span (ct||tag). Slice to compare against the
            // RFC vectors which give ciphertext and tag separately.
            byte[] ctTag = new byte[aeadPlain.Length + 16];
            aead.Encrypt(aeadNonce, aeadPlain, ctTag, aad);
            byte[] ct = ctTag[..aeadPlain.Length];
            byte[] gotTag = ctTag[aeadPlain.Length..];
            Eq("AEAD-ChaCha20-Poly1305 ciphertext (RFC 8439 §2.8.2)", X(ct), X(expectedAead));
            Eq("AEAD-ChaCha20-Poly1305 tag (RFC 8439 §2.8.2)", X(gotTag), X(expectedTag));

            // Round-trip: decrypt produces the original plaintext, and a flipped tag is rejected.
            byte[] pt = new byte[ct.Length];
            aead.Decrypt(aeadNonce, ctTag, pt, aad);
            Check("AEAD-ChaCha20-Poly1305 decrypt roundtrip", Eqb(pt, aeadPlain));

            // Flip a tag byte in a fresh copy and confirm decrypt rejects.
            byte[] badCtTag = (byte[])ctTag.Clone();
            badCtTag[aeadPlain.Length] ^= 1;
            bool rejected = false;
            try { aead.Decrypt(aeadNonce, badCtTag, pt, aad); }
            catch (System.Security.Cryptography.AuthenticationTagMismatchException) { rejected = true; }
            Check("AEAD-ChaCha20-Poly1305 rejects bad tag", rejected);
        }
    }

    // RFC 8879 cert compression — both backends are vendored pure-managed ports
    // (BrotliSharpLib for Brotli, ZstdSharp for Zstd). Verifies round-trip and that the
    // compressed form is actually smaller than the input.
    // ML-KEM-768 (FIPS 203) deterministic known-answer test. Drives the seeded internal entry
    // points (KeyGenInternal(d,z) / EncapsInternal(ek,m)) so outputs are fully reproducible, then
    // locks a golden digest over (ek‖dk‖ct‖ss) as a byte-exact regression vector. (Cross-checking
    // the golden against NIST ACVP vectors is a follow-up; this catches any drift in our impl.)
    private static void MlKem768DeterministicKat()
    {
        Section("ML-KEM-768 (FIPS 203) — deterministic seeded KAT");

        byte[] d = new byte[32], z = new byte[32], m = new byte[32];
        for (int i = 0; i < 32; i++) { d[i] = (byte)i; z[i] = (byte)(0x40 + i); m[i] = (byte)(0x80 + i); }

        var (ek, dk) = MlKem768.KeyGenInternal(d, z);
        var (ss, ct) = MlKem768.EncapsInternal(ek, m);
        byte[] ssDecaps = MlKem768.Decaps(dk, ct);

        Check("ML-KEM-768 KAT sizes (ek=1184, dk=2400, ct=1088, ss=32)",
            ek.Length == 1184 && dk.Length == 2400 && ct.Length == 1088 && ss.Length == 32);
        Check("ML-KEM-768 KAT round-trip (Encaps/Decaps agree)", Eqb(ss, ssDecaps));

        // Determinism: identical seeds MUST give identical outputs (no hidden RNG dependence).
        var (ek2, dk2) = MlKem768.KeyGenInternal(d, z);
        var (ss2, ct2) = MlKem768.EncapsInternal(ek, m);
        Check("ML-KEM-768 KeyGen deterministic", Eqb(ek, ek2) && Eqb(dk, dk2));
        Check("ML-KEM-768 Encaps deterministic", Eqb(ss, ss2) && Eqb(ct, ct2));

        byte[] all = new byte[ek.Length + dk.Length + ct.Length + ss.Length];
        int o = 0;
        Buffer.BlockCopy(ek, 0, all, o, ek.Length); o += ek.Length;
        Buffer.BlockCopy(dk, 0, all, o, dk.Length); o += dk.Length;
        Buffer.BlockCopy(ct, 0, all, o, ct.Length); o += ct.Length;
        Buffer.BlockCopy(ss, 0, all, o, ss.Length);
        string golden = Convert.ToHexString(Sha2Managed.Sha256(all));
        Check("ML-KEM-768 KAT golden digest (byte-exact regression lock)",
            golden == "0CCCBDA39DE04D3410ED736D93BE1B13B9EFB42E4E2A49243E85B1185DDD5B51");

        // ML-KEM-1024 (k=4, du=11, dv=5) — same seeded harness.
        var (ek4, dk4) = MlKem1024.KeyGenInternal(d, z);
        var (ss4, ct4) = MlKem1024.EncapsInternal(ek4, m);
        byte[] ss4Decaps = MlKem1024.Decaps(dk4, ct4);
        Check("ML-KEM-1024 KAT sizes (ek=1568, dk=3168, ct=1568, ss=32)",
            ek4.Length == 1568 && dk4.Length == 3168 && ct4.Length == 1568 && ss4.Length == 32);
        Check("ML-KEM-1024 KAT round-trip (Encaps/Decaps agree)", Eqb(ss4, ss4Decaps));
        var (ek4b, _) = MlKem1024.KeyGenInternal(d, z);
        Check("ML-KEM-1024 KeyGen deterministic", Eqb(ek4, ek4b));
        ct4[0] ^= 0xFF;
        Check("ML-KEM-1024 implicit rejection on corrupted ciphertext", !Eqb(MlKem1024.Decaps(dk4, ct4), ss4));

        byte[] all4 = new byte[ek4.Length + dk4.Length + ct4.Length + ss4.Length];
        int o4 = 0;
        Buffer.BlockCopy(ek4, 0, all4, o4, ek4.Length); o4 += ek4.Length;
        Buffer.BlockCopy(dk4, 0, all4, o4, dk4.Length); o4 += dk4.Length;
        // NB: ct4 was tampered above; recompute a clean ciphertext for the golden lock.
        var (ssG, ctG) = MlKem1024.EncapsInternal(ek4, m);
        Buffer.BlockCopy(ctG, 0, all4, o4, ctG.Length); o4 += ctG.Length;
        Buffer.BlockCopy(ssG, 0, all4, o4, ssG.Length);
        string golden4 = Convert.ToHexString(Sha2Managed.Sha256(all4));
        Check("ML-KEM-1024 KAT golden digest (byte-exact regression lock)",
            golden4 == "2F5F9120816D2CCCEC5D803E3DEC97BB5F440F38E7984C0544FD3C9FD0E8840C");
    }

    // HPKE (RFC 9180) seal/open round-trip for both AEADs ECH needs — the foundation of ECH.
    private static void HpkeRoundTrip()
    {
        Section("HPKE (RFC 9180) — DHKEM(X25519,HKDF-SHA256), AES-128-GCM + ChaCha20Poly1305");
        foreach (var (aead, name) in new[] {
            (Hpke.AEAD_AES_128_GCM, "AES-128-GCM"),
            (Hpke.AEAD_CHACHA20_POLY1305, "ChaCha20Poly1305") })
        {
            byte[] skR = X25519.GeneratePrivateKey();
            byte[] pkR = X25519.PublicFromPrivate(skR);
            byte[] info = Encoding.ASCII.GetBytes("hpke-info");
            byte[] aad = Encoding.ASCII.GetBytes("associated-data");
            byte[] pt = Encoding.ASCII.GetBytes("the quick brown fox sealed over HPKE");

            var (enc, sctx) = Hpke.KeySchedule.SetupBaseSender(pkR, info, aead);
            byte[] ct = sctx.Seal(aad, pt);
            byte[]? dec = Hpke.KeySchedule.SetupBaseReceiver(enc, skR, info, aead).Open(aad, ct);
            Check($"HPKE {name} seal/open round-trip", dec != null && Eqb(dec, pt));

            byte[]? bad = Hpke.KeySchedule.SetupBaseReceiver(enc, skR, info, aead).Open(Encoding.ASCII.GetBytes("wrong-aad"), ct);
            Check($"HPKE {name} rejects tampered AAD", bad == null);
        }
    }

    // RFC 9180 Appendix A.1 known-answer vectors — DHKEM(X25519,HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM,
    // base mode. A self seal/open round-trip can't detect a non-conformant labeled KDF (both ends share the
    // bug); these vectors come from the RFC reference implementation, so reproducing them proves byte-level
    // interoperability with any compliant HPKE peer (real-browser ECH, ODoH, etc.).
    private static void HpkeKnownAnswer()
    {
        Section("HPKE (RFC 9180) — Appendix A.1 known-answer vectors (interop conformance)");
        static byte[] H(string s) => Convert.FromHexString(s);

        byte[] info = H("4f6465206f6e2061204772656369616e2055726e");
        byte[] skRm = H("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
        byte[] enc  = H("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");

        // DHKEM Decap → shared_secret (validates the KEM suite_id + ExtractAndExpand).
        byte[] ss = Hpke.DhKem.Decap(enc, skRm);
        Check("A.1 DHKEM shared_secret matches RFC vector",
            Eqb(ss, H("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc")));

        // Base key schedule → Open the RFC's seq-0 ciphertext (validates key + base_nonce + AEAD path).
        var ctx = Hpke.KeySchedule.SetupBaseReceiver(enc, skRm, info, Hpke.AEAD_AES_128_GCM);
        byte[]? pt0 = ctx.Open(H("436f756e742d30"),
            H("f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"));
        Check("A.1 base-mode seq-0 Open recovers RFC plaintext",
            pt0 != null && Eqb(pt0, H("4265617574792069732074727574682c20747275746820626561757479")));

        // Secret export (validates exporter_secret + LabeledExpand "sec"); this exercises the same
        // LabeledExpand path that key/base_nonce use, so matching these locks the whole key schedule.
        var ctxE = Hpke.KeySchedule.SetupBaseReceiver(enc, skRm, info, Hpke.AEAD_AES_128_GCM);
        Check("A.1 export(empty, 32) matches RFC vector",
            Eqb(ctxE.Export(Array.Empty<byte>(), 32), H("3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee")));
        Check("A.1 export(0x00, 32) matches RFC vector",
            Eqb(ctxE.Export(H("00"), 32), H("2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5")));
        Check("A.1 export(\"TestContext\", 32) matches RFC vector",
            Eqb(ctxE.Export(H("54657374436f6e74657874"), 32), H("e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931")));

        // Sender side with the RFC's fixed ephemeral (skEm) so enc + the ciphertext are reproducible:
        // pin enc, key, base_nonce, exporter_secret directly, and re-derive the seq-0 ciphertext by
        // *sealing* (the most literal "first ciphertext matches the published vector").
        byte[] skEm = H("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736");
        byte[] pkRm = H("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
        var (encS, sctx) = Hpke.KeySchedule.SetupBaseSenderDeterministic(pkRm, info, Hpke.AEAD_AES_128_GCM, skEm);
        Check("A.1 enc (ephemeral public key) matches RFC vector", Eqb(encS, enc));
        Check("A.1 key matches RFC vector",
            Eqb(sctx.KeyForTest, H("4531685d41d65f03dc48f6b8302c05b0")));
        Check("A.1 base_nonce matches RFC vector",
            Eqb(sctx.BaseNonceForTest, H("56d890e5accaaf011cff4b7d")));
        Check("A.1 exporter_secret matches RFC vector",
            Eqb(sctx.ExporterSecretForTest, H("45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8")));
        byte[] ctS = sctx.Seal(H("436f756e742d30"),
            H("4265617574792069732074727574682c20747275746820626561757479"));
        Check("A.1 seq-0 Seal reproduces RFC ciphertext",
            Eqb(ctS, H("f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a")));
    }

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
            (CertificateCompression.AlgorithmZlib,   "zlib (BouncyCastle JZlib)"),
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
