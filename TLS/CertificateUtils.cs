namespace TLS;

using System.Numerics;
using System.Security.Cryptography;

/// <summary>
/// X.509 certificate generation with CA chaining, signature, PFX/PEM export.
/// Supports both ECDSA (P-256) and RSA key types.
/// All ASN.1 DER encoding is done from scratch — no System.Security.Cryptography.X509Certificates.
/// </summary>

public sealed class TlsCertificate
{
    public byte[] DerData { get; init; } = null!;
    public byte[] PrivateKey { get; init; } = null!;     // EC: 32-byte D | RSA: PKCS#1 RSAPrivateKey DER
    public byte[] PublicKey { get; init; } = null!;      // EC: 65-byte uncompressed (0x04 ‖ X ‖ Y) | RSA: PKCS#1 RSAPublicKey DER
    public SignatureScheme SignatureAlgorithm { get; init; }
    /// <summary>Optional DER-encoded CA chain certificates (issuer first).</summary>
    public byte[][]? ChainCertificates { get; init; }

    public bool IsRsa => SignatureAlgorithm is SignatureScheme.RsaPssRsaeSha256 or SignatureScheme.RsaPssRsaeSha384;

    public bool IsGost => CertificateUtils.IsGostScheme(SignatureAlgorithm);

    public bool IsSm2 => SignatureAlgorithm == SignatureScheme.Sm2Sm3;
}

public enum CertificateProfile { CA, Server, Client }

public static class CertificateUtils
{
    // ---- OIDs ----
    private const string OidEcPublicKey = "1.2.840.10045.2.1";
    private const string OidSecp256r1 = "1.2.840.10045.3.1.7";
    private const string OidEcdsaSha256 = "1.2.840.10045.4.3.2";
    private const string OidRsaEncryption = "1.2.840.113549.1.1.1";
    private const string OidRsaSha256 = "1.2.840.113549.1.1.11";
    private const string OidCommonName = "2.5.4.3";
    private const string OidSubjectAltName = "2.5.29.17";
    private const string OidBasicConstraints = "2.5.29.19";
    private const string OidKeyUsage = "2.5.29.15";
    private const string OidExtKeyUsage = "2.5.29.37";
    private const string OidSubjectKeyId = "2.5.29.14";
    private const string OidAuthorityKeyId = "2.5.29.35";
    private const string OidServerAuth = "1.3.6.1.5.5.7.3.1";
    private const string OidClientAuth = "1.3.6.1.5.5.7.3.2";
    private const string OidOcspBasic = "1.3.6.1.5.5.7.48.1.1";

    // ================================================================
    //  ECDSA Certificate generation
    // ================================================================

    /// <summary>Generate a self-signed ECDSA (P-256) certificate.</summary>
    public static TlsCertificate GenerateSelfSigned(string commonName, int validDays = 365)
    {
        var (privKey, pubKey, ecdsa) = GenerateEcKeyPair();
        using var _ = ecdsa;

        var extensions = new List<byte[]>
        {
            BuildExtension(OidBasicConstraints, true, Asn1.Sequence()),
            BuildSanExtension(commonName),
            BuildKeyUsageExtension(CertificateProfile.Server),
            BuildSkiExtension(pubKey)
        };

        byte[] spki = BuildEcSpki(pubKey);
        byte[] sigAlgSeq = EcdsaSigAlg();
        byte[] cert = BuildAndSignCertificateCore(commonName, commonName, spki, extensions, sigAlgSeq,
            tbs => ecdsa.SignDataDer(tbs, HashAlgorithmName.SHA256), validDays);

        return new TlsCertificate
        {
            DerData = cert,
            PrivateKey = privKey,
            PublicKey = pubKey,
            SignatureAlgorithm = SignatureScheme.EcdsaSecp256r1Sha256
        };
    }

    /// <summary>Generate an ECDSA (P-256) Certificate Authority (self-signed, CA:TRUE).</summary>
    public static TlsCertificate GenerateCA(string commonName, int validDays = 3650)
    {
        var (privKey, pubKey, ecdsa) = GenerateEcKeyPair();
        using var _ = ecdsa;

        var extensions = new List<byte[]>
        {
            BuildExtension(OidBasicConstraints, true,
                Asn1.Sequence(Asn1.Wrap(0x01, new byte[] { 0xFF }))), // CA:TRUE
            BuildKeyUsageExtension(CertificateProfile.CA),
            BuildSkiExtension(pubKey)
        };

        byte[] spki = BuildEcSpki(pubKey);
        byte[] sigAlgSeq = EcdsaSigAlg();
        byte[] cert = BuildAndSignCertificateCore(commonName, commonName, spki, extensions, sigAlgSeq,
            tbs => ecdsa.SignDataDer(tbs, HashAlgorithmName.SHA256), validDays);

        return new TlsCertificate
        {
            DerData = cert,
            PrivateKey = privKey,
            PublicKey = pubKey,
            SignatureAlgorithm = SignatureScheme.EcdsaSecp256r1Sha256
        };
    }

    /// <summary>
    /// Issue an ECDSA (P-256) certificate signed by a CA.
    /// The CA can be either ECDSA or RSA — the signing algorithm is auto-detected.
    /// </summary>
    public static TlsCertificate IssueCertificate(string commonName, TlsCertificate ca,
        CertificateProfile profile, int validDays = 365)
    {
        var (privKey, pubKey, _disposable) = GenerateEcKeyPair();
        _disposable.Dispose();

        string caCommonName = ExtractCommonName(ca.DerData);

        var extensions = BuildIssuedExtensions(commonName, ca.PublicKey, profile);
        byte[] spki = BuildEcSpki(pubKey);
        byte[] cert = SignCertWithCa(caCommonName, commonName, spki, extensions, ca, validDays);

        return new TlsCertificate
        {
            DerData = cert,
            PrivateKey = privKey,
            PublicKey = pubKey,
            SignatureAlgorithm = SignatureScheme.EcdsaSecp256r1Sha256,
            ChainCertificates = new[] { ca.DerData }
        };
    }

    // ================================================================
    //  RSA Certificate generation
    // ================================================================

    /// <summary>Generate a self-signed RSA certificate.</summary>
    public static TlsCertificate GenerateSelfSignedRsa(string commonName, int validDays = 365, int keySize = 2048)
    {
        using var rsa = RsaManaged.Create(keySize);
        byte[] privKey = rsa.ExportRSAPrivateKey();
        byte[] pubKey = rsa.ExportRSAPublicKey();

        var extensions = new List<byte[]>
        {
            BuildExtension(OidBasicConstraints, true, Asn1.Sequence()),
            BuildSanExtension(commonName),
            BuildKeyUsageExtension(CertificateProfile.Server),
            BuildSkiExtension(pubKey)
        };

        byte[] spki = BuildRsaSpki(pubKey);
        byte[] sigAlgSeq = RsaSha256SigAlg();
        byte[] cert = BuildAndSignCertificateCore(commonName, commonName, spki, extensions, sigAlgSeq,
            tbs => rsa.SignData(tbs, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), validDays);

        return new TlsCertificate
        {
            DerData = cert,
            PrivateKey = privKey,
            PublicKey = pubKey,
            SignatureAlgorithm = SignatureScheme.RsaPssRsaeSha256
        };
    }

    /// <summary>Generate an RSA Certificate Authority (self-signed, CA:TRUE).</summary>
    public static TlsCertificate GenerateCARsa(string commonName, int validDays = 3650, int keySize = 2048)
    {
        using var rsa = RsaManaged.Create(keySize);
        byte[] privKey = rsa.ExportRSAPrivateKey();
        byte[] pubKey = rsa.ExportRSAPublicKey();

        var extensions = new List<byte[]>
        {
            BuildExtension(OidBasicConstraints, true,
                Asn1.Sequence(Asn1.Wrap(0x01, new byte[] { 0xFF }))), // CA:TRUE
            BuildKeyUsageExtension(CertificateProfile.CA),
            BuildSkiExtension(pubKey)
        };

        byte[] spki = BuildRsaSpki(pubKey);
        byte[] sigAlgSeq = RsaSha256SigAlg();
        byte[] cert = BuildAndSignCertificateCore(commonName, commonName, spki, extensions, sigAlgSeq,
            tbs => rsa.SignData(tbs, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), validDays);

        return new TlsCertificate
        {
            DerData = cert,
            PrivateKey = privKey,
            PublicKey = pubKey,
            SignatureAlgorithm = SignatureScheme.RsaPssRsaeSha256
        };
    }

    /// <summary>
    /// Issue an RSA certificate signed by a CA.
    /// The CA can be either ECDSA or RSA — the signing algorithm is auto-detected.
    /// </summary>
    public static TlsCertificate IssueCertificateRsa(string commonName, TlsCertificate ca,
        CertificateProfile profile, int validDays = 365, int keySize = 2048)
    {
        using var rsa = RsaManaged.Create(keySize);
        byte[] privKey = rsa.ExportRSAPrivateKey();
        byte[] pubKey = rsa.ExportRSAPublicKey();

        string caCommonName = ExtractCommonName(ca.DerData);

        var extensions = BuildIssuedExtensions(commonName, ca.PublicKey, profile);
        byte[] spki = BuildRsaSpki(pubKey);
        byte[] cert = SignCertWithCa(caCommonName, commonName, spki, extensions, ca, validDays);

        return new TlsCertificate
        {
            DerData = cert,
            PrivateKey = privKey,
            PublicKey = pubKey,
            SignatureAlgorithm = SignatureScheme.RsaPssRsaeSha256,
            ChainCertificates = new[] { ca.DerData }
        };
    }

    // ================================================================
    //  Verify chain
    // ================================================================

    /// <summary>Verify that a certificate was signed by the given CA certificate.</summary>
    public static bool VerifyChain(TlsCertificate cert, TlsCertificate ca)
    {
        var (_, certSeqValue, _) = Asn1.ReadTlv(cert.DerData);
        var certItems = Asn1.ReadSequenceItems(certSeqValue);

        byte[] tbsCertDer = Asn1.Wrap(0x30, certItems[0].value);
        byte[] sigBitString = certItems[2].value;
        byte[] signature = sigBitString[1..]; // skip unused-bits byte

        if (ca.IsRsa)
        {
            using var rsa = RsaManaged.Create();
            rsa.ImportRSAPublicKey(ca.PublicKey, out _);
            return rsa.VerifyData(tbsCertDer, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        else
        {
            using var caEcdsa = ImportEcdsaPubKey(ca.PublicKey);
            return caEcdsa.VerifyDataDer(tbsCertDer, signature, HashAlgorithmName.SHA256);
        }
    }

    // ================================================================
    //  Export / Import
    // ================================================================

    /// <summary>Export certificate + private key as PFX (PKCS#12) bytes.</summary>
    public static byte[] ExportPfx(TlsCertificate cert, string password, TlsCertificate? ca = null)
    {
        byte[][]? chain = ca != null ? new[] { ca.DerData } : null;
        return Pkcs12.Export(cert, password, chain);
    }

    /// <summary>Import a PFX file.</summary>
    public static TlsCertificate ImportPfx(byte[] pfxData, string password) =>
        Pkcs12.Import(pfxData, password);

    /// <summary>Export certificate as PEM.</summary>
    public static string ToPem(byte[] der, string label = "CERTIFICATE")
    {
        string b64 = Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks);
        return $"-----BEGIN {label}-----\n{b64}\n-----END {label}-----\n";
    }

    /// <summary>Export private key as PKCS#8 PEM.</summary>
    public static string PrivateKeyToPem(TlsCertificate cert)
    {
        byte[] pkcs8;
        if (cert.IsRsa)
        {
            pkcs8 = Asn1.Sequence(
                Asn1.Integer(0),
                Asn1.Sequence(Asn1.Oid(OidRsaEncryption), Asn1.Null()),
                Asn1.OctetString(cert.PrivateKey)
            );
        }
        else
        {
            byte[] ecPrivKey = Asn1.Sequence(
                Asn1.Integer(1),
                Asn1.OctetString(cert.PrivateKey),
                Asn1.Explicit(1, Asn1.BitString(cert.PublicKey))
            );
            pkcs8 = Asn1.Sequence(
                Asn1.Integer(0),
                Asn1.Sequence(Asn1.Oid(OidEcPublicKey), Asn1.Oid(OidSecp256r1)),
                Asn1.OctetString(ecPrivKey)
            );
        }
        return ToPem(pkcs8, "PRIVATE KEY");
    }

    /// <summary>Export a full PEM bundle: cert chain + private key.</summary>
    public static string ExportPemBundle(TlsCertificate cert, TlsCertificate? ca = null)
    {
        var sb = new System.Text.StringBuilder();
        sb.Append(ToPem(cert.DerData));
        if (ca != null) sb.Append(ToPem(ca.DerData));
        sb.Append(PrivateKeyToPem(cert));
        return sb.ToString();
    }

    // ================================================================
    //  PEM Import
    // ================================================================

    /// <summary>Parse PEM text into labeled DER blocks.</summary>
    public static List<(string label, byte[] data)> ParsePemBlocks(string pem)
    {
        var blocks = new List<(string, byte[])>();
        int pos = 0;
        while (pos < pem.Length)
        {
            int beginIdx = pem.IndexOf("-----BEGIN ", pos, StringComparison.Ordinal);
            if (beginIdx < 0) break;
            int labelStart = beginIdx + "-----BEGIN ".Length;
            int labelEnd = pem.IndexOf("-----", labelStart, StringComparison.Ordinal);
            if (labelEnd < 0) break;
            string label = pem[labelStart..labelEnd];
            int dataStart = labelEnd + 5;

            string endMarker = $"-----END {label}-----";
            int endIdx = pem.IndexOf(endMarker, dataStart, StringComparison.Ordinal);
            if (endIdx < 0) break;

            string base64 = pem[dataStart..endIdx]
                .Replace("\r", "").Replace("\n", "").Replace(" ", "").Replace("\t", "");
            blocks.Add((label, Convert.FromBase64String(base64)));
            pos = endIdx + endMarker.Length;
        }
        return blocks;
    }

    /// <summary>Import all certificates from PEM text. Returns DER-encoded certificates.</summary>
    public static byte[][] ImportPemCertificates(string pem)
    {
        var blocks = ParsePemBlocks(pem);
        var certs = new List<byte[]>();
        foreach (var (label, data) in blocks)
        {
            if (label == "CERTIFICATE")
                certs.Add(data);
            else if (label is "PKCS7" or "CMS")
                certs.AddRange(Pkcs7.Import(data));
        }
        return certs.ToArray();
    }

    /// <summary>
    /// Import a TlsCertificate from PEM text containing certificate(s) and a private key.
    /// Accepts any combination of CERTIFICATE, PRIVATE KEY, RSA PRIVATE KEY, EC PRIVATE KEY blocks.
    /// Chain certificates (second CERTIFICATE onward) are stored in ChainCertificates.
    /// </summary>
    public static TlsCertificate ImportPem(string pem)
    {
        var blocks = ParsePemBlocks(pem);

        var certs = new List<byte[]>();
        byte[]? privateKey = null;
        byte[]? publicKey = null;
        SignatureScheme sigAlg = default;

        foreach (var (label, data) in blocks)
        {
            switch (label)
            {
                case "CERTIFICATE":
                    certs.Add(data);
                    break;
                case "PKCS7":
                case "CMS":
                    certs.AddRange(Pkcs7.Import(data));
                    break;
                case "PRIVATE KEY":
                    if (privateKey == null)
                        (privateKey, publicKey, sigAlg) = ImportPkcs8Key(data);
                    break;
                case "RSA PRIVATE KEY":
                    if (privateKey == null)
                        (privateKey, publicKey, sigAlg) = ImportRsaPrivateKey(data);
                    break;
                case "EC PRIVATE KEY":
                    if (privateKey == null)
                        (privateKey, publicKey, sigAlg) = ImportEcPrivateKey(data);
                    break;
            }
        }

        if (certs.Count == 0 || privateKey == null || publicKey == null)
            throw new TlsException(AlertDescription.InternalError,
                "PEM must contain at least one CERTIFICATE and one private key block");

        return new TlsCertificate
        {
            DerData = certs[0],
            PrivateKey = privateKey,
            PublicKey = publicKey,
            SignatureAlgorithm = sigAlg,
            ChainCertificates = certs.Count > 1 ? certs.Skip(1).ToArray() : null
        };
    }

    /// <summary>Import a private key from PEM text. Auto-detects PKCS#8, PKCS#1 RSA, or EC format.</summary>
    public static (byte[] privateKey, byte[] publicKey, SignatureScheme sigAlg) ImportPrivateKeyPem(string pem)
    {
        var blocks = ParsePemBlocks(pem);
        foreach (var (label, data) in blocks)
        {
            switch (label)
            {
                case "PRIVATE KEY": return ImportPkcs8Key(data);
                case "RSA PRIVATE KEY": return ImportRsaPrivateKey(data);
                case "EC PRIVATE KEY": return ImportEcPrivateKey(data);
            }
        }
        throw new TlsException(AlertDescription.InternalError,
            "PEM does not contain a recognized private key block");
    }

    // ================================================================
    //  Standalone Key Import (DER)
    // ================================================================

    /// <summary>Import a PKCS#8 (PrivateKeyInfo) private key from full DER bytes.</summary>
    public static (byte[] privateKey, byte[] publicKey, SignatureScheme sigAlg) ImportPkcs8Key(byte[] der)
    {
        var (_, seqContent, _) = Asn1.ReadTlv(der);
        return Pkcs12.ParsePkcs8Key(seqContent);
    }

    /// <summary>Import a PKCS#1 RSA private key (RSAPrivateKey) from DER bytes.</summary>
    public static (byte[] privateKey, byte[] publicKey, SignatureScheme sigAlg) ImportRsaPrivateKey(byte[] der)
    {
        using var rsa = RsaManaged.Create();
        rsa.ImportRSAPrivateKey(der, out _);
        byte[] pubKey = rsa.ExportRSAPublicKey();
        return (der, pubKey, SignatureScheme.RsaPssRsaeSha256);
    }

    /// <summary>Import an EC private key (RFC 5915 ECPrivateKey) from DER bytes.</summary>
    public static (byte[] privateKey, byte[] publicKey, SignatureScheme sigAlg) ImportEcPrivateKey(byte[] der)
    {
        var (_, seqContent, _) = Asn1.ReadTlv(der);
        var items = Asn1.ReadSequenceItems(seqContent);

        byte[] privKey = items[1].value; // OCTET STRING = raw D scalar
        byte[]? pubKey = null;

        // Look for [1] publicKey BIT STRING
        for (int i = 2; i < items.Count; i++)
        {
            if (items[i].tag == 0xA1)
            {
                var (_, bitStringTlv, _) = Asn1.ReadTlv(items[i].value);
                pubKey = bitStringTlv[1..]; // skip unused-bits byte
                break;
            }
        }

        // If public key not embedded, derive from private key on P-256.
        if (pubKey == null)
            pubKey = EcdsaManaged.DerivePublicFromPrivate("P-256", privKey);

        return (privKey, pubKey, SignatureScheme.EcdsaSecp256r1Sha256);
    }

    /// <summary>
    /// Import a private key from DER bytes, auto-detecting the format.
    /// Supports PKCS#8, PKCS#1 RSA, and RFC 5915 EC.
    /// </summary>
    public static (byte[] privateKey, byte[] publicKey, SignatureScheme sigAlg) ImportPrivateKeyDer(byte[] der)
    {
        var (_, seqContent, _) = Asn1.ReadTlv(der);
        var items = Asn1.ReadSequenceItems(seqContent);

        if (items.Count < 2)
            throw new TlsException(AlertDescription.DecodeError, "Invalid private key DER");

        // PKCS#8: version(0) + AlgorithmIdentifier(SEQUENCE) + OCTET STRING
        if (items[0].tag == Asn1.TagInteger && items[1].tag == Asn1.TagSequence)
            return ImportPkcs8Key(der);

        // EC RFC 5915: version(1) + privateKey(OCTET STRING)
        if (items[0].tag == Asn1.TagInteger && items[0].value.Length == 1 && items[0].value[0] == 1
            && items[1].tag == Asn1.TagOctetString)
            return ImportEcPrivateKey(der);

        // PKCS#1 RSA: version(0) + modulus(INTEGER) + publicExponent(INTEGER) + ...
        if (items[0].tag == Asn1.TagInteger && items[1].tag == Asn1.TagInteger)
            return ImportRsaPrivateKey(der);

        throw new TlsException(AlertDescription.DecodeError, "Unrecognized private key format");
    }

    // ================================================================
    //  Signature utilities (for CertificateVerify)
    // ================================================================

    public static byte[] Sign(byte[] data, byte[] privateKey, byte[] publicKey, SignatureScheme scheme)
    {
        switch (scheme)
        {
            case SignatureScheme.EcdsaSecp256r1Sha256:
                using (var ecdsa = ImportEcdsaKey(privateKey, publicKey))
                    return ecdsa.SignDataDer(data, HashAlgorithmName.SHA256);

            case SignatureScheme.Ed25519:
                return Ed25519.Sign(data, privateKey);

            case SignatureScheme.RsaPssRsaeSha256:
                using (var rsa = RsaManaged.Create())
                {
                    rsa.ImportRSAPrivateKey(privateKey, out _);
                    return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
                }

            case SignatureScheme.RsaPssRsaeSha384:
                using (var rsa = RsaManaged.Create())
                {
                    rsa.ImportRSAPrivateKey(privateKey, out _);
                    return rsa.SignData(data, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
                }

            // RFC 9963 §3: Legacy RSASSA-PKCS1-v1_5 (certificate verification only)
            case SignatureScheme.RsaPkcs1Sha256:
                using (var rsa = RsaManaged.Create())
                {
                    rsa.ImportRSAPrivateKey(privateKey, out _);
                    return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }

            case SignatureScheme.RsaPkcs1Sha384:
                using (var rsa = RsaManaged.Create())
                {
                    rsa.ImportRSAPrivateKey(privateKey, out _);
                    return rsa.SignData(data, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
                }

            case SignatureScheme.RsaPkcs1Sha512:
                using (var rsa = RsaManaged.Create())
                {
                    rsa.ImportRSAPrivateKey(privateKey, out _);
                    return rsa.SignData(data, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                }

            default:
                if (IsGostScheme(scheme))
                {
                    var (_, _, is512) = GostParams(scheme);
                    byte[] h = is512 ? GostCrypto.Streebog.Hash512(data) : GostCrypto.Streebog.Hash256(data);
                    using (var g = ImportGostKey(privateKey, publicKey, scheme))
                        return g.SignHash(h);
                }
                if (scheme == SignatureScheme.Sm2Sm3)
                {
                    var (r, s) = ChineseCrypto.SM2.Sign(ChineseCrypto.SM2.Sm2P256, privateKey, data, Sm2TlsId);
                    return Asn1.Sequence(
                        Asn1.Integer(new BigInteger(r, isUnsigned: true, isBigEndian: true)),
                        Asn1.Integer(new BigInteger(s, isUnsigned: true, isBigEndian: true)));
                }
                throw new TlsException(AlertDescription.HandshakeFailure, $"Unsupported sign scheme: {scheme}");
        }
    }

    public static bool Verify(byte[] data, byte[] signature, byte[] publicKey, SignatureScheme scheme)
    {
        try
        {
            switch (scheme)
            {
                case SignatureScheme.EcdsaSecp256r1Sha256:
                    using (var ecdsa = ImportEcdsaPubKey(publicKey))
                        return ecdsa.VerifyDataDer(data, signature, HashAlgorithmName.SHA256);

                case SignatureScheme.Ed25519:
                    return Ed25519.Verify(data, signature, publicKey);

                case SignatureScheme.RsaPssRsaeSha256:
                    using (var rsa = RsaManaged.Create())
                    {
                        rsa.ImportRSAPublicKey(publicKey, out _);
                        return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
                    }

                case SignatureScheme.RsaPssRsaeSha384:
                    using (var rsa = RsaManaged.Create())
                    {
                        rsa.ImportRSAPublicKey(publicKey, out _);
                        return rsa.VerifyData(data, signature, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
                    }

                // RFC 9963 §3: Legacy RSASSA-PKCS1-v1_5 (certificate verification only)
                case SignatureScheme.RsaPkcs1Sha256:
                    using (var rsa = RsaManaged.Create())
                    {
                        rsa.ImportRSAPublicKey(publicKey, out _);
                        return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    }

                case SignatureScheme.RsaPkcs1Sha384:
                    using (var rsa = RsaManaged.Create())
                    {
                        rsa.ImportRSAPublicKey(publicKey, out _);
                        return rsa.VerifyData(data, signature, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
                    }

                case SignatureScheme.RsaPkcs1Sha512:
                    using (var rsa = RsaManaged.Create())
                    {
                        rsa.ImportRSAPublicKey(publicKey, out _);
                        return rsa.VerifyData(data, signature, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                    }

                default:
                    if (IsGostScheme(scheme))
                    {
                        var (_, _, is512) = GostParams(scheme);
                        byte[] h = is512 ? GostCrypto.Streebog.Hash512(data) : GostCrypto.Streebog.Hash256(data);
                        // NB: see GostEcdh for why we don't route through BC's GOST curves —
                        // they fall back to generic FpCurve and end up worse than OpenGost.
                        using (var g = ImportGostKey(null, publicKey, scheme))
                            return g.VerifyHash(h, signature);
                    }
                    if (scheme == SignatureScheme.Sm2Sm3)
                    {
                        var seq = Asn1.ReadSequenceItems(Asn1.ReadTlv(signature).value);
                        byte[] r = ToFixed(seq[0].value, 32);
                        byte[] s = ToFixed(seq[1].value, 32);
                        return ChineseCrypto.SM2.Verify(ChineseCrypto.SM2.Sm2P256, publicKey, data, r, s, Sm2TlsId);
                    }
                    throw new TlsException(AlertDescription.HandshakeFailure, $"Unsupported verify scheme: {scheme}");
            }
        }
        catch (CryptographicException)
        {
            return false; // key/scheme mismatch or corrupt signature
        }
    }

    // ================================================================
    //  GOST R 34.10-2012 signatures + certificates (RFC 9367 / RFC 4491)
    // ================================================================

    private const string OidGost256 = "1.2.643.7.1.1.1.1";   // id-tc26-gost3410-12-256
    private const string OidGost512 = "1.2.643.7.1.1.1.2";   // id-tc26-gost3410-12-512
    private const string OidStreebog256 = "1.2.643.7.1.1.2.2";
    private const string OidStreebog512 = "1.2.643.7.1.1.2.3";

    internal static bool IsGostScheme(SignatureScheme s) =>
        s is SignatureScheme.Gostr34102012_256a or SignatureScheme.Gostr34102012_256b
          or SignatureScheme.Gostr34102012_256c or SignatureScheme.Gostr34102012_256d
          or SignatureScheme.Gostr34102012_512a or SignatureScheme.Gostr34102012_512b
          or SignatureScheme.Gostr34102012_512c;

    // scheme → (curve OID, coordinate size in bytes, is-512)
    private static (string curveOid, int size, bool is512) GostParams(SignatureScheme s) => s switch
    {
        SignatureScheme.Gostr34102012_256a => ("1.2.643.7.1.2.1.1.1", 32, false),
        SignatureScheme.Gostr34102012_256b => ("1.2.643.2.2.35.1", 32, false),
        SignatureScheme.Gostr34102012_256c => ("1.2.643.2.2.35.2", 32, false),
        SignatureScheme.Gostr34102012_256d => ("1.2.643.2.2.35.3", 32, false),
        SignatureScheme.Gostr34102012_512a => ("1.2.643.7.1.2.1.2.1", 64, true),
        SignatureScheme.Gostr34102012_512b => ("1.2.643.7.1.2.1.2.2", 64, true),
        SignatureScheme.Gostr34102012_512c => ("1.2.643.7.1.2.1.2.3", 64, true),
        _ => throw new TlsException(AlertDescription.HandshakeFailure, $"Not a GOST scheme: {s}")
    };

    private static SignatureScheme MatchGostCurveOid(byte[] curveOidTlv)
    {
        foreach (var oid in new[] {
            "1.2.643.7.1.2.1.1.1", "1.2.643.2.2.35.1", "1.2.643.2.2.35.2", "1.2.643.2.2.35.3",
            "1.2.643.7.1.2.1.2.1", "1.2.643.7.1.2.1.2.2", "1.2.643.7.1.2.1.2.3" })
            if (curveOidTlv.AsSpan().SequenceEqual(Asn1.Oid(oid)))
                return CurveOidToScheme(oid);
        throw new TlsException(AlertDescription.HandshakeFailure, "Unknown GOST curve in certificate");
    }

    private static SignatureScheme CurveOidToScheme(string curveOid) => curveOid switch
    {
        "1.2.643.7.1.2.1.1.1" => SignatureScheme.Gostr34102012_256a,
        "1.2.643.2.2.35.1" => SignatureScheme.Gostr34102012_256b,
        "1.2.643.2.2.35.2" => SignatureScheme.Gostr34102012_256c,
        "1.2.643.2.2.35.3" => SignatureScheme.Gostr34102012_256d,
        "1.2.643.7.1.2.1.2.1" => SignatureScheme.Gostr34102012_512a,
        "1.2.643.7.1.2.1.2.2" => SignatureScheme.Gostr34102012_512b,
        "1.2.643.7.1.2.1.2.3" => SignatureScheme.Gostr34102012_512c,
        _ => throw new TlsException(AlertDescription.HandshakeFailure, $"Unknown GOST curve OID: {curveOid}")
    };

    // PublicKey layout: Q.X(LE) ‖ Q.Y(LE); PrivateKey: D(LE) — both as exported by GostECDsaManaged.
    // We pass the explicit curve from OpenGost's own dictionary instead of ECCurve.CreateFromValue
    // so the BCL Oid type (and its CryptFindOIDInfo dependency) never gets linked.
    private static OpenGost.Security.Cryptography.GostECDsaManaged ImportGostKey(
        byte[]? privateKey, byte[] publicKey, SignatureScheme scheme)
    {
        var (curveOid, size, _) = GostParams(scheme);
        var p = new ECParameters
        {
            Curve = OpenGost.Security.Cryptography.ECCurveOidMap.GetExplicitCurveByOid(curveOid),
            Q = new ECPoint { X = publicKey[..size], Y = publicKey[size..(2 * size)] },
            D = privateKey,
        };
        return new OpenGost.Security.Cryptography.GostECDsaManaged(p);
    }

    /// <summary>Generate a GOST keypair + X.509 certificate signed by an (ECDSA/RSA) CA.</summary>
    public static TlsCertificate IssueGostCertificate(string commonName, TlsCertificate ca,
        CertificateProfile profile, SignatureScheme scheme = SignatureScheme.Gostr34102012_256a, int validDays = 365)
    {
        var (curveOid, size, _) = GostParams(scheme);
        using var g = new OpenGost.Security.Cryptography.GostECDsaManaged();
        g.GenerateKey(OpenGost.Security.Cryptography.ECCurveOidMap.GetExplicitCurveByOid(curveOid));
        var p = g.ExportParameters(true);
        byte[] pub = new byte[2 * size];
        Buffer.BlockCopy(p.Q.X!, 0, pub, 0, size);
        Buffer.BlockCopy(p.Q.Y!, 0, pub, size, size);
        byte[] priv = p.D!;

        string caCommonName = ExtractCommonName(ca.DerData);
        var extensions = BuildIssuedExtensions(commonName, ca.PublicKey, profile);
        byte[] spki = BuildGostSpki(pub, scheme);
        byte[] cert = SignCertWithCa(caCommonName, commonName, spki, extensions, ca, validDays);

        return new TlsCertificate
        {
            DerData = cert,
            PrivateKey = priv,
            PublicKey = pub,
            SignatureAlgorithm = scheme,
            ChainCertificates = new[] { ca.DerData }
        };
    }

    // RFC 4491 GOST SubjectPublicKeyInfo: BIT STRING wraps a DER OCTET STRING of X(LE)‖Y(LE).
    private static byte[] BuildGostSpki(byte[] pub, SignatureScheme scheme)
    {
        var (curveOid, _, is512) = GostParams(scheme);
        return Asn1.Sequence(
            Asn1.Sequence(
                Asn1.Oid(is512 ? OidGost512 : OidGost256),
                Asn1.Sequence(
                    Asn1.Oid(curveOid),
                    Asn1.Oid(is512 ? OidStreebog512 : OidStreebog256))),
            Asn1.BitString(Asn1.OctetString(pub)));
    }

    // ================================================================
    //  SM2 signatures + certificates (GB/T 32918 / RFC 8998)
    // ================================================================

    // RFC 8998 §3.1: SM2 identifier for TLS 1.3 handshake (CertificateVerify) signatures.
    private const string Sm2TlsId = "TLSv1.3+GM+Cipher+Suite";
    private const string OidSm2Curve = "1.2.156.10197.1.301"; // sm2p256v1 / curveSM2

    private static byte[] ToFixed(byte[] derInt, int size)
    {
        // strip a DER leading sign-zero / extra zeros, then left-pad to size
        int start = 0;
        while (start < derInt.Length - 1 && derInt[start] == 0) start++;
        int len = derInt.Length - start;
        byte[] r = new byte[size];
        Buffer.BlockCopy(derInt, start, r, size - len, Math.Min(len, size));
        return r;
    }

    /// <summary>Generate an SM2 keypair + X.509 certificate signed by an (ECDSA/RSA) CA.</summary>
    public static TlsCertificate IssueSm2Certificate(string commonName, TlsCertificate ca,
        CertificateProfile profile, int validDays = 365)
    {
        var (priv, pub) = ChineseCrypto.SM2.GenerateKeyPair();   // priv: d(32 BE), pub: X‖Y (64 BE)
        string caCommonName = ExtractCommonName(ca.DerData);
        var extensions = BuildIssuedExtensions(commonName, ca.PublicKey, profile);
        byte[] spki = BuildSm2Spki(pub);
        byte[] cert = SignCertWithCa(caCommonName, commonName, spki, extensions, ca, validDays);

        return new TlsCertificate
        {
            DerData = cert,
            PrivateKey = priv,
            PublicKey = pub,
            SignatureAlgorithm = SignatureScheme.Sm2Sm3,
            ChainCertificates = new[] { ca.DerData }
        };
    }

    // SM2 SubjectPublicKeyInfo: id-ecPublicKey + sm2 curve OID, BIT STRING(0x04‖X‖Y) uncompressed point.
    private static byte[] BuildSm2Spki(byte[] pubXY)
    {
        byte[] uncompressed = new byte[1 + pubXY.Length];
        uncompressed[0] = 0x04;
        Buffer.BlockCopy(pubXY, 0, uncompressed, 1, pubXY.Length);
        return Asn1.Sequence(
            Asn1.Sequence(Asn1.Oid(OidEcPublicKey), Asn1.Oid(OidSm2Curve)),
            Asn1.BitString(uncompressed));
    }

    public static (byte[] publicKey, SignatureScheme sigAlg) ParseCertificatePublicKey(byte[] certDer)
    {
        var (_, certSeqValue, _) = Asn1.ReadTlv(certDer);
        var certItems = Asn1.ReadSequenceItems(certSeqValue);
        var tbsItems = Asn1.ReadSequenceItems(certItems[0].value);
        int spkiIdx = (tbsItems[0].tag == 0xA0) ? 6 : 5;
        var spkiItems = Asn1.ReadSequenceItems(tbsItems[spkiIdx].value);

        // Detect algorithm from SPKI
        var algItems = Asn1.ReadSequenceItems(spkiItems[0].value);
        byte[] algOidTlv = Asn1.Wrap(algItems[0].tag, algItems[0].value);
        byte[] ecOidTlv = Asn1.Oid(OidEcPublicKey);
        byte[] rsaOidTlv = Asn1.Oid(OidRsaEncryption);

        if (algOidTlv.AsSpan().SequenceEqual(ecOidTlv))
        {
            byte[] pubKey = spkiItems[1].value[1..]; // skip unused-bits byte → 0x04‖X‖Y
            // SM2 uses id-ecPublicKey with the sm2 curve OID; distinguish from secp256r1.
            if (algItems.Count > 1 && Asn1.Wrap(algItems[1].tag, algItems[1].value)
                    .AsSpan().SequenceEqual(Asn1.Oid(OidSm2Curve)))
                return (pubKey[1..], SignatureScheme.Sm2Sm3); // strip 0x04 → X‖Y
            return (pubKey, SignatureScheme.EcdsaSecp256r1Sha256);
        }

        if (algOidTlv.AsSpan().SequenceEqual(rsaOidTlv))
        {
            byte[] rsaPubKeyDer = spkiItems[1].value[1..]; // skip unused-bits → DER RSAPublicKey
            return (rsaPubKeyDer, SignatureScheme.RsaPssRsaeSha256);
        }

        if (algOidTlv.AsSpan().SequenceEqual(Asn1.Oid(OidGost256)) ||
            algOidTlv.AsSpan().SequenceEqual(Asn1.Oid(OidGost512)))
        {
            // parameters SEQUENCE: first OID is the curve (param set)
            var gostParamItems = Asn1.ReadSequenceItems(algItems[1].value);
            byte[] curveOidTlv = Asn1.Wrap(gostParamItems[0].tag, gostParamItems[0].value);
            SignatureScheme scheme = MatchGostCurveOid(curveOidTlv);
            // subjectPublicKey BIT STRING → strip unused-bits byte → DER OCTET STRING → X(LE)‖Y(LE)
            byte[] octetTlv = spkiItems[1].value[1..];
            var (_, keyOctets, _) = Asn1.ReadTlv(octetTlv);
            return (keyOctets, scheme);
        }

        throw new TlsException(AlertDescription.HandshakeFailure, "Unsupported certificate key algorithm");
    }

    // ================================================================
    //  Certificate inspection (for optional validation)
    // ================================================================

    /// <summary>Parse the validity period from a DER-encoded certificate.</summary>
    public static (DateTime notBefore, DateTime notAfter) ParseCertificateValidity(byte[] certDer)
    {
        var (_, certSeqValue, _) = Asn1.ReadTlv(certDer);
        var certItems = Asn1.ReadSequenceItems(certSeqValue);
        var tbsItems = Asn1.ReadSequenceItems(certItems[0].value);

        // Validity is at TBS index 4 (with explicit version [0] tag) or 3 (without)
        int validityIdx = (tbsItems[0].tag == 0xA0) ? 4 : 3;
        var validityItems = Asn1.ReadSequenceItems(tbsItems[validityIdx].value);

        DateTime notBefore = ParseAsn1Time(validityItems[0].tag, validityItems[0].value);
        DateTime notAfter = ParseAsn1Time(validityItems[1].tag, validityItems[1].value);
        return (notBefore, notAfter);
    }

    /// <summary>Parse Subject Alternative Name dNSName entries from a DER certificate.</summary>
    public static List<string> ParseCertificateSAN(byte[] certDer)
    {
        var sans = new List<string>();
        try
        {
            var (_, certSeqValue, _) = Asn1.ReadTlv(certDer);
            var certItems = Asn1.ReadSequenceItems(certSeqValue);
            var tbsItems = Asn1.ReadSequenceItems(certItems[0].value);

            // Find extensions ([3] EXPLICIT = tag 0xA3)
            int extIdx = -1;
            for (int i = 0; i < tbsItems.Count; i++)
                if (tbsItems[i].tag == 0xA3) { extIdx = i; break; }
            if (extIdx < 0) return sans;

            // Strip the outer Extensions SEQUENCE wrapper before iterating individual extensions
            var (_, extSeqContent, _) = Asn1.ReadTlv(tbsItems[extIdx].value);
            var extensions = Asn1.ReadSequenceItems(extSeqContent);
            byte[] sanOidTlv = Asn1.Oid(OidSubjectAltName);

            foreach (var (_, extSeqValue) in extensions)
            {
                var extItems = Asn1.ReadSequenceItems(extSeqValue);
                if (extItems.Count < 2) continue;

                byte[] oidTlv = Asn1.Wrap(extItems[0].tag, extItems[0].value);
                if (!oidTlv.AsSpan().SequenceEqual(sanOidTlv)) continue;

                // Last item is the OCTET STRING value containing GeneralNames SEQUENCE
                byte[] sanDer = extItems[^1].value;
                var (_, sanSeqValue, _) = Asn1.ReadTlv(sanDer);
                var sanEntries = Asn1.ReadSequenceItems(sanSeqValue);

                foreach (var (tag, value) in sanEntries)
                {
                    if (tag == 0x82) // dNSName [2] IMPLICIT IA5String
                        sans.Add(System.Text.Encoding.ASCII.GetString(value));
                }
                break;
            }
        }
        catch { /* cert may be from external source with unexpected structure */ }
        return sans;
    }

    private static DateTime ParseAsn1Time(byte tag, byte[] value)
    {
        string s = System.Text.Encoding.ASCII.GetString(value);
        if (tag == Asn1.TagUtcTime)
        {
            int yy = int.Parse(s[0..2]);
            int year = yy >= 50 ? 1900 + yy : 2000 + yy;
            return new DateTime(year, int.Parse(s[2..4]), int.Parse(s[4..6]),
                int.Parse(s[6..8]), int.Parse(s[8..10]), int.Parse(s[10..12]), DateTimeKind.Utc);
        }
        // GeneralizedTime: YYYYMMDDHHMMSSZ
        return new DateTime(int.Parse(s[0..4]), int.Parse(s[4..6]), int.Parse(s[6..8]),
            int.Parse(s[8..10]), int.Parse(s[10..12]), int.Parse(s[12..14]), DateTimeKind.Utc);
    }

    // ================================================================
    //  Internal — certificate building core
    // ================================================================

    private static byte[] BuildAndSignCertificateCore(
        string issuerCn, string subjectCn, byte[] spki,
        List<byte[]> extensions, byte[] sigAlgSeq,
        Func<byte[], byte[]> signTbs, int validDays)
    {
        var now = DateTime.UtcNow;
        byte[] serial = RandomnessWrapper.GetBytes(16);
        serial[0] &= 0x7F;

        byte[] tbsCert = Asn1.Sequence(
            Asn1.Explicit(0, Asn1.Integer(2)),           // v3
            Asn1.IntegerRaw(serial),
            sigAlgSeq,
            BuildName(issuerCn),
            Asn1.Sequence(                                // validity
                Asn1.UtcTime(now.AddMinutes(-5)),
                Asn1.UtcTime(now.AddDays(validDays))
            ),
            BuildName(subjectCn),
            spki,
            Asn1.Explicit(3, Asn1.Sequence(extensions.ToArray())) // extensions
        );

        byte[] sig = signTbs(tbsCert);
        return Asn1.Sequence(tbsCert, sigAlgSeq, Asn1.BitString(sig));
    }

    /// <summary>Sign a cert using the CA's key — auto-detects ECDSA vs RSA from the CA's SignatureAlgorithm.</summary>
    private static byte[] SignCertWithCa(string issuerCn, string subjectCn,
        byte[] spki, List<byte[]> extensions, TlsCertificate ca, int validDays)
    {
        if (ca.IsRsa)
        {
            using var rsa = RsaManaged.Create();
            rsa.ImportRSAPrivateKey(ca.PrivateKey, out _);
            byte[] sigAlgSeq = RsaSha256SigAlg();
            return BuildAndSignCertificateCore(issuerCn, subjectCn, spki, extensions, sigAlgSeq,
                tbs => rsa.SignData(tbs, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), validDays);
        }
        else
        {
            using var ecdsa = ImportEcdsaKey(ca.PrivateKey, ca.PublicKey);
            byte[] sigAlgSeq = EcdsaSigAlg();
            return BuildAndSignCertificateCore(issuerCn, subjectCn, spki, extensions, sigAlgSeq,
                tbs => ecdsa.SignDataDer(tbs, HashAlgorithmName.SHA256), validDays);
        }
    }

    // ================================================================
    //  Internal — SPKI builders
    // ================================================================

    private static byte[] BuildEcSpki(byte[] pubKey) =>
        Asn1.Sequence(
            Asn1.Sequence(Asn1.Oid(OidEcPublicKey), Asn1.Oid(OidSecp256r1)),
            Asn1.BitString(pubKey));

    internal static byte[] BuildRsaSpki(byte[] rsaPubKeyDer) =>
        Asn1.Sequence(
            Asn1.Sequence(Asn1.Oid(OidRsaEncryption), Asn1.Null()),
            Asn1.BitString(rsaPubKeyDer));

    // ================================================================
    //  Internal — signature algorithm identifiers
    // ================================================================

    private static byte[] EcdsaSigAlg() => Asn1.Sequence(Asn1.Oid(OidEcdsaSha256));
    private static byte[] RsaSha256SigAlg() => Asn1.Sequence(Asn1.Oid(OidRsaSha256), Asn1.Null());

    // ================================================================
    //  Internal — extensions
    // ================================================================

    private static byte[] BuildExtension(string oid, bool critical, byte[] value)
    {
        var items = new List<byte[]> { Asn1.Oid(oid) };
        if (critical) items.Add(Asn1.Wrap(0x01, new byte[] { 0xFF }));
        items.Add(Asn1.OctetString(value));
        return Asn1.Sequence(items.ToArray());
    }

    private static byte[] BuildKeyUsageExtension(CertificateProfile profile)
    {
        byte flags;
        byte unusedBits;
        switch (profile)
        {
            case CertificateProfile.CA:
                flags = 0x86; // digitalSignature + keyCertSign + cRLSign
                unusedBits = 1;
                break;
            case CertificateProfile.Server:
                flags = 0xA0; // digitalSignature + keyEncipherment
                unusedBits = 5;
                break;
            default: // Client
                flags = 0x80; // digitalSignature
                unusedBits = 7;
                break;
        }

        byte[] bitString = Asn1.Wrap(0x03, new byte[] { unusedBits, flags });
        return BuildExtension(OidKeyUsage, true, bitString);
    }

    private static byte[] BuildEkuExtension(CertificateProfile profile)
    {
        string oid = profile switch
        {
            CertificateProfile.Server => OidServerAuth,
            CertificateProfile.Client => OidClientAuth,
            _ => throw new ArgumentException("CA does not have EKU")
        };
        byte[] value = Asn1.Sequence(Asn1.Oid(oid));
        return BuildExtension(OidExtKeyUsage, false, value);
    }

    private static byte[] BuildSanExtension(string dnsName)
    {
        byte[] nameBytes = System.Text.Encoding.ASCII.GetBytes(dnsName);
        byte[] value = Asn1.Sequence(Asn1.Wrap(0x82, nameBytes)); // dNSName [2]
        return BuildExtension(OidSubjectAltName, false, value);
    }

    private static byte[] BuildSkiExtension(byte[] publicKey)
    {
        byte[] keyHash = Sha1OneShot(publicKey);
        return BuildExtension(OidSubjectKeyId, false, Asn1.OctetString(keyHash));
    }

    private static byte[] BuildAkiExtension(byte[] issuerPublicKey)
    {
        byte[] keyHash = Sha1OneShot(issuerPublicKey);
        byte[] value = Asn1.Sequence(Asn1.Wrap(0x80, keyHash));
        return BuildExtension(OidAuthorityKeyId, false, value);
    }

    // X.509 SubjectKeyIdentifier / AuthorityKeyIdentifier extensions need SHA-1 of the
    // public key (RFC 5280 §4.2.1.2). Routed through BC's Sha1Digest so that
    // System.Security.Cryptography.SHA1 (and the whole BCL hash registry it pulls in
    // via BCryptCreateHash / BCryptHashData / etc.) doesn't get linked into the assembly.
    private static byte[] Sha1OneShot(byte[] data)
    {
        var d = new Org.BouncyCastle.Crypto.Digests.Sha1Digest();
        d.BlockUpdate(data, 0, data.Length);
        var hash = new byte[d.GetDigestSize()];
        d.DoFinal(hash, 0);
        return hash;
    }

    private static List<byte[]> BuildIssuedExtensions(string commonName, byte[] caPublicKey, CertificateProfile profile)
    {
        var extensions = new List<byte[]>
        {
            BuildExtension(OidBasicConstraints, true, Asn1.Sequence()), // CA:FALSE
            BuildKeyUsageExtension(profile),
            BuildEkuExtension(profile),
            BuildAkiExtension(caPublicKey)
        };

        if (profile == CertificateProfile.Server)
            extensions.Add(BuildSanExtension(commonName));

        return extensions;
    }

    // ================================================================
    //  Internal — key helpers
    // ================================================================

    private static byte[] BuildName(string cn) =>
        Asn1.Sequence(Asn1.Set(Asn1.Sequence(Asn1.Oid(OidCommonName), Asn1.Utf8String(cn))));

    private static (byte[] privKey, byte[] pubKey, EcdsaManaged ecdsa) GenerateEcKeyPair()
    {
        var ecdsa = EcdsaManaged.Create("P-256");
        byte[] privKey = ecdsa.ExportPrivateScalar();
        byte[] pubKey = ecdsa.ExportPublicKeyUncompressed();
        return (privKey, pubKey, ecdsa);
    }

    private static EcdsaManaged ImportEcdsaKey(byte[] d, byte[] uncompressedPub)
    {
        ValidateUncompressedP256Point(uncompressedPub);
        var ecdsa = EcdsaManaged.Create();
        ecdsa.ImportFromComponents("P-256", d, uncompressedPub);
        return ecdsa;
    }

    private static EcdsaManaged ImportEcdsaPubKey(byte[] uncompressedPub)
    {
        ValidateUncompressedP256Point(uncompressedPub);
        var ecdsa = EcdsaManaged.Create();
        ecdsa.ImportFromComponents("P-256", null, uncompressedPub);
        return ecdsa;
    }

    private static void ValidateUncompressedP256Point(byte[] uncompressedPub)
    {
        // SEC1 §2.3.3: uncompressed P-256 point is 0x04 || X(32) || Y(32) = 65 bytes.
        if (uncompressedPub.Length != 65 || uncompressedPub[0] != 0x04)
            throw new TlsException(AlertDescription.BadCertificate,
                $"Invalid uncompressed P-256 public key (length={uncompressedPub.Length}, " +
                $"prefix=0x{(uncompressedPub.Length > 0 ? uncompressedPub[0] : 0):X2})");
    }

    /// <summary>Extract the CN from a DER certificate.</summary>
    internal static string ExtractCommonName(byte[] certDer)
    {
        var (_, certSeqValue, _) = Asn1.ReadTlv(certDer);
        var certItems = Asn1.ReadSequenceItems(certSeqValue);
        var tbsItems = Asn1.ReadSequenceItems(certItems[0].value);
        int subjectIdx = (tbsItems[0].tag == 0xA0) ? 5 : 4;
        var rdnSeq = Asn1.ReadSequenceItems(tbsItems[subjectIdx].value);
        foreach (var (_, rdnSetValue) in rdnSeq)
        {
            var rdnItems = Asn1.ReadSequenceItems(rdnSetValue);
            foreach (var (_, attrSeqValue) in rdnItems)
            {
                var attrItems = Asn1.ReadSequenceItems(attrSeqValue);
                if (attrItems.Count >= 2)
                {
                    byte[] expectedOid = Asn1.Oid(OidCommonName);
                    byte[] actualOid = Asn1.Wrap(attrItems[0].tag, attrItems[0].value);
                    if (actualOid.AsSpan().SequenceEqual(expectedOid.AsSpan()))
                        return System.Text.Encoding.UTF8.GetString(attrItems[1].value);
                }
            }
        }
        return "Unknown";
    }

    // ================================================================
    //  OCSP Response Verification (RFC 6960)
    // ================================================================

    /// <summary>
    /// Verify an OCSP response against the leaf certificate and issuer CA.
    /// Returns the revocation status of the certificate.
    /// </summary>
    public static OcspStatus VerifyOcspResponse(byte[] ocspResponseDer, byte[] certDer, TlsCertificate caCert)
    {
        try
        {
            // OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED, responseBytes [0] EXPLICIT SEQUENCE }
            var (_, ocspRespValue, _) = Asn1.ReadTlv(ocspResponseDer);
            var ocspItems = Asn1.ReadSequenceItems(ocspRespValue);
            if (ocspItems.Count < 2) return OcspStatus.InvalidResponse;

            // responseStatus must be 0 (successful)
            if (ocspItems[0].value.Length != 1 || ocspItems[0].value[0] != 0)
                return OcspStatus.InvalidResponse;

            // responseBytes: [0] EXPLICIT → SEQUENCE { responseType OID, response OCTET STRING }
            var (_, respBytesSeq, _) = Asn1.ReadTlv(ocspItems[1].value);
            var respBytesItems = Asn1.ReadSequenceItems(respBytesSeq);
            if (respBytesItems.Count < 2) return OcspStatus.InvalidResponse;

            // Verify responseType is id-pkix-ocsp-basic
            byte[] respTypeOid = Asn1.Wrap(respBytesItems[0].tag, respBytesItems[0].value);
            if (!respTypeOid.AsSpan().SequenceEqual(Asn1.Oid(OidOcspBasic)))
                return OcspStatus.InvalidResponse;

            // response is OCTET STRING containing BasicOCSPResponse DER
            byte[] basicRespDer = respBytesItems[1].value;

            // BasicOCSPResponse ::= SEQUENCE { tbsResponseData, signatureAlgorithm, signature, [0] certs OPTIONAL }
            var (_, basicValue, _) = Asn1.ReadTlv(basicRespDer);
            var basicItems = Asn1.ReadSequenceItems(basicValue);
            if (basicItems.Count < 3) return OcspStatus.InvalidResponse;

            byte[] tbsResponseDataDer = Asn1.Wrap(basicItems[0].tag, basicItems[0].value);
            byte[] sigAlgValue = basicItems[1].value;
            byte[] signatureBits = basicItems[2].value;
            if (signatureBits.Length < 2) return OcspStatus.InvalidResponse;
            byte[] signatureBytes = signatureBits[1..]; // skip unused-bits byte

            // Determine signature algorithm from OID
            var sigAlgItems = Asn1.ReadSequenceItems(sigAlgValue);
            byte[] sigOidTlv = Asn1.Wrap(sigAlgItems[0].tag, sigAlgItems[0].value);
            byte[] ecdsaSha256Oid = Asn1.Oid(OidEcdsaSha256);
            byte[] rsaSha256Oid = Asn1.Oid(OidRsaSha256);

            // Verify signature using CA public key
            bool sigValid;
            if (sigOidTlv.AsSpan().SequenceEqual(ecdsaSha256Oid))
            {
                using var ecdsa = ImportEcdsaPubKey(caCert.PublicKey);
                sigValid = ecdsa.VerifyDataDer(tbsResponseDataDer, signatureBytes, HashAlgorithmName.SHA256);
            }
            else if (sigOidTlv.AsSpan().SequenceEqual(rsaSha256Oid))
            {
                using var rsa = RsaManaged.Create();
                rsa.ImportRSAPublicKey(caCert.PublicKey, out _);
                sigValid = rsa.VerifyData(tbsResponseDataDer, signatureBytes,
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            else
            {
                return OcspStatus.InvalidResponse; // unsupported sig algorithm
            }

            if (!sigValid) return OcspStatus.InvalidResponse;

            // Parse tbsResponseData → responses (SEQUENCE OF SingleResponse)
            var tbsItems = Asn1.ReadSequenceItems(basicItems[0].value);
            // tbsResponseData: [0] version OPTIONAL, responderID, producedAt, responses, [1] extensions OPTIONAL
            // version [0] is optional — skip if present
            int idx = 0;
            if (tbsItems.Count > 0 && tbsItems[0].tag == 0xA0) idx++; // skip version
            idx++; // skip responderID
            idx++; // skip producedAt

            if (idx >= tbsItems.Count) return OcspStatus.InvalidResponse;
            var responses = Asn1.ReadSequenceItems(tbsItems[idx].value);
            if (responses.Count == 0) return OcspStatus.InvalidResponse;

            // Extract leaf cert serial number for matching
            byte[] targetSerial = ParseCertificateSerialNumber(certDer);

            // Search for matching SingleResponse
            foreach (var (_, singleRespValue) in responses)
            {
                var srItems = Asn1.ReadSequenceItems(singleRespValue);
                if (srItems.Count < 3) continue;

                // certID: SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }
                var certIdItems = Asn1.ReadSequenceItems(srItems[0].value);
                if (certIdItems.Count < 4) continue;
                byte[] respSerial = certIdItems[3].value;

                // Match serial number
                if (!respSerial.AsSpan().SequenceEqual(targetSerial.AsSpan())) continue;

                // certStatus: [0]=good, [1]=revoked, [2]=unknown
                byte statusTag = srItems[1].tag;
                if (statusTag == 0x80 || statusTag == 0xA0) // IMPLICIT/EXPLICIT [0] = good
                {
                    // Check freshness: thisUpdate (index 2) and nextUpdate (index 3, optional [0])
                    if (srItems.Count > 3 && srItems[3].tag == 0xA0)
                    {
                        var (_, nextUpdateValue, _) = Asn1.ReadTlv(srItems[3].value);
                        string nextUpdateStr = System.Text.Encoding.ASCII.GetString(nextUpdateValue);
                        if (TryParseGeneralizedTime(nextUpdateStr, out var nextUpdate))
                        {
                            if (DateTime.UtcNow > nextUpdate)
                                return OcspStatus.InvalidResponse; // stale response
                        }
                    }
                    return OcspStatus.Good;
                }
                if (statusTag == 0x81 || statusTag == 0xA1) return OcspStatus.Revoked;
                if (statusTag == 0x82 || statusTag == 0xA2) return OcspStatus.Unknown;
            }

            return OcspStatus.Unknown; // no matching SingleResponse found
        }
        catch
        {
            return OcspStatus.InvalidResponse;
        }
    }

    /// <summary>Extract the serial number bytes from a DER certificate.</summary>
    private static byte[] ParseCertificateSerialNumber(byte[] certDer)
    {
        var (_, certSeqValue, _) = Asn1.ReadTlv(certDer);
        var certItems = Asn1.ReadSequenceItems(certSeqValue);
        var tbsItems = Asn1.ReadSequenceItems(certItems[0].value);
        // serialNumber is after [0] version (if present)
        int serialIdx = (tbsItems[0].tag == 0xA0) ? 1 : 0;
        return tbsItems[serialIdx].value; // INTEGER value bytes
    }

    private static bool TryParseGeneralizedTime(string s, out DateTime result)
    {
        result = default;
        // GeneralizedTime: YYYYMMDDHHmmssZ or UTCTime: YYMMDDHHmmssZ
        if (s.Length == 15 && s[14] == 'Z')
            return DateTime.TryParseExact(s, "yyyyMMddHHmmss'Z'", null,
                System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out result);
        if (s.Length == 13 && s[12] == 'Z')
            return DateTime.TryParseExact(s, "yyMMddHHmmss'Z'", null,
                System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out result);
        return false;
    }
}
