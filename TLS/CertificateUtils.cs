namespace TLS;

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
            tbs => ecdsa.SignData(tbs, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence), validDays);

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
            tbs => ecdsa.SignData(tbs, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence), validDays);

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
        using var rsa = RSA.Create(keySize);
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
        using var rsa = RSA.Create(keySize);
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
        using var rsa = RSA.Create(keySize);
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
            using var rsa = RSA.Create();
            rsa.ImportRSAPublicKey(ca.PublicKey, out _);
            return rsa.VerifyData(tbsCertDer, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        else
        {
            using var caEcdsa = ImportEcdsaPubKey(ca.PublicKey);
            return caEcdsa.VerifyData(tbsCertDer, signature, HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
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
        using var rsa = RSA.Create();
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

        // If public key not embedded, derive from private key
        if (pubKey == null)
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportECPrivateKey(der, out _);
            var p = ecdsa.ExportParameters(false);
            pubKey = new byte[1 + p.Q.X!.Length + p.Q.Y!.Length];
            pubKey[0] = 0x04;
            Buffer.BlockCopy(p.Q.X!, 0, pubKey, 1, p.Q.X!.Length);
            Buffer.BlockCopy(p.Q.Y!, 0, pubKey, 1 + p.Q.X!.Length, p.Q.Y!.Length);
        }

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
                    return ecdsa.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

            case SignatureScheme.Ed25519:
                return Ed25519.Sign(data, privateKey);

            case SignatureScheme.RsaPssRsaeSha256:
                using (var rsa = RSA.Create())
                {
                    rsa.ImportRSAPrivateKey(privateKey, out _);
                    return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
                }

            case SignatureScheme.RsaPssRsaeSha384:
                using (var rsa = RSA.Create())
                {
                    rsa.ImportRSAPrivateKey(privateKey, out _);
                    return rsa.SignData(data, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
                }

            default:
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
                        return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256,
                            DSASignatureFormat.Rfc3279DerSequence);

                case SignatureScheme.Ed25519:
                    return Ed25519.Verify(data, signature, publicKey);

                case SignatureScheme.RsaPssRsaeSha256:
                    using (var rsa = RSA.Create())
                    {
                        rsa.ImportRSAPublicKey(publicKey, out _);
                        return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
                    }

                case SignatureScheme.RsaPssRsaeSha384:
                    using (var rsa = RSA.Create())
                    {
                        rsa.ImportRSAPublicKey(publicKey, out _);
                        return rsa.VerifyData(data, signature, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
                    }

                default:
                    throw new TlsException(AlertDescription.HandshakeFailure, $"Unsupported verify scheme: {scheme}");
            }
        }
        catch (CryptographicException)
        {
            return false; // key/scheme mismatch or corrupt signature
        }
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
            byte[] pubKey = spkiItems[1].value[1..]; // skip unused-bits byte
            return (pubKey, SignatureScheme.EcdsaSecp256r1Sha256);
        }

        if (algOidTlv.AsSpan().SequenceEqual(rsaOidTlv))
        {
            byte[] rsaPubKeyDer = spkiItems[1].value[1..]; // skip unused-bits → DER RSAPublicKey
            return (rsaPubKeyDer, SignatureScheme.RsaPssRsaeSha256);
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
        byte[] serial = RandomNumberGenerator.GetBytes(16);
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
            using var rsa = RSA.Create();
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
                tbs => ecdsa.SignData(tbs, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence), validDays);
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
        byte[] keyHash = SHA1.HashData(publicKey);
        return BuildExtension(OidSubjectKeyId, false, Asn1.OctetString(keyHash));
    }

    private static byte[] BuildAkiExtension(byte[] issuerPublicKey)
    {
        byte[] keyHash = SHA1.HashData(issuerPublicKey);
        byte[] value = Asn1.Sequence(Asn1.Wrap(0x80, keyHash));
        return BuildExtension(OidAuthorityKeyId, false, value);
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

    private static (byte[] privKey, byte[] pubKey, ECDsa ecdsa) GenerateEcKeyPair()
    {
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var p = ecdsa.ExportParameters(true);
        byte[] privKey = p.D!;
        byte[] pubKey = new byte[1 + p.Q.X!.Length + p.Q.Y!.Length];
        pubKey[0] = 0x04;
        Buffer.BlockCopy(p.Q.X!, 0, pubKey, 1, p.Q.X!.Length);
        Buffer.BlockCopy(p.Q.Y!, 0, pubKey, 1 + p.Q.X!.Length, p.Q.Y!.Length);
        return (privKey, pubKey, ecdsa);
    }

    private static ECDsa ImportEcdsaKey(byte[] d, byte[] uncompressedPub) =>
        ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = d,
            Q = new ECPoint { X = uncompressedPub[1..33], Y = uncompressedPub[33..65] }
        });

    private static ECDsa ImportEcdsaPubKey(byte[] uncompressedPub) =>
        ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = uncompressedPub[1..33], Y = uncompressedPub[33..65] }
        });

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
}
