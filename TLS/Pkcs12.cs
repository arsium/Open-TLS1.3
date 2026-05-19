namespace TLS;

using System.Security.Cryptography;
using System.Text;

/// <summary>
/// Minimal PKCS#12 (PFX) builder and parser.
/// Produces unencrypted bags with HMAC-SHA1 MAC for integrity.
/// </summary>
public static class Pkcs12
{
    // OIDs
    private const string OidData = "1.2.840.113549.1.7.1";
    private const string OidCertBag = "1.2.840.113549.1.12.10.1.3";
    private const string OidKeyBag = "1.2.840.113549.1.12.10.1.1";
    private const string OidX509Cert = "1.2.840.113549.1.9.22.1";
    private const string OidLocalKeyId = "1.2.840.113549.1.9.21";
    private const string OidFriendlyName = "1.2.840.113549.1.9.20";
    private const string OidEcPublicKey = "1.2.840.10045.2.1";
    private const string OidSecp256r1 = "1.2.840.10045.3.1.7";
    private const string OidRsaEncryption = "1.2.840.113549.1.1.1";
    private const string OidSha1 = "1.3.14.3.2.26";

    /// <summary>
    /// Export a certificate + private key (+ optional CA chain) to PKCS#12 / PFX format.
    /// Uses unencrypted bags with HMAC-SHA1 MAC.
    /// </summary>
    public static byte[] Export(TlsCertificate cert, string password, byte[][]? chainCerts = null)
    {
        byte[] localKeyId = SHA1.HashData(cert.PublicKey);

        // ---- Build SafeBags ----
        var bags = new List<byte[]>();

        // Certificate bag for the main cert
        bags.Add(BuildCertBag(cert.DerData, localKeyId));

        // Chain certificates (CA certs)
        if (chainCerts != null)
            foreach (var ca in chainCerts)
                bags.Add(BuildCertBag(ca, null));

        // Key bag (PKCS#8 PrivateKeyInfo, unencrypted)
        if (cert.IsRsa)
            bags.Add(BuildRsaKeyBag(cert.PrivateKey, localKeyId));
        else
            bags.Add(BuildEcKeyBag(cert.PrivateKey, cert.PublicKey, localKeyId));

        // SafeContents = SEQUENCE OF SafeBag
        byte[] safeContents = Asn1.Sequence(bags.ToArray());

        // Wrap in a single ContentInfo { data, [0] OCTET STRING { safeContents } }
        byte[] contentInfo = Asn1.Sequence(
            Asn1.Oid(OidData),
            Asn1.Explicit(0, Asn1.OctetString(safeContents))
        );

        // AuthenticatedSafe = SEQUENCE OF ContentInfo (we have one)
        byte[] authSafe = Asn1.Sequence(contentInfo);

        // Outer ContentInfo wrapping authSafe
        byte[] outerContent = Asn1.Sequence(
            Asn1.Oid(OidData),
            Asn1.Explicit(0, Asn1.OctetString(authSafe))
        );

        // ---- MAC ----
        byte[] macSalt = RandomNumberGenerator.GetBytes(20);
        int iterations = 2048;
        byte[] macKey = Pkcs12Kdf(PasswordToBmp(password), macSalt, iterations, 3, 20);

        using var hmac = new HMACSHA1(macKey);
        byte[] macValue = hmac.ComputeHash(authSafe);

        byte[] macData = Asn1.Sequence(
            Asn1.Sequence( // DigestInfo
                Asn1.Sequence(Asn1.Oid(OidSha1), Asn1.Null()),
                Asn1.OctetString(macValue)
            ),
            Asn1.OctetString(macSalt),
            Asn1.Integer(iterations)
        );

        // PFX = SEQUENCE { version(3), authSafe, macData }
        return Asn1.Sequence(Asn1.Integer(3), outerContent, macData);
    }

    /// <summary>
    /// Import a PKCS#12 / PFX file. Returns the first cert + private key found.
    /// Supports unencrypted bags only.
    /// </summary>
    public static TlsCertificate Import(byte[] pfxData, string password)
    {
        var (_, pfxValue, _) = Asn1.ReadTlv(pfxData);
        var pfxItems = Asn1.ReadSequenceItems(pfxValue);

        // Verify MAC integrity if macData is present (pfxItems[2])
        if (pfxItems.Count >= 3)
        {
            // Extract authSafe DER bytes — the OCTET STRING value inside the outer ContentInfo
            var authSafeCIForMac = Asn1.ReadSequenceItems(pfxItems[1].value);
            var (_, authSafeBytes, _) = Asn1.ReadTlv(authSafeCIForMac[1].value);

            var macItems = Asn1.ReadSequenceItems(pfxItems[2].value);
            // macItems[0] = DigestInfo { AlgorithmIdentifier, OCTET STRING(digest) }
            var digestInfoItems = Asn1.ReadSequenceItems(macItems[0].value);
            byte[] expectedMac = digestInfoItems[1].value;
            byte[] macSalt = macItems[1].value;
            // macItems[2] = iterations (INTEGER value, parse manually)
            int iterations = 0;
            foreach (byte b in macItems[2].value)
                iterations = (iterations << 8) | b;

            byte[] macKey = Pkcs12Kdf(PasswordToBmp(password), macSalt, iterations, 3, 20);
            using var hmac = new System.Security.Cryptography.HMACSHA1(macKey);
            byte[] actualMac = hmac.ComputeHash(authSafeBytes);

            if (!CryptographicOperations.FixedTimeEquals(actualMac, expectedMac))
                throw new TlsException(AlertDescription.DecryptError, "PFX MAC verification failed — wrong password or corrupted file");
        }

        // pfxItems[1] = authSafe ContentInfo
        var authSafeCI = Asn1.ReadSequenceItems(pfxItems[1].value);
        // authSafeCI[1] = [0] EXPLICIT OCTET STRING
        var (_, authSafeExplicit, _) = Asn1.ReadTlv(authSafeCI[1].value);
        // authSafeExplicit = OCTET STRING value containing AuthenticatedSafe SEQUENCE DER
        // Strip the outer SEQUENCE tag to get the content (list of ContentInfo)
        var (_, authSafeSeqContent, _) = Asn1.ReadTlv(authSafeExplicit);
        var authSafeItems = Asn1.ReadSequenceItems(authSafeSeqContent);

        byte[]? certDer = null;
        byte[]? privateKey = null;
        byte[]? publicKey = null;
        SignatureScheme sigAlg = SignatureScheme.EcdsaSecp256r1Sha256;

        foreach (var (_, ciValue) in authSafeItems)
        {
            var ciItems = Asn1.ReadSequenceItems(ciValue);
            if (ciItems.Count < 2) continue;

            // Get the data content: [0] EXPLICIT → OCTET STRING → SEQUENCE (SafeContents)
            var (_, explicitContent, _) = Asn1.ReadTlv(ciItems[1].value);
            // explicitContent is the OCTET STRING value = full DER of SafeContents SEQUENCE
            var (_, safeContentsInner, _) = Asn1.ReadTlv(explicitContent);
            var safeBags = Asn1.ReadSequenceItems(safeContentsInner);
            foreach (var (_, bagValue) in safeBags)
            {
                var bagItems = Asn1.ReadSequenceItems(bagValue);
                if (bagItems.Count < 2) continue;

                // Check for certBag
                if (IsCertBagOid(bagItems[0].value))
                {
                    var (_, certBagExplicit, _) = Asn1.ReadTlv(bagItems[1].value);
                    var certBagItems = Asn1.ReadSequenceItems(certBagExplicit);
                    if (certBagItems.Count >= 2)
                    {
                        var (_, certExplicit, _) = Asn1.ReadTlv(certBagItems[1].value);
                        certDer ??= certExplicit; // take first cert
                    }
                }
                // Check for keyBag
                else if (IsKeyBagOid(bagItems[0].value))
                {
                    var (_, keyInfoExplicit, _) = Asn1.ReadTlv(bagItems[1].value);
                    (privateKey, publicKey, sigAlg) = ParsePkcs8Key(keyInfoExplicit);
                }
            }
        }

        if (certDer == null || privateKey == null || publicKey == null)
            throw new TlsException(AlertDescription.InternalError, "PFX does not contain cert + key");

        return new TlsCertificate
        {
            DerData = certDer,
            PrivateKey = privateKey,
            PublicKey = publicKey,
            SignatureAlgorithm = sigAlg
        };
    }

    // ================================================================
    //  PKCS#12 KDF (RFC 7292 Appendix B)
    // ================================================================

    internal static byte[] Pkcs12Kdf(byte[] password, byte[] salt, int iterations, int id, int keyLen)
    {
        const int v = 64; // SHA-1 block size
        const int u = 20; // SHA-1 output size

        byte[] D = new byte[v];
        Array.Fill(D, (byte)id);

        byte[] S = PadRepeat(salt, v);
        byte[] P = PadRepeat(password, v);

        byte[] I = new byte[S.Length + P.Length];
        Buffer.BlockCopy(S, 0, I, 0, S.Length);
        Buffer.BlockCopy(P, 0, I, S.Length, P.Length);

        int n = (keyLen + u - 1) / u;
        byte[] result = new byte[n * u];

        for (int i = 0; i < n; i++)
        {
            byte[] A;
            using (var sha = SHA1.Create())
            {
                sha.TransformBlock(D, 0, D.Length, null, 0);
                sha.TransformFinalBlock(I, 0, I.Length);
                A = sha.Hash!;
            }

            for (int j = 1; j < iterations; j++)
                A = SHA1.HashData(A);

            Buffer.BlockCopy(A, 0, result, i * u, u);

            if (i + 1 < n)
            {
                byte[] B = PadRepeat(A, v);
                for (int k = 0; k < I.Length / v; k++)
                {
                    int carry = 1;
                    for (int j = v - 1; j >= 0; j--)
                    {
                        int sum = I[k * v + j] + B[j] + carry;
                        I[k * v + j] = (byte)sum;
                        carry = sum >> 8;
                    }
                }
            }
        }

        return result[..keyLen];
    }

    // ================================================================
    //  Internal helpers
    // ================================================================

    private static byte[] PasswordToBmp(string password)
    {
        if (string.IsNullOrEmpty(password)) return Array.Empty<byte>();
        byte[] result = new byte[(password.Length + 1) * 2];
        for (int i = 0; i < password.Length; i++)
        {
            result[i * 2] = (byte)(password[i] >> 8);
            result[i * 2 + 1] = (byte)(password[i] & 0xFF);
        }
        return result;
    }

    private static byte[] PadRepeat(byte[] data, int blockSize)
    {
        if (data.Length == 0) return Array.Empty<byte>();
        int len = ((data.Length + blockSize - 1) / blockSize) * blockSize;
        byte[] result = new byte[len];
        for (int i = 0; i < len; i++)
            result[i] = data[i % data.Length];
        return result;
    }

    private static byte[] BuildCertBag(byte[] certDer, byte[]? localKeyId)
    {
        byte[] certBagValue = Asn1.Sequence(
            Asn1.Oid(OidX509Cert),
            Asn1.Explicit(0, Asn1.OctetString(certDer))
        );

        if (localKeyId != null)
        {
            byte[] attrs = Asn1.Set(
                Asn1.Sequence(Asn1.Oid(OidLocalKeyId), Asn1.Set(Asn1.OctetString(localKeyId)))
            );
            return Asn1.Sequence(Asn1.Oid(OidCertBag), Asn1.Explicit(0, certBagValue), attrs);
        }
        return Asn1.Sequence(Asn1.Oid(OidCertBag), Asn1.Explicit(0, certBagValue));
    }

    private static byte[] BuildEcKeyBag(byte[] privateKey, byte[] publicKey, byte[] localKeyId)
    {
        // ECPrivateKey (RFC 5915)
        byte[] ecPrivKey = Asn1.Sequence(
            Asn1.Integer(1),
            Asn1.OctetString(privateKey),
            Asn1.Explicit(1, Asn1.BitString(publicKey))
        );

        // PKCS#8 PrivateKeyInfo
        byte[] pkcs8 = Asn1.Sequence(
            Asn1.Integer(0),
            Asn1.Sequence(Asn1.Oid(OidEcPublicKey), Asn1.Oid(OidSecp256r1)),
            Asn1.OctetString(ecPrivKey)
        );

        byte[] attrs = Asn1.Set(
            Asn1.Sequence(Asn1.Oid(OidLocalKeyId), Asn1.Set(Asn1.OctetString(localKeyId)))
        );

        return Asn1.Sequence(Asn1.Oid(OidKeyBag), Asn1.Explicit(0, pkcs8), attrs);
    }

    private static byte[] BuildRsaKeyBag(byte[] rsaPrivateKeyDer, byte[] localKeyId)
    {
        // PKCS#8 PrivateKeyInfo for RSA
        byte[] pkcs8 = Asn1.Sequence(
            Asn1.Integer(0),
            Asn1.Sequence(Asn1.Oid(OidRsaEncryption), Asn1.Null()),
            Asn1.OctetString(rsaPrivateKeyDer)
        );

        byte[] attrs = Asn1.Set(
            Asn1.Sequence(Asn1.Oid(OidLocalKeyId), Asn1.Set(Asn1.OctetString(localKeyId)))
        );

        return Asn1.Sequence(Asn1.Oid(OidKeyBag), Asn1.Explicit(0, pkcs8), attrs);
    }

    /// <summary>Parse a PKCS#8 key — auto-detects EC vs RSA from the AlgorithmIdentifier.</summary>
    private static (byte[] privateKey, byte[] publicKey, SignatureScheme sigAlg) ParsePkcs8Key(byte[] pkcs8)
    {
        var items = Asn1.ReadSequenceItems(pkcs8);
        // items[1] = AlgorithmIdentifier SEQUENCE
        var algItems = Asn1.ReadSequenceItems(items[1].value);
        byte[] algOid = Asn1.Wrap(algItems[0].tag, algItems[0].value);
        byte[] ecOid = Asn1.Oid(OidEcPublicKey);
        byte[] rsaOid = Asn1.Oid(OidRsaEncryption);

        if (algOid.AsSpan().SequenceEqual(ecOid))
        {
            // EC key — parse ECPrivateKey from OCTET STRING
            byte[] ecPrivKeyDer = items[2].value;
            var (_, ecPrivKeyContent, _) = Asn1.ReadTlv(ecPrivKeyDer);
            var ecItems = Asn1.ReadSequenceItems(ecPrivKeyContent);

            byte[] privKey = ecItems[1].value;
            byte[]? pubKey = null;
            for (int i = 2; i < ecItems.Count; i++)
            {
                if (ecItems[i].tag == 0xA1)
                {
                    var (_, bitStringValue, _) = Asn1.ReadTlv(ecItems[i].value);
                    pubKey = bitStringValue[1..];
                    break;
                }
            }
            if (pubKey == null)
                throw new TlsException(AlertDescription.InternalError, "EC key missing public key in PFX");

            return (privKey, pubKey, SignatureScheme.EcdsaSecp256r1Sha256);
        }

        if (algOid.AsSpan().SequenceEqual(rsaOid))
        {
            // RSA key — OCTET STRING value is full RSAPrivateKey DER
            byte[] rsaPrivKeyDer = items[2].value;
            using var rsa = System.Security.Cryptography.RSA.Create();
            rsa.ImportRSAPrivateKey(rsaPrivKeyDer, out _);
            byte[] pubKey = rsa.ExportRSAPublicKey();
            return (rsaPrivKeyDer, pubKey, SignatureScheme.RsaPssRsaeSha256);
        }

        throw new TlsException(AlertDescription.InternalError, "Unsupported key type in PFX");
    }

    private static bool IsCertBagOid(byte[] oidTlv)
    {
        byte[] expected = Asn1.Oid(OidCertBag);
        return oidTlv.AsSpan().SequenceEqual(expected.AsSpan(2)); // skip tag+length
    }

    private static bool IsKeyBagOid(byte[] oidTlv)
    {
        byte[] expected = Asn1.Oid(OidKeyBag);
        return oidTlv.AsSpan().SequenceEqual(expected.AsSpan(2));
    }
}
