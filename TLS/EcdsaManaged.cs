namespace TLS;

using System.Collections.Concurrent;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;
using BcECPoint = Org.BouncyCastle.Math.EC.ECPoint;

/// <summary>
/// ECDSA wrapper backed by BouncyCastle, covering the bits of
/// <see cref="System.Security.Cryptography.ECDsa"/> we use: keypair generation on
/// named NIST curves, import/export of parameters, SignData / VerifyData in
/// IEEE-P1363 raw or DER format.
/// </summary>
internal sealed class EcdsaManaged : IDisposable
{
    private X9ECParameters _curveParams = null!;
    private string _curveName = null!;
    private ECPrivateKeyParameters? _priv;
    private ECPublicKeyParameters? _pub;
    private bool _disposed;

    private EcdsaManaged() { }

    // Cache (X9ECParameters, ECDomainParameters) per NIST curve so that:
    //   - we don't re-construct ECDomainParameters per call (~10-50 KB each)
    //   - W-NAF / comb table precomputation on the basepoint persists across calls
    //     (BC stores it on the curve instance, which is shared via CustomNamedCurves).
    private static readonly ConcurrentDictionary<string, (X9ECParameters parms, ECDomainParameters domain)> _curveCache = new();

    // Per-thread SecureRandom — same rationale as in EcdhManaged: BC's default ctor
    // builds a fresh DRBG every call, costing ~1-2 KB. ThreadStatic dodges contention
    // while keeping each thread's DRBG hot.
    [ThreadStatic] private static SecureRandom? _tlsRandom;
    private static SecureRandom Random => _tlsRandom ??= new SecureRandom();

    private static (X9ECParameters parms, ECDomainParameters domain) GetCurve(string secName)
    {
        return _curveCache.GetOrAdd(secName, n =>
        {
            var p = CustomNamedCurves.GetByName(n)
                ?? throw new CryptographicException($"BC curve lookup failed for {n}");
            return (p, new ECDomainParameters(p));
        });
    }

    /// <summary>Empty instance — caller imports parameters after.</summary>
    public static EcdsaManaged Create()
    {
        var (parms, _) = GetCurve("secp256r1");
        return new EcdsaManaged
        {
            _curveParams = parms,
            _curveName = "secp256r1",
        };
    }

    /// <summary>Mirrors ECDsa.Create(curve): generate a fresh keypair on the named curve.</summary>
    public static EcdsaManaged Create(string curveOid)
    {
        var (name, _) = LookupCurve(curveOid);
        var (parms, domain) = GetCurve(name);

        var gen = new ECKeyPairGenerator();
        gen.Init(new ECKeyGenerationParameters(domain, Random));
        var pair = gen.GenerateKeyPair();
        return new EcdsaManaged
        {
            _curveParams = parms,
            _curveName = name,
            _priv = (ECPrivateKeyParameters)pair.Private,
            _pub = (ECPublicKeyParameters)pair.Public,
        };
    }

    /// <summary>Import from raw scalar D and uncompressed point Q (0x04 || X || Y).</summary>
    public void ImportFromComponents(string curveOid, byte[]? d, byte[] uncompressedQ)
    {
        var (name, _) = LookupCurve(curveOid);
        var (parms, domain) = GetCurve(name);
        _curveParams = parms;
        _curveName = name;

        BcECPoint q = parms.Curve.DecodePoint(uncompressedQ);
        _pub = new ECPublicKeyParameters(q, domain);
        if (d != null)
            _priv = new ECPrivateKeyParameters(new BcBigInteger(1, d), domain);
    }

    public byte[] ExportPublicKeyUncompressed()
    {
        if (_pub == null) throw new CryptographicException("No public key available");
        return _pub.Q.Normalize().GetEncoded(false); // false = uncompressed
    }

    public byte[] ExportPrivateScalar()
    {
        if (_priv == null) throw new CryptographicException("No private key available");
        return BigIntegerToFixedBytes(_priv.D, (_curveParams.N.BitLength + 7) / 8);
    }

    /// <summary>SignData producing an ASN.1 DER (r,s) signature.</summary>
    public byte[] SignDataDer(byte[] data, HashAlgorithmName hashAlg)
    {
        if (_priv == null) throw new CryptographicException("No private key available");
        IDigest digest = NewDigest(hashAlg);
        byte[] hash = new byte[digest.GetDigestSize()];
        digest.BlockUpdate(data, 0, data.Length);
        digest.DoFinal(hash, 0);

        var signer = new ECDsaSigner();
        signer.Init(true, new ParametersWithRandom(_priv, Random));
        BcBigInteger[] rs = signer.GenerateSignature(hash);
        var seq = new DerSequence(new DerInteger(rs[0]), new DerInteger(rs[1]));
        return seq.GetEncoded();
    }

    /// <summary>VerifyData against an ASN.1 DER (r,s) signature.</summary>
    public bool VerifyDataDer(byte[] data, byte[] derSignature, HashAlgorithmName hashAlg)
    {
        if (_pub == null) throw new CryptographicException("No public key available");
        HandshakePhaseHook.Mark("ecdsa/verify/enter");
        IDigest digest = NewDigest(hashAlg);
        byte[] hash = new byte[digest.GetDigestSize()];
        digest.BlockUpdate(data, 0, data.Length);
        digest.DoFinal(hash, 0);
        HandshakePhaseHook.Mark("ecdsa/verify/after-hash");

        try
        {
            var seq = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(derSignature));
            var r = ((DerInteger)seq[0]).Value;
            var s = ((DerInteger)seq[1]).Value;
            HandshakePhaseHook.Mark("ecdsa/verify/after-asn1-decode");
            var verifier = new ECDsaSigner();
            verifier.Init(false, _pub);
            HandshakePhaseHook.Mark("ecdsa/verify/after-init");
            bool ok = verifier.VerifySignature(hash, r, s);
            HandshakePhaseHook.Mark("ecdsa/verify/after-VerifySignature");
            return ok;
        }
        catch
        {
            return false;
        }
    }

    private static IDigest NewDigest(HashAlgorithmName hashAlg)
    {
        if (hashAlg == HashAlgorithmName.SHA256) return new Sha256Digest();
        if (hashAlg == HashAlgorithmName.SHA384) return new Sha384Digest();
        if (hashAlg == HashAlgorithmName.SHA512) return new Sha512Digest();
        throw new CryptographicException($"Unsupported hash for ECDSA: {hashAlg}");
    }

    private static (string name, X9ECParameters parms) LookupCurve(string nameOrOid)
    {
        // BC's CustomNamedCurves keys on the SEC name (secp256r1, etc.) — NOT on the NIST
        // alias (P-256). Passing the NIST alias returns null and BC's keypair generator
        // fails with "Invalid result" on the first scalar multiply.
        string sec = nameOrOid switch
        {
            "1.2.840.10045.3.1.7" or "secp256r1" or "nistP256" or "P-256" => "secp256r1",
            "1.3.132.0.34" or "secp384r1" or "nistP384" or "P-384" => "secp384r1",
            "1.3.132.0.35" or "secp521r1" or "nistP521" or "P-521" => "secp521r1",
            _ => throw new CryptographicException($"Unsupported curve: {nameOrOid}")
        };
        // CustomNamedCurves provides the curve-specific optimized field arithmetic
        // (e.g. SecP256R1Curve with Mersenne-style reduction) PLUS cached basepoint
        // W-NAF / comb tables. Using SecNamedCurves instead uses the generic FpCurve
        // path which re-precomputes scalar-mult tables per call — measured at ~4.4 MB
        // per ECDSA verify (~99% of the entire default TLS handshake allocation budget).
        var p = CustomNamedCurves.GetByName(sec);
        if (p == null) throw new CryptographicException($"BC curve lookup failed for {sec}");
        return (sec, p);
    }

    /// <summary>Derive the uncompressed public point from a raw D scalar on the given curve.</summary>
    public static byte[] DerivePublicFromPrivate(string curveOid, byte[] d)
    {
        var (_, parms) = LookupCurve(curveOid);
        var scalar = new BcBigInteger(1, d);
        var q = parms.G.Multiply(scalar).Normalize();
        return q.GetEncoded(false); // 0x04 || X || Y
    }

    internal static byte[] BigIntegerToFixedBytes(BcBigInteger v, int size)
    {
        byte[] raw = v.ToByteArrayUnsigned();
        if (raw.Length == size) return raw;
        if (raw.Length > size) return raw[(raw.Length - size)..];
        byte[] padded = new byte[size];
        Buffer.BlockCopy(raw, 0, padded, size - raw.Length, raw.Length);
        return padded;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _priv = null;
        _pub = null;
    }
}
