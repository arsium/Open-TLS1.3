namespace TLS;

using System.Collections.Concurrent;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;
using BcECPoint = Org.BouncyCastle.Math.EC.ECPoint;

/// <summary>
/// ECDH on NIST P-256 / P-384 / P-521 via BouncyCastle. Exposes just the operations we need:
/// generate ephemeral keypair, import peer public key, derive the raw X coordinate as the
/// shared secret (TLS 1.3 uses raw-X agreement, not the SP800-56 KDF wrapper).
///
/// Domain parameters and SecureRandom are cached / pooled to avoid the per-call allocation
/// of <see cref="ECDomainParameters"/> + DRBG state that profiling traced to ~300 KB per
/// P-384 keygen in the default-suite handshake.
/// </summary>
internal static class EcdhManaged
{
    // BC's CustomNamedCurves.GetByName likely caches internally but constructing a new
    // ECDomainParameters per call is not free — wrap it once per curve. Thread-safe by
    // virtue of being immutable after init (ECDomainParameters is a value container).
    private static readonly ConcurrentDictionary<string, (X9ECParameters parms, ECDomainParameters domain)> _domainCache = new();

    // Per-thread SecureRandom: BC's default ctor builds a fresh DRBG (Sha256DigestRandomGenerator
    // backed by CryptoApiRandomGenerator) every time. ~1-2 KB of state per construction.
    // ThreadStatic keeps the impl single-threaded (no internal lock contention).
    [ThreadStatic] private static SecureRandom? _tlsRandom;
    private static SecureRandom GetRandom() => _tlsRandom ??= new SecureRandom();

    private static (X9ECParameters parms, ECDomainParameters domain) GetCurve(string curveName)
    {
        string normalized = NormalizeName(curveName);
        return _domainCache.GetOrAdd(normalized, n =>
        {
            var p = CustomNamedCurves.GetByName(n)
                ?? throw new CryptographicException($"BC curve lookup failed for {n}");
            return (p, new ECDomainParameters(p));
        });
    }

    /// <summary>Generate a fresh ECDH keypair on the named curve. Returns (privScalar, pubUncompressed).</summary>
    public static (byte[] priv, byte[] pubUncompressed) Generate(string curveName)
    {
        var (p, domain) = GetCurve(curveName);
        var gen = new ECKeyPairGenerator();
        gen.Init(new ECKeyGenerationParameters(domain, GetRandom()));
        var pair = gen.GenerateKeyPair();
        var priv = (ECPrivateKeyParameters)pair.Private;
        var pub = (ECPublicKeyParameters)pair.Public;
        byte[] privBytes = EcdsaManaged.BigIntegerToFixedBytes(priv.D, (p.N.BitLength + 7) / 8);
        byte[] pubBytes = pub.Q.Normalize().GetEncoded(false); // uncompressed
        return (privBytes, pubBytes);
    }

    /// <summary>Compute raw-X shared secret given our scalar and the peer's uncompressed point.</summary>
    public static byte[] DeriveRawSecret(string curveName, byte[] ourScalar, byte[] peerUncompressed)
    {
        var (p, domain) = GetCurve(curveName);

        var ourPriv = new ECPrivateKeyParameters(new BcBigInteger(1, ourScalar), domain);
        BcECPoint peerQ = p.Curve.DecodePoint(peerUncompressed);
        var peerPub = new ECPublicKeyParameters(peerQ, domain);

        var agreement = new ECDHBasicAgreement();
        agreement.Init(ourPriv);
        BcBigInteger sharedX = agreement.CalculateAgreement(peerPub);
        return EcdsaManaged.BigIntegerToFixedBytes(sharedX, (p.N.BitLength + 7) / 8);
    }

    private static string NormalizeName(string nameOrOid) => nameOrOid switch
    {
        "1.2.840.10045.3.1.7" or "secp256r1" or "nistP256" or "P-256" => "P-256",
        "1.3.132.0.34" or "secp384r1" or "nistP384" or "P-384" => "P-384",
        "1.3.132.0.35" or "secp521r1" or "nistP521" or "P-521" => "P-521",
        _ => throw new CryptographicException($"Unsupported ECDH curve: {nameOrOid}")
    };
}
