namespace TLS;

using System.Security.Cryptography;
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
/// </summary>
internal static class EcdhManaged
{
    /// <summary>Generate a fresh ECDH keypair on the named curve. Returns (privScalar, pubUncompressed).</summary>
    public static (byte[] priv, byte[] pubUncompressed) Generate(string curveName)
    {
        var p = CustomNamedCurves.GetByName(NormalizeName(curveName));
        var domain = new ECDomainParameters(p);
        var gen = new ECKeyPairGenerator();
        gen.Init(new ECKeyGenerationParameters(domain, new SecureRandom()));
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
        var p = CustomNamedCurves.GetByName(NormalizeName(curveName));
        var domain = new ECDomainParameters(p);

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
