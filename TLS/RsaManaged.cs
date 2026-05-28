namespace TLS;

using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;

// Per-thread SecureRandom for RSA signing — see the same pattern in EcdsaManaged.

/// <summary>
/// RSA wrapper backed by BouncyCastle. Mirrors the parts of
/// <see cref="System.Security.Cryptography.RSA"/> we actually use:
/// key gen, PKCS#1 import/export, SignData / VerifyData with PSS or PKCS#1 v1.5 padding.
/// Replaces the BCrypt/OpenSSL P/Invoke path with managed crypto throughout the cert paths.
/// </summary>
internal sealed class RsaManaged : IDisposable
{
    [ThreadStatic] private static SecureRandom? _tlsRandom;
    private static SecureRandom Random => _tlsRandom ??= new SecureRandom();

    private RsaPrivateCrtKeyParameters? _priv;
    private RsaKeyParameters? _pub;
    private bool _disposed;

    private RsaManaged() { }

    /// <summary>Mirrors RSA.Create(keySize) — generates a fresh keypair.</summary>
    public static RsaManaged Create(int keySize)
    {
        var gen = new RsaKeyPairGenerator();
        gen.Init(new KeyGenerationParameters(new SecureRandom(), keySize));
        var pair = gen.GenerateKeyPair();
        return new RsaManaged
        {
            _priv = (RsaPrivateCrtKeyParameters)pair.Private,
            _pub = (RsaKeyParameters)pair.Public,
        };
    }

    /// <summary>Mirrors RSA.Create() — empty instance, caller imports a key after.</summary>
    public static RsaManaged Create() => new RsaManaged();

    /// <summary>Mirrors RSA.ImportRSAPrivateKey: PKCS#1 RSAPrivateKey DER.</summary>
    public void ImportRSAPrivateKey(ReadOnlySpan<byte> source, out int bytesRead)
    {
        byte[] der = source.ToArray();
        bytesRead = der.Length;
        var seq = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(der));
        // RFC 8017 RSAPrivateKey: version, n, e, d, p, q, dP, dQ, qInv
        var n  = ((DerInteger)seq[1]).Value;
        var e  = ((DerInteger)seq[2]).Value;
        var d  = ((DerInteger)seq[3]).Value;
        var p  = ((DerInteger)seq[4]).Value;
        var q  = ((DerInteger)seq[5]).Value;
        var dP = ((DerInteger)seq[6]).Value;
        var dQ = ((DerInteger)seq[7]).Value;
        var qI = ((DerInteger)seq[8]).Value;
        _priv = new RsaPrivateCrtKeyParameters(n, e, d, p, q, dP, dQ, qI);
        _pub = new RsaKeyParameters(false, n, e);
    }

    /// <summary>Mirrors RSA.ImportRSAPublicKey: PKCS#1 RSAPublicKey DER.</summary>
    public void ImportRSAPublicKey(ReadOnlySpan<byte> source, out int bytesRead)
    {
        byte[] der = source.ToArray();
        bytesRead = der.Length;
        var seq = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(der));
        var n = ((DerInteger)seq[0]).Value;
        var e = ((DerInteger)seq[1]).Value;
        _pub = new RsaKeyParameters(false, n, e);
    }

    public byte[] ExportRSAPrivateKey()
    {
        if (_priv == null) throw new CryptographicException("No private key available");
        var seq = new DerSequence(
            new DerInteger(0), // version
            new DerInteger(_priv.Modulus),
            new DerInteger(_priv.PublicExponent),
            new DerInteger(_priv.Exponent),
            new DerInteger(_priv.P),
            new DerInteger(_priv.Q),
            new DerInteger(_priv.DP),
            new DerInteger(_priv.DQ),
            new DerInteger(_priv.QInv));
        return seq.GetEncoded();
    }

    public byte[] ExportRSAPublicKey()
    {
        if (_pub == null) throw new CryptographicException("No public key available");
        var seq = new DerSequence(new DerInteger(_pub.Modulus), new DerInteger(_pub.Exponent));
        return seq.GetEncoded();
    }

    public byte[] SignData(byte[] data, HashAlgorithmName hashAlg, RSASignaturePadding padding)
    {
        if (_priv == null) throw new CryptographicException("No private key available");
        ISigner signer = BuildSigner(hashAlg, padding);
        signer.Init(true, new ParametersWithRandom(_priv, Random));
        signer.BlockUpdate(data, 0, data.Length);
        return signer.GenerateSignature();
    }

    public bool VerifyData(byte[] data, byte[] signature, HashAlgorithmName hashAlg, RSASignaturePadding padding)
    {
        if (_pub == null) throw new CryptographicException("No public key available");
        ISigner verifier = BuildSigner(hashAlg, padding);
        verifier.Init(false, _pub);
        verifier.BlockUpdate(data, 0, data.Length);
        return verifier.VerifySignature(signature);
    }

    private static ISigner BuildSigner(HashAlgorithmName hashAlg, RSASignaturePadding padding)
    {
        IDigest digest = NewDigest(hashAlg);
        // RSASignaturePadding doesn't expose Mode directly, but the BCL ships exactly two
        // singletons (Pss and Pkcs1) plus an enum on the type; compare against them.
        if (padding == RSASignaturePadding.Pss)
            return new PssSigner(new RsaEngine(), digest, digest.GetDigestSize());
        if (padding == RSASignaturePadding.Pkcs1)
            return new RsaDigestSigner(digest);
        throw new CryptographicException($"Unsupported RSA padding: {padding}");
    }

    private static IDigest NewDigest(HashAlgorithmName hashAlg)
    {
        if (hashAlg == HashAlgorithmName.SHA256) return new Sha256Digest();
        if (hashAlg == HashAlgorithmName.SHA384) return new Sha384Digest();
        if (hashAlg == HashAlgorithmName.SHA512) return new Sha512Digest();
        if (hashAlg == HashAlgorithmName.SHA1)   return new Sha1Digest();
        throw new CryptographicException($"Unsupported hash for RSA signing: {hashAlg}");
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        // BC's BigInteger holds an int[] mag we can't reach; rely on GC for now.
        _priv = null;
        _pub = null;
    }
}
