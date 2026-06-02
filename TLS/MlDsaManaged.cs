namespace TLS;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

/// <summary>
/// ML-DSA (FIPS 204) post-quantum signatures for TLS 1.3, per draft-ietf-tls-mldsa.
///
/// Spec status: the ML-DSA algorithm is final (FIPS 204) and its X.509 certificate encoding is final
/// (RFC 9881), but its TLS integration — the signature_algorithms code points 0x0904/0905/0906 used
/// here — is an Internet-Draft (draft-ietf-tls-mldsa), NOT yet an RFC, and may change.
///
/// Thin wrapper over the vendored BouncyCastle ML-DSA (pure-managed, ACVP-tested) — the same
/// approach used for RSA (<see cref="RsaManaged"/>) and NIST EC (<see cref="EcdsaManaged"/>),
/// so there is no BCrypt/OpenSSL P/Invoke. The draft (§3-4) mandates the *pure* ML-DSA.Sign /
/// ML-DSA.Verify (FIPS 204 Algorithms 2 and 3) over the RFC 8446 §4.4.3 CertificateVerify content,
/// with the FIPS-204 context parameter set to the EMPTY string (distinct from the §4.4.3 context
/// string, which is already baked into the signed content by the caller).
/// </summary>
public static class MlDsaManaged
{
    public static bool IsMlDsa(SignatureScheme scheme) =>
        scheme is SignatureScheme.MlDsa44 or SignatureScheme.MlDsa65 or SignatureScheme.MlDsa87;

    private static MLDsaParameters Params(SignatureScheme scheme) => scheme switch
    {
        SignatureScheme.MlDsa44 => MLDsaParameters.ml_dsa_44,
        SignatureScheme.MlDsa65 => MLDsaParameters.ml_dsa_65,
        SignatureScheme.MlDsa87 => MLDsaParameters.ml_dsa_87,
        _ => throw new ArgumentException($"Not an ML-DSA signature scheme: {scheme}", nameof(scheme))
    };

    /// <summary>Generate an ML-DSA key pair. Returns the FIPS 204 raw encodings
    /// (private = rho‖K‖tr‖s1‖s2‖t0, public = rho‖t1).</summary>
    public static (byte[] privateKey, byte[] publicKey) GenerateKeyPair(SignatureScheme scheme)
    {
        var p = Params(scheme);
        var kpg = new MLDsaKeyPairGenerator();
        kpg.Init(new MLDsaKeyGenerationParameters(new SecureRandom(), p));
        var kp = kpg.GenerateKeyPair();
        var pub = (MLDsaPublicKeyParameters)kp.Public;
        var priv = (MLDsaPrivateKeyParameters)kp.Private;
        return (priv.GetEncoded(), pub.GetEncoded());
    }

    /// <summary>ML-DSA.Sign (hedged/randomized, empty context) over <paramref name="data"/>.</summary>
    public static byte[] Sign(byte[] data, byte[] privateKey, SignatureScheme scheme)
    {
        var p = Params(scheme);
        var sk = MLDsaPrivateKeyParameters.FromEncoding(p, privateKey);
        var signer = new MLDsaSigner(p, deterministic: false);
        signer.Init(forSigning: true, sk);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.GenerateSignature();
    }

    /// <summary>ML-DSA.Verify (empty context). Returns false on an invalid signature.</summary>
    public static bool Verify(byte[] data, byte[] signature, byte[] publicKey, SignatureScheme scheme)
    {
        var p = Params(scheme);
        var pk = MLDsaPublicKeyParameters.FromEncoding(p, publicKey);
        var signer = new MLDsaSigner(p, deterministic: false);
        signer.Init(forSigning: false, pk);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.VerifySignature(signature);
    }
}
