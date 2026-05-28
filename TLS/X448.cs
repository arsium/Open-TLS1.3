namespace TLS;

using BcX448 = Org.BouncyCastle.Math.EC.Rfc7748.X448;

/// <summary>
/// X448 Diffie-Hellman key exchange (RFC 7748).
///
/// Thin wrapper over BouncyCastle's vendored Rfc7748.X448 — same rationale as X25519.cs.
/// The previous BigInteger-based ladder allocated ~30 BigInts × 448 iterations ≈
/// **~1.6 MB per ScalarMult** (the heaviest single allocator in the eager-keygen block).
/// BC's packed-limb impl drops that to ~1 KB.
/// </summary>
public static class X448
{
    /// <summary>Generate a clamped 56-byte X448 private key from the RFC 8937 RNG wrapper.</summary>
    public static byte[] GeneratePrivateKey()
    {
        byte[] key = RandomnessWrapper.GetKeyBytes(56);
        Clamp(key);
        return key;
    }

    /// <summary>X448(privateKey, basepoint) — derive the matching 56-byte public key.</summary>
    public static byte[] PublicFromPrivate(byte[] privateKey)
    {
        byte[] result = new byte[56];
        BcX448.ScalarMultBase(privateKey.AsSpan(), result.AsSpan());
        return result;
    }

    /// <summary>X448(myPrivate, theirPublic) — derive the 56-byte shared secret.
    /// Throws on an all-zero result (small-subgroup attack rejection).</summary>
    public static byte[] SharedSecret(byte[] myPrivate, byte[] theirPublic)
    {
        byte[] result = new byte[56];
        if (!BcX448.CalculateAgreement(myPrivate.AsSpan(), theirPublic.AsSpan(), result.AsSpan()))
            throw new TlsException(AlertDescription.IllegalParameter, "X448 produced all-zero shared secret");
        return result;
    }

    /// <summary>RFC 7748 §5: clear the bottom two bits of byte 0, set the high bit of byte 55.</summary>
    private static void Clamp(byte[] k)
    {
        k[0] &= 252;
        k[55] |= 128;
    }
}
