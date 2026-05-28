namespace TLS;

using BcX25519 = Org.BouncyCastle.Math.EC.Rfc7748.X25519;

/// <summary>
/// X25519 Diffie-Hellman key exchange (RFC 7748).
///
/// Thin wrapper over BouncyCastle's vendored Rfc7748.X25519. We previously implemented
/// the Montgomery ladder directly in <see cref="System.Numerics.BigInteger"/>, which
/// allocated ~30 immutable BigInteger objects per ladder iteration × 255 iterations ≈
/// **~600 KB per ScalarMult call** (measured by GC.GetTotalAllocatedBytes). BC's
/// implementation works in packed int[10] limbs and allocates a handful of small fixed-
/// size scratch arrays — about 700 B per call. ~1000× reduction with byte-identical
/// output (RFC 7748 vectors verified by CryptoVectorTests).
/// </summary>
public static class X25519
{
    /// <summary>Generate a clamped 32-byte X25519 private key from the RFC 8937 RNG wrapper.</summary>
    public static byte[] GeneratePrivateKey()
    {
        byte[] key = RandomnessWrapper.GetKeyBytes(32);
        Clamp(key);
        return key;
    }

    /// <summary>X25519(privateKey, basepoint) — derive the matching 32-byte public key.</summary>
    public static byte[] PublicFromPrivate(byte[] privateKey)
    {
        byte[] result = new byte[32];
        BcX25519.ScalarMultBase(privateKey.AsSpan(), result.AsSpan());
        return result;
    }

    /// <summary>X25519(myPrivate, theirPublic) — derive the 32-byte shared secret.
    /// Throws on an all-zero result (small-subgroup attack rejection, RFC 7748 §6.1).</summary>
    public static byte[] SharedSecret(byte[] myPrivate, byte[] theirPublic)
    {
        byte[] result = new byte[32];
        // CalculateAgreement returns false when the result is the all-zero point.
        // Matches the validation we did manually in the old BigInteger implementation.
        if (!BcX25519.CalculateAgreement(myPrivate.AsSpan(), theirPublic.AsSpan(), result.AsSpan()))
            throw new TlsException(AlertDescription.IllegalParameter, "X25519 produced all-zero shared secret");
        return result;
    }

    /// <summary>RFC 7748 §5: clear the bottom three bits of byte 0 and set the high bit pattern of byte 31.</summary>
    private static void Clamp(byte[] k)
    {
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;
    }
}
