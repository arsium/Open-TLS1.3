namespace TLS;

/// <summary>P-256 (secp256r1) ECDH key exchange for TLS 1.3 — backed by BouncyCastle.</summary>
public static class EcdhP256
{
    public static (byte[] privateKey, byte[] publicKey) GenerateKeyPair() =>
        EcdhManaged.Generate("P-256");

    public static byte[] SharedSecret(byte[] myPrivateKey, byte[] myPublicKey, byte[] theirPublicKey)
    {
        if (myPublicKey.Length < 65)
            throw new TlsException(AlertDescription.InternalError, "P-256 local public key too short");
        if (theirPublicKey.Length < 65)
            throw new TlsException(AlertDescription.IllegalParameter, "P-256 peer public key too short");

        byte[] result = EcdhManaged.DeriveRawSecret("P-256", myPrivateKey, theirPublicKey);

        // Defence against pathological cofactor-induced zero outputs (small-subgroup attack).
        bool allZero = true;
        for (int i = 0; i < result.Length; i++)
            if (result[i] != 0) { allZero = false; break; }
        if (allZero)
            throw new TlsException(AlertDescription.IllegalParameter, "P-256 ECDH produced all-zero shared secret");

        return result;
    }
}
