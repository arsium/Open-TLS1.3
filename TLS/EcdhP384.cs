namespace TLS;

/// <summary>P-384 (secp384r1) ECDH key exchange for TLS 1.3 — backed by BouncyCastle.</summary>
public static class EcdhP384
{
    public static (byte[] privateKey, byte[] publicKey) GenerateKeyPair() =>
        EcdhManaged.Generate("P-384");

    public static byte[] SharedSecret(byte[] myPrivateKey, byte[] myPublicKey, byte[] theirPublicKey)
    {
        if (myPublicKey.Length < 97)
            throw new TlsException(AlertDescription.InternalError, "P-384 local public key too short");
        if (theirPublicKey.Length < 97)
            throw new TlsException(AlertDescription.IllegalParameter, "P-384 peer public key too short");

        byte[] result = EcdhManaged.DeriveRawSecret("P-384", myPrivateKey, theirPublicKey);

        bool allZero = true;
        for (int i = 0; i < result.Length; i++)
            if (result[i] != 0) { allZero = false; break; }
        if (allZero)
            throw new TlsException(AlertDescription.IllegalParameter, "P-384 ECDH produced all-zero shared secret");

        return result;
    }
}
