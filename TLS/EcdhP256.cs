namespace TLS;

using System.Security.Cryptography;

/// <summary>P-256 (secp256r1) ECDH key exchange for TLS 1.3.</summary>
public static class EcdhP256
{
    public static (byte[] privateKey, byte[] publicKey) GenerateKeyPair()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var p = ecdh.ExportParameters(true);
        byte[] pubKey = new byte[65];
        pubKey[0] = 0x04;
        Buffer.BlockCopy(p.Q.X!, 0, pubKey, 1, 32);
        Buffer.BlockCopy(p.Q.Y!, 0, pubKey, 33, 32);
        return (p.D!, pubKey);
    }

    public static byte[] SharedSecret(byte[] myPrivateKey, byte[] myPublicKey, byte[] theirPublicKey)
    {
        if (myPublicKey.Length < 65)
            throw new TlsException(AlertDescription.InternalError, "P-256 local public key too short");
        if (theirPublicKey.Length < 65)
            throw new TlsException(AlertDescription.IllegalParameter, "P-256 peer public key too short");

        var ourParams = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = myPrivateKey,
            Q = new ECPoint { X = myPublicKey[1..33], Y = myPublicKey[33..65] }
        };
        using var ours = ECDiffieHellman.Create(ourParams);

        var theirParams = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = theirPublicKey[1..33], Y = theirPublicKey[33..65] }
        };
        using var theirs = ECDiffieHellman.Create(theirParams);

        byte[] result = ours.DeriveRawSecretAgreement(theirs.PublicKey);

        bool allZero = true;
        for (int i = 0; i < result.Length; i++)
            if (result[i] != 0) { allZero = false; break; }
        if (allZero)
            throw new TlsException(AlertDescription.IllegalParameter, "P-256 ECDH produced all-zero shared secret");

        return result;
    }
}
