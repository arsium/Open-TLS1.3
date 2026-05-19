namespace TLS;

using System.Security.Cryptography;

/// <summary>P-384 (secp384r1) ECDH key exchange for TLS 1.3.</summary>
public static class EcdhP384
{
    public static (byte[] privateKey, byte[] publicKey) GenerateKeyPair()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);
        var p = ecdh.ExportParameters(true);
        byte[] pubKey = new byte[97];
        pubKey[0] = 0x04;
        Buffer.BlockCopy(p.Q.X!, 0, pubKey, 1, 48);
        Buffer.BlockCopy(p.Q.Y!, 0, pubKey, 49, 48);
        return (p.D!, pubKey);
    }

    public static byte[] SharedSecret(byte[] myPrivateKey, byte[] myPublicKey, byte[] theirPublicKey)
    {
        if (myPublicKey.Length < 97)
            throw new TlsException(AlertDescription.InternalError, "P-384 local public key too short");
        if (theirPublicKey.Length < 97)
            throw new TlsException(AlertDescription.IllegalParameter, "P-384 peer public key too short");

        var ourParams = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP384,
            D = myPrivateKey,
            Q = new ECPoint { X = myPublicKey[1..49], Y = myPublicKey[49..97] }
        };
        using var ours = ECDiffieHellman.Create(ourParams);

        var theirParams = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP384,
            Q = new ECPoint { X = theirPublicKey[1..49], Y = theirPublicKey[49..97] }
        };
        using var theirs = ECDiffieHellman.Create(theirParams);

        byte[] result = ours.DeriveRawSecretAgreement(theirs.PublicKey);

        bool allZero = true;
        for (int i = 0; i < result.Length; i++)
            if (result[i] != 0) { allZero = false; break; }
        if (allZero)
            throw new TlsException(AlertDescription.IllegalParameter, "P-384 ECDH produced all-zero shared secret");

        return result;
    }
}
