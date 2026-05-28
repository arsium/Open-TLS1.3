namespace TLS;

using System.Numerics;
using System.Security.Cryptography;
using OpenGost.Security.Cryptography;

/// <summary>
/// GOST elliptic-curve Diffie-Hellman for the RFC 9367 TLS 1.3 key exchange.
/// key_share = PlainPointRepresentation { X[len]; Y[len]; } little-endian.
/// shared secret = little-endian X-coordinate of (cofactor · d) · Q_peer.
/// Reuses the vendored BigIntegerPoint EC math over the GOST curves.
/// </summary>
internal static class GostEcdh
{
    public static int CoordinateLength(string curveOid)
        => ECCurveOidMap.GetExplicitCurveByOid(curveOid).Prime!.Length;

    public static (byte[] priv, byte[] pub) GenerateKeyPair(string curveOid)
    {
        // NB: an experimental BC `ECGost3410NamedCurves`-backed fast path was tried here
        // (see git history) — it made GOST handshakes *worse* (6.4 MB → 21.8 MB per
        // handshake). Root cause: BC only provides optimized Custom*Curve impls for
        // a few NIST curves; the GOST curves fall back to generic `FpCurve` which uses
        // BC's BigInteger — same allocation profile as our OpenGost BigIntegerPoint plus
        // overhead from BC's W-NAF table precomputation per-call on the random peer point.
        var c = ECCurveOidMap.GetExplicitCurveByOid(curveOid);
        int size = c.Prime!.Length;
        var prime = CryptoUtils.UnsignedBigIntegerFromLittleEndian(c.Prime);
        var a = CryptoUtils.UnsignedBigIntegerFromLittleEndian(c.A!);
        var subgroupOrder = CryptoUtils.UnsignedBigIntegerFromLittleEndian(c.Order!) /
            CryptoUtils.UnsignedBigIntegerFromLittleEndian(c.Cofactor!);

        byte[] priv = new byte[size];
        BigInteger d;
        do
        {
            RandomNumberGenerator.Fill(priv);
            d = CryptoUtils.UnsignedBigIntegerFromLittleEndian(priv) % subgroupOrder;
        }
        while (d.IsZero);
        CryptoUtils.ToLittleEndian(d, priv, 0, size);

        var q = BigIntegerPoint.Multiply(new BigIntegerPoint(c.G), d, prime, a);
        var qp = q.ToECPoint(size);
        byte[] pub = new byte[2 * size];
        Buffer.BlockCopy(qp.X!, 0, pub, 0, size);
        Buffer.BlockCopy(qp.Y!, 0, pub, size, size);
        return (priv, pub);
    }

    public static byte[] ComputeSharedSecret(byte[] priv, byte[] peerPub, string curveOid)
    {
        var c = ECCurveOidMap.GetExplicitCurveByOid(curveOid);
        int size = c.Prime!.Length;
        if (peerPub.Length != 2 * size)
            throw new TlsException(AlertDescription.IllegalParameter, "Invalid GOST key_share length");

        var prime = CryptoUtils.UnsignedBigIntegerFromLittleEndian(c.Prime);
        var a = CryptoUtils.UnsignedBigIntegerFromLittleEndian(c.A!);
        var cofactor = CryptoUtils.UnsignedBigIntegerFromLittleEndian(c.Cofactor!);
        var d = CryptoUtils.UnsignedBigIntegerFromLittleEndian(priv);

        var peer = new BigIntegerPoint(new ECPoint
        {
            X = peerPub[..size],
            Y = peerPub[size..(2 * size)],
        });
        var shared = BigIntegerPoint.Multiply(peer, cofactor * d, prime, a);
        return CryptoUtils.ToLittleEndian(shared.X, size);
    }
}
