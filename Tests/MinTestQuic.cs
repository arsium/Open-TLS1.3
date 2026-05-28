namespace MinTLS;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;

public static class MinBcTest
{
    public static void Run()
    {
        Console.WriteLine("=== Min BC EC test ===");

        // First try CustomNamedCurves (returns optimized SecP256R1Curve).
        X9ECParameters parmsC = Org.BouncyCastle.Crypto.EC.CustomNamedCurves.GetByName("secp256r1");
        Console.WriteLine($"[Custom] G class: {parmsC.G.GetType().FullName}, Curve: {parmsC.G.Curve.GetType().FullName}");
        try {
            var r = parmsC.G.Multiply(Org.BouncyCastle.Math.BigInteger.One).Normalize();
            Console.WriteLine($"[Custom] G*1 OK, IsInfinity={r.IsInfinity}");
        } catch (Exception e) { Console.WriteLine($"[Custom] G*1 FAILED: {e.Message}"); }

        X9ECParameters parms = SecNamedCurves.GetByName("secp256r1");
        Console.WriteLine($"[Sec] G class: {parms.G.GetType().FullName}, Curve: {parms.G.Curve.GetType().FullName}");
        Console.WriteLine($"[Sec] G.IsValid: {parms.G.IsValid()}");
        // direct curve-equation check via reflection
        var mi = typeof(Org.BouncyCastle.Math.EC.ECPoint).GetMethod("SatisfiesCurveEquation",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Console.WriteLine($"[Sec] G.SatisfiesCurveEquation()={mi?.Invoke(parms.G, null)}");
        Console.WriteLine($"[Sec] G normalized X={parms.G.AffineXCoord.ToBigInteger().ToString(16)}");
        Console.WriteLine($"[Sec] G normalized Y={parms.G.AffineYCoord.ToBigInteger().ToString(16)}");
        Console.WriteLine($"[Sec] Curve.A={parms.Curve.A.ToBigInteger().ToString(16)}");
        Console.WriteLine($"[Sec] Curve.B={parms.Curve.B.ToBigInteger().ToString(16)}");
        Console.WriteLine($"[Sec] Field.Char={parms.Curve.Field.Characteristic.ToString(16)}");
        try {
            // Try G + Infinity = G
            var inf = parms.Curve.Infinity;
            var addedInf = parms.G.Add(inf);
            Console.WriteLine($"[Sec] G+Inf SatisfiesCurveEquation: {mi?.Invoke(addedInf, null)}");
            var addedInfNorm = addedInf.Normalize();
            Console.WriteLine($"[Sec] G+Inf normalized SatisfiesCurveEquation: {mi?.Invoke(addedInfNorm, null)}");
        } catch (Exception e) { Console.WriteLine($"[Sec] G+Inf FAILED: {e.Message}"); }
        try {
            // Try G.Twice()
            var twice = parms.G.Twice();
            Console.WriteLine($"[Sec] 2G SatisfiesCurveEquation (unnormalized): {mi?.Invoke(twice, null)}");
            var twiceNorm = twice.Normalize();
            Console.WriteLine($"[Sec] 2G SatisfiesCurveEquation (normalized): {mi?.Invoke(twiceNorm, null)}");
        } catch (Exception e) { Console.WriteLine($"[Sec] 2G FAILED: {e.Message}"); }
        try {
            var scalarOne = new Org.BouncyCastle.Math.BigInteger("1");
            var result = parms.G.Multiply(scalarOne).Normalize();
            Console.WriteLine($"[Sec] G*1 result class: {result.GetType().FullName}, IsInfinity={result.IsInfinity}");
        } catch (Exception e) {
            Console.WriteLine($"[Sec] G*1 FAILED: {e.GetType()}: {e.Message}");
        }

        // Manually normalize 2G without BC's blinding logic, see if THAT works.
        {
            var twoG = parms.G.Twice();
            var zField = twoG.GetType().GetMethod("GetZCoord", new[] { typeof(int) });
            var z = zField?.Invoke(twoG, new object[] { 0 }) as Org.BouncyCastle.Math.EC.ECFieldElement;
            Console.WriteLine($"[Sec] 2G Z = {z?.ToBigInteger().ToString(16)?[..16]}...");
            // Manual normalize without blinding: zInv = z.Invert().
            try {
                var zInv = z!.Invert();
                Console.WriteLine($"[Sec] zInv = {zInv.ToBigInteger().ToString(16)[..16]}...");
                var check = z.Multiply(zInv);
                Console.WriteLine($"[Sec] z*zInv = {check.ToBigInteger()}");  // should be 1
            } catch (Exception e) { Console.WriteLine($"[Sec] z.Invert() FAILED: {e.Message}"); }
        }

        // Examine 2G — unnormalized passes curve check, normalized fails. So Normalize() is
        // the broken step. Compare RawX, RawY, RawZ before and after normalization.
        var twiceP = parms.G.Twice();
        var rxF = twiceP.GetType().GetProperty("RawXCoord", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        var ryF = twiceP.GetType().GetProperty("RawYCoord", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        var rzF = twiceP.GetType().GetProperty("RawZCoords", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Console.WriteLine($"[Sec] 2G coord-system: {twiceP.GetType().GetProperty("CurveCoordinateSystem")?.GetValue(twiceP)}");
        var rawXFe = rxF?.GetValue(twiceP) as Org.BouncyCastle.Math.EC.ECFieldElement;
        var rawYFe = ryF?.GetValue(twiceP) as Org.BouncyCastle.Math.EC.ECFieldElement;
        Console.WriteLine($"[Sec] 2G rawX={rawXFe?.ToBigInteger().ToString(16)[..16]}... rawY={rawYFe?.ToBigInteger().ToString(16)[..16]}...");

        // Test VmpcRandomGenerator (ArbitraryRandom's underlying generator).
        var vmpcField = typeof(SecureRandom).GetField("ArbitraryRandom",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        var arbRand = vmpcField?.GetValue(null) as SecureRandom;
        byte[] vmpcOut = new byte[16];
        arbRand!.NextBytes(vmpcOut);
        Console.WriteLine($"[Sec] ArbitraryRandom output 16B: {BitConverter.ToString(vmpcOut).Replace("-", "")}");

        // Test RandomFieldElementMult — what Normalize() actually uses for blinding.
        var rfeMethod = typeof(Org.BouncyCastle.Math.EC.ECCurve).GetMethod("RandomFieldElementMult");
        var rfe = rfeMethod?.Invoke(parms.Curve, new object[] { arbRand! });
        var rfeBI = (rfe as Org.BouncyCastle.Math.EC.ECFieldElement)?.ToBigInteger();
        Console.WriteLine($"[Sec] RandomFieldElementMult = {rfeBI?.ToString(16)[..32]}...");

        // Test BOTH paths of modular inverse.
        var pmod = parms.Curve.Field.Characteristic;
        var three = new Org.BouncyCastle.Math.BigInteger("3");
        try {
            var inv = three.ModInverse(pmod);
            var check = three.Multiply(inv).Mod(pmod);
            Console.WriteLine($"[Math] BigInteger.ModInverse: 3*inv mod p = {check}");
        } catch (Exception e) { Console.WriteLine($"[Math] BigInteger.ModInverse FAILED: {e.Message}"); }
        try {
            var inv = Org.BouncyCastle.Utilities.BigIntegers.ModOddInverse(pmod, three);
            var check = three.Multiply(inv).Mod(pmod);
            Console.WriteLine($"[Math] BigIntegers.ModOddInverse: 3*inv mod p = {check}");
        } catch (Exception e) { Console.WriteLine($"[Math] BigIntegers.ModOddInverse FAILED: {e.Message}"); }
        try {
            var domain = new ECDomainParameters(parms);
            var rng = new SecureRandom(new CryptoApiRandomGenerator());
            var gen = new ECKeyPairGenerator();
            gen.Init(new ECKeyGenerationParameters(domain, rng));
            var pair = gen.GenerateKeyPair();
            Console.WriteLine("ECKeyPairGenerator OK");
        } catch (Exception e) {
            Console.WriteLine($"ECKeyPairGenerator FAILED: {e.GetType()}: {e.Message}");
        }
    }
}
