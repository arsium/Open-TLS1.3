#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Generators
{
    /**
     * a DSA key pair generator.
     *
     * This Generates DSA keys in line with the method described
     * in <i>FIPS 186-3 B.1 FFC Key Pair Generation</i>.
     */
    public class DsaKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private static readonly BigInteger One = BigInteger.One;

        private DsaKeyGenerationParameters param;

        public void Init(
            KeyGenerationParameters parameters)
        {
            if (parameters == null)
                throw new ArgumentNullException("parameters");

            // Note: If we start accepting instances of KeyGenerationParameters,
            // must apply constraint checking on strength (see DsaParametersGenerator.Init)

            this.param = (DsaKeyGenerationParameters) parameters;
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            DsaParameters dsaParams = param.Parameters;

            BigInteger x = GeneratePrivateKey(dsaParams.Q, param.Random);
            BigInteger y = CalculatePublicKey(dsaParams.P, dsaParams.G, x);

            return new AsymmetricCipherKeyPair(
                new DsaPublicKeyParameters(y, dsaParams),
                new DsaPrivateKeyParameters(x, dsaParams));
        }

        private static BigInteger GeneratePrivateKey(BigInteger q, SecureRandom random)
        {
            // B.1.2 Key Pair Generation by Testing Candidates
            int minWeight = q.BitLength >> 2;
            for (;;)
            {
                // TODO Prefer this method? (change test cases that used fixed random)
                // B.1.1 Key Pair Generation Using Extra Random Bits
                //BigInteger x = new BigInteger(q.BitLength + 64, random).Mod(q.Subtract(One)).Add(One);

                BigInteger x = BigIntegers.CreateRandomInRange(One, q.Subtract(One), random);
                if (WNafUtilities.GetNafWeight(x) >= minWeight)
                {
                    return x;
                }
            }
        }

        private static BigInteger CalculatePublicKey(BigInteger p, BigInteger g, BigInteger x)
        {
            return g.ModPow(x, p);
        }
    }
}
