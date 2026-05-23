#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Generators
{
    public class DHParametersGenerator
    {
        private int				size;
        private int				certainty;
        private SecureRandom	random;

        public virtual void Init(
            int				size,
            int				certainty,
            SecureRandom	random)
        {
            this.size = size;
            this.certainty = certainty;
            this.random = random;
        }

        /**
         * which Generates the p and g values from the given parameters,
         * returning the DHParameters object.
         * <p>
         * Note: can take a while...</p>
         */
        public virtual DHParameters GenerateParameters()
        {
			//
			// find a safe prime p where p = 2*q + 1, where p and q are prime.
			//
			BigInteger[] safePrimes = DHParametersHelper.GenerateSafePrimes(size, certainty, random);

			BigInteger p = safePrimes[0];
			BigInteger q = safePrimes[1];
			BigInteger g = DHParametersHelper.SelectGenerator(p, q, random);

			return new DHParameters(p, g, q, BigInteger.Two, null);
		}
	}
}
