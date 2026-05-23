#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;
using System.Collections.Generic;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
	/**
	 * Private key parameters for NaccacheStern cipher. For details on this cipher,
	 * please see
	 *
	 * http://www.gemplus.com/smart/rd/publications/pdf/NS98pkcs.pdf
	 */
	public class NaccacheSternPrivateKeyParameters : NaccacheSternKeyParameters
	{
		private readonly BigInteger phiN;
		private readonly IList<BigInteger> smallPrimes;

		/**
		 * Constructs a NaccacheSternPrivateKey
		 *
		 * @param g
		 *            the public enryption parameter g
		 * @param n
		 *            the public modulus n = p*q
		 * @param lowerSigmaBound
		 *            the public lower sigma bound up to which data can be encrypted
		 * @param smallPrimes
		 *            the small primes, of which sigma is constructed in the right
		 *            order
		 * @param phi_n
		 *            the private modulus phi(n) = (p-1)(q-1)
		 */
		public NaccacheSternPrivateKeyParameters(
			BigInteger	g,
			BigInteger	n,
			int			lowerSigmaBound,
			IList<BigInteger> smallPrimes,
			BigInteger	phiN)
			: base(true, g, n, lowerSigmaBound)
		{
			this.smallPrimes = smallPrimes;
			this.phiN = phiN;
		}

		public BigInteger PhiN
		{
			get { return phiN; }
		}

        public IList<BigInteger> SmallPrimesList
        {
            get { return smallPrimes; }
        }
    }
}
