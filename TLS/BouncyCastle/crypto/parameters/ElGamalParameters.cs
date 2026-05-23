#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
    // TODO[api] Don't implement ICipherParameters
    public class ElGamalParameters
		: ICipherParameters
    {
        private readonly BigInteger p, g;
		private readonly int l;

		public ElGamalParameters(
            BigInteger	p,
            BigInteger	g)
			: this(p, g, 0)
        {
        }

		public ElGamalParameters(
			BigInteger	p,
			BigInteger	g,
			int			l)
		{
			if (p == null)
				throw new ArgumentNullException("p");
			if (g == null)
				throw new ArgumentNullException("g");

			this.p = p;
			this.g = g;
			this.l = l;
		}

		public BigInteger P
        {
            get { return p; }
        }

		/**
        * return the generator - g
        */
        public BigInteger G
        {
            get { return g; }
        }

		/**
		 * return private value limit - l
		 */
		public int L
		{
			get { return l; }
		}

		public override bool Equals(
            object obj)
        {
			if (obj == this)
				return true;

			ElGamalParameters other = obj as ElGamalParameters;

			if (other == null)
				return false;

			return Equals(other);
        }

		protected bool Equals(
			ElGamalParameters other)
		{
			return p.Equals(other.p) && g.Equals(other.g) && l == other.l;
		}

		public override int GetHashCode()
        {
            return p.GetHashCode() ^ g.GetHashCode() ^ l;
        }
    }
}
