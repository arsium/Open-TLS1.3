#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>ElGamal public key parameters.</summary>
    public class ElGamalPublicKeyParameters
		: ElGamalKeyParameters
    {
        private readonly BigInteger y;

        /// <summary>Initializes a new instance of <see cref="ElGamalPublicKeyParameters"/>.</summary>
        /// <param name="y">The public value Y.</param>
        /// <param name="parameters">The ElGamal domain parameters.</param>
		public ElGamalPublicKeyParameters(
            BigInteger			y,
            ElGamalParameters	parameters)
			: base(false, parameters)
        {
			if (y == null)
				throw new ArgumentNullException("y");

			this.y = y;
        }

        /// <summary>Gets the public value Y.</summary>
		public BigInteger Y => y;

		public override bool Equals(
            object obj)
        {
			if (obj == this)
				return true;

			ElGamalPublicKeyParameters other = obj as ElGamalPublicKeyParameters;

			if (other == null)
				return false;

			return Equals(other);
        }

		protected bool Equals(
			ElGamalPublicKeyParameters other)
		{
			return y.Equals(other.y) && base.Equals(other);
		}

		public override int GetHashCode()
        {
			return y.GetHashCode() ^ base.GetHashCode();
        }
    }
}
