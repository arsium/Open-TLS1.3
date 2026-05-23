#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Digital Signature Algorithm (DSA) private key parameters.</summary>
    public class DsaPrivateKeyParameters
		: DsaKeyParameters
    {
        private readonly BigInteger x;

        /// <summary>Initializes a new instance of <see cref="DsaPrivateKeyParameters"/>.</summary>
        /// <param name="x">The private value X.</param>
        /// <param name="parameters">The DSA domain parameters.</param>
		public DsaPrivateKeyParameters(
            BigInteger		x,
            DsaParameters	parameters)
			: base(true, parameters)
        {
			if (x == null)
				throw new ArgumentNullException("x");

			this.x = x;
        }

        /// <summary>Gets the private value X.</summary>
		public BigInteger X => x;

		public override bool Equals(
			object obj)
        {
			if (obj == this)
				return true;

			DsaPrivateKeyParameters other = obj as DsaPrivateKeyParameters;

			if (other == null)
				return false;

			return Equals(other);
        }

		protected bool Equals(
			DsaPrivateKeyParameters other)
		{
			return x.Equals(other.x) && base.Equals(other);
		}

		public override int GetHashCode()
        {
            return x.GetHashCode() ^ base.GetHashCode();
        }
    }
}
