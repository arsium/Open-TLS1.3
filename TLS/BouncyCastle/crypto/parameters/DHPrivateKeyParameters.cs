#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Diffie-Hellman private key parameters.</summary>
    public class DHPrivateKeyParameters
		: DHKeyParameters
    {
        private readonly BigInteger x;

        /// <summary>Initializes a new instance of <see cref="DHPrivateKeyParameters"/>.</summary>
        /// <param name="x">The private value X.</param>
        /// <param name="parameters">The DH domain parameters.</param>
		public DHPrivateKeyParameters(
            BigInteger		x,
            DHParameters	parameters)
			: base(true, parameters)
        {
            this.x = x;
        }

		public DHPrivateKeyParameters(
            BigInteger			x,
            DHParameters		parameters,
		    DerObjectIdentifier	algorithmOid)
			: base(true, parameters, algorithmOid)
        {
            this.x = x;
        }

        /// <summary>Gets the private value X.</summary>
		public BigInteger X
        {
            get { return x; }
        }

		public override bool Equals(
			object obj)
        {
			if (obj == this)
				return true;

			DHPrivateKeyParameters other = obj as DHPrivateKeyParameters;

			if (other == null)
				return false;

			return Equals(other);
        }

		protected bool Equals(
			DHPrivateKeyParameters other)
		{
			return x.Equals(other.x) && base.Equals(other);
		}

		public override int GetHashCode()
        {
            return x.GetHashCode() ^ base.GetHashCode();
        }
    }
}
