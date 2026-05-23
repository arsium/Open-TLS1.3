#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Base class for ElGamal key parameters.</summary>
    public class ElGamalKeyParameters
		: AsymmetricKeyParameter
    {
        private readonly ElGamalParameters parameters;

        /// <summary>Initializes a new instance of <see cref="ElGamalKeyParameters"/>.</summary>
        /// <param name="isPrivate">Whether the key is private or not.</param>
        /// <param name="parameters">The ElGamal domain parameters.</param>
		protected ElGamalKeyParameters(
            bool				isPrivate,
            ElGamalParameters	parameters)
			: base(isPrivate)
        {
			// TODO Should we allow 'parameters' to be null?
            this.parameters = parameters;
        }

        /// <summary>Gets the ElGamal domain parameters.</summary>
		public ElGamalParameters Parameters => parameters;

		public override bool Equals(
            object obj)
        {
			if (obj == this)
				return true;

			ElGamalKeyParameters other = obj as ElGamalKeyParameters;

			if (other == null)
				return false;

			return Equals(other);
        }

		protected bool Equals(
			ElGamalKeyParameters other)
		{
			return Objects.Equals(parameters, other.parameters)
				&& base.Equals(other);
		}

		public override int GetHashCode()
        {
			int hc = base.GetHashCode();

			if (parameters != null)
			{
				hc ^= parameters.GetHashCode();
			}

			return hc;
        }
    }
}
