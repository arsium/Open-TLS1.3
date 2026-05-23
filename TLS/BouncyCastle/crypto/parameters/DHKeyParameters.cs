#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class DHKeyParameters
		: AsymmetricKeyParameter
    {
        private readonly DHParameters parameters;
		private readonly DerObjectIdentifier algorithmOid;

		protected DHKeyParameters(
            bool			isPrivate,
            DHParameters	parameters)
			: this(isPrivate, parameters, PkcsObjectIdentifiers.DhKeyAgreement)
        {
        }

		protected DHKeyParameters(
            bool				isPrivate,
            DHParameters		parameters,
			DerObjectIdentifier	algorithmOid)
			: base(isPrivate)
        {
			// TODO Should we allow parameters to be null?
            this.parameters = parameters;
			this.algorithmOid = algorithmOid;
        }

		public DHParameters Parameters
        {
            get { return parameters; }
        }

		public DerObjectIdentifier AlgorithmOid
		{
			get { return algorithmOid; }
		}

		public override bool Equals(
			object obj)
        {
			if (obj == this)
				return true;

			DHKeyParameters other = obj as DHKeyParameters;

			if (other == null)
				return false;

			return Equals(other);
        }

		protected bool Equals(
			DHKeyParameters other)
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
