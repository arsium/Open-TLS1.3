#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
	public abstract class Gost3410KeyParameters
		: AsymmetricKeyParameter
	{
		private readonly Gost3410Parameters parameters;
		private readonly DerObjectIdentifier publicKeyParamSet;

		protected Gost3410KeyParameters(
			bool				isPrivate,
			Gost3410Parameters	parameters)
			: base(isPrivate)
		{
			this.parameters = parameters;
		}

		protected Gost3410KeyParameters(
			bool				isPrivate,
			DerObjectIdentifier	publicKeyParamSet)
			: base(isPrivate)
		{
			this.parameters = LookupParameters(publicKeyParamSet);
			this.publicKeyParamSet = publicKeyParamSet;
		}

		public Gost3410Parameters Parameters
		{
			get { return parameters; }
		}

		public DerObjectIdentifier PublicKeyParamSet
		{
			get { return publicKeyParamSet; }
		}

		// TODO Implement Equals/GetHashCode

		private static Gost3410Parameters LookupParameters(
			DerObjectIdentifier publicKeyParamSet)
		{
			if (publicKeyParamSet == null)
				throw new ArgumentNullException("publicKeyParamSet");

			Gost3410ParamSetParameters p = Gost3410NamedParameters.GetByOid(publicKeyParamSet);

			if (p == null)
				throw new ArgumentException("OID is not a valid CryptoPro public key parameter set", "publicKeyParamSet");

			return new Gost3410Parameters(p.P, p.Q, p.A);
		}
	}
}
