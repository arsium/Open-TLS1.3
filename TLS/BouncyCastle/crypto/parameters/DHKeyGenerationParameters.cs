#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class DHKeyGenerationParameters
		: KeyGenerationParameters
    {
        private readonly DHParameters parameters;

		public DHKeyGenerationParameters(
            SecureRandom	random,
            DHParameters	parameters)
			: base(random, GetStrength(parameters))
        {
            this.parameters = parameters;
        }

		public DHParameters Parameters
        {
            get { return parameters; }
        }

		internal static int GetStrength(
			DHParameters parameters)
		{
			return parameters.L != 0 ? parameters.L : parameters.P.BitLength;
		}
    }
}
