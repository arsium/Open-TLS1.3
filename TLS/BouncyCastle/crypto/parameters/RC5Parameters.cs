#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class RC5Parameters
		: KeyParameter
    {
        private readonly int rounds;

		public RC5Parameters(
            byte[]	key,
            int		rounds)
			: base(key)
        {
            if (key.Length > 255)
                throw new ArgumentException("RC5 key length can be no greater than 255");

			this.rounds = rounds;
        }

		public int Rounds
        {
			get { return rounds; }
        }
    }
}
