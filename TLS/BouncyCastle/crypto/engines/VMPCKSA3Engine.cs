#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Crypto.Engines
{
	public class VmpcKsa3Engine
		: VmpcEngine
	{
		public override string AlgorithmName => "VMPC-KSA3";

		protected override void InitKey(byte[] keyBytes, byte[] ivBytes)
		{
			base.InitKey(keyBytes, ivBytes);

            KsaRound(P, ref s, keyBytes);
		}
	}
}
