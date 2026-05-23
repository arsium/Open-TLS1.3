#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
	public class Gost3410ValidationParameters
	{
		private int x0;
		private int c;
		private long x0L;
		private long cL;

		public Gost3410ValidationParameters(
			int x0,
			int c)
		{
			this.x0 = x0;
			this.c = c;
		}

		public Gost3410ValidationParameters(
			long x0L,
			long cL)
		{
			this.x0L = x0L;
			this.cL = cL;
		}

		public int C { get { return c; } }
		public int X0 { get { return x0; } }
		public long CL { get { return cL; } }
		public long X0L { get { return x0L; } }

		public override bool Equals(
			object obj)
		{
			Gost3410ValidationParameters other = obj as Gost3410ValidationParameters;

			return other != null
				&& other.c == this.c
				&& other.x0 == this.x0
				&& other.cL == this.cL
				&& other.x0L == this.x0L;
		}

		public override int GetHashCode()
		{
			return c.GetHashCode() ^ x0.GetHashCode() ^ cL.GetHashCode() ^ x0L.GetHashCode();
		}

	}
}
