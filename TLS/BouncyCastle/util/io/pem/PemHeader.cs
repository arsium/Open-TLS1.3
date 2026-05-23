#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Utilities.IO.Pem
{
	public class PemHeader
	{
		private string name;
		private string val;

		public PemHeader(string name, string val)
		{
			this.name = name;
			this.val = val;
		}

		public virtual string Name
		{
			get { return name; }
		}

		public virtual string Value
		{
			get { return val; }
		}

		public override int GetHashCode()
		{
			return GetHashCode(this.name) + 31 * GetHashCode(this.val);
		}

		public override bool Equals(object obj)
		{
			if (obj == this)
				return true;

			if (!(obj is PemHeader))
				return false;

			PemHeader other = (PemHeader)obj;

			return Objects.Equals(this.name, other.name)
				&& Objects.Equals(this.val, other.val);
		}

		private int GetHashCode(string s)
		{
			if (s == null)
			{
				return 1;
			}

			return s.GetHashCode();
		}

        public override string ToString()
        {
			return name + ":" + val;
        }
    }
}
