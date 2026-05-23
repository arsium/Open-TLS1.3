#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class DHValidationParameters
    {
        private readonly byte[] seed;
        private readonly int counter;

		public DHValidationParameters(
            byte[]	seed,
            int		counter)
        {
			if (seed == null)
				throw new ArgumentNullException("seed");

			this.seed = (byte[]) seed.Clone();
            this.counter = counter;
        }

		public byte[] GetSeed()
        {
            return (byte[]) seed.Clone();
        }

		public int Counter
        {
            get { return counter; }
        }

		public override bool Equals(
            object obj)
        {
			if (obj == this)
				return true;

			DHValidationParameters other = obj as DHValidationParameters;

			if (other == null)
				return false;

			return Equals(other);
		}

		protected bool Equals(
			DHValidationParameters other)
		{
			return counter == other.counter
				&& Arrays.AreEqual(this.seed, other.seed);
		}

		public override int GetHashCode()
        {
			return counter.GetHashCode() ^ Arrays.GetHashCode(seed);
		}
    }
}
