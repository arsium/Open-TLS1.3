#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
	public class RC2Parameters
		: KeyParameter
	{
		private readonly int bits;

		public RC2Parameters(
			byte[] key)
			: this(key, (key.Length > 128) ? 1024 : (key.Length * 8))
		{
		}

		public RC2Parameters(
			byte[]	key,
			int		keyOff,
			int		keyLen)
			: this(key, keyOff, keyLen, (keyLen > 128) ? 1024 : (keyLen * 8))
		{
		}

		public RC2Parameters(
			byte[]	key,
			int		bits)
			: base(key)
		{
			this.bits = bits;
		}

		public RC2Parameters(
			byte[]	key,
			int		keyOff,
			int		keyLen,
			int		bits)
			: base(key, keyOff, keyLen)
		{
			this.bits = bits;
		}

		public int EffectiveKeyBits
		{
			get { return bits; }
		}
	}
}
