#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{

	/// <summary>
	/// Parameters for tweakable block ciphers.
	/// </summary>
	public class TweakableBlockCipherParameters
		: ICipherParameters
	{
		private readonly byte[] tweak;
		private readonly KeyParameter key;

		public TweakableBlockCipherParameters(KeyParameter key, byte[] tweak)
		{
			this.key = key;
			this.tweak = Arrays.Clone(tweak);
		}

		/// <summary>
		/// Gets the key.
		/// </summary>
		/// <value>the key to use, or <code>null</code> to use the current key.</value>
		public KeyParameter Key
		{
			get { return key; }
		}

		/// <summary>
		/// Gets the tweak value.
		/// </summary>
		/// <value>The tweak to use, or <code>null</code> to use the current tweak.</value>
		public byte[] Tweak
		{
			get { return tweak; }
		}
	}
}