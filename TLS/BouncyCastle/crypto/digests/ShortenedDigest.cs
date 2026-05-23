#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Crypto.Digests
{
	/**
	* Wrapper class that reduces the output length of a particular digest to
	* only the first n bytes of the digest function.
	*/
	public class ShortenedDigest
		: IDigest
	{
		private IDigest	baseDigest;
		private int		length;

		/**
		* Base constructor.
		*
		* @param baseDigest underlying digest to use.
		* @param length length in bytes of the output of doFinal.
		* @exception ArgumentException if baseDigest is null, or length is greater than baseDigest.GetDigestSize().
		*/
		public ShortenedDigest(
			IDigest	baseDigest,
			int		length)
		{
			if (baseDigest == null)
			{
				throw new ArgumentNullException("baseDigest");
			}

			if (length > baseDigest.GetDigestSize())
			{
				throw new ArgumentException("baseDigest output not large enough to support length");
			}

			this.baseDigest = baseDigest;
			this.length = length;
		}

		public string AlgorithmName
		{
			get { return baseDigest.AlgorithmName + "(" + length * 8 + ")"; }
		}

		public int GetDigestSize()
		{
			return length;
		}

		public void Update(byte input)
		{
			baseDigest.Update(input);
		}

		public void BlockUpdate(byte[] input, int inOff, int length)
		{
			baseDigest.BlockUpdate(input, inOff, length);
		}

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            baseDigest.BlockUpdate(input);
        }
#endif

        public int DoFinal(byte[] output, int outOff)
		{
			byte[] tmp = new byte[baseDigest.GetDigestSize()];

			baseDigest.DoFinal(tmp, 0);

	        Array.Copy(tmp, 0, output, outOff, length);

			return length;
		}

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int DoFinal(Span<byte> output)
        {
			int baseDigestSize = baseDigest.GetDigestSize();
            Span<byte> tmp = baseDigestSize <= 128
				? stackalloc byte[baseDigestSize]
				: new byte[baseDigestSize];

            baseDigest.DoFinal(tmp);

            tmp[..length].CopyTo(output);

            return length;
        }
#endif

        public void Reset()
		{
			baseDigest.Reset();
		}

		public int GetByteLength()
		{
			return baseDigest.GetByteLength();
		}
	}
}
