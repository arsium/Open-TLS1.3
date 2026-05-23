#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;
using System.IO;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.Digests
{
	public class NullDigest : IDigest
	{
		private readonly MemoryStream bOut = new MemoryStream();

		public string AlgorithmName
		{
			get { return "NULL"; }
		}

		public int GetByteLength()
		{
			// TODO Is this okay?
			return 0;
		}

		public int GetDigestSize()
		{
			return Convert.ToInt32(bOut.Length);
		}

		public void Update(byte b)
		{
			bOut.WriteByte(b);
		}

		public void BlockUpdate(byte[] inBytes, int inOff, int len)
		{
			bOut.Write(inBytes, inOff, len);
		}

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
		public void BlockUpdate(ReadOnlySpan<byte> input)
		{
			bOut.Write(input);
		}
#endif

		public int DoFinal(byte[] outBytes, int outOff)
		{
            try
            {
                byte[] data = bOut.GetBuffer();
				int length = Convert.ToInt32(bOut.Length);

				Array.Copy(data, 0, outBytes, outOff, length);

				return length;
			}
			finally
            {
                Reset();
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int DoFinal(Span<byte> output)
        {
            try
            {
				byte[] data = bOut.GetBuffer();
				int length = Convert.ToInt32(bOut.Length);

				data.AsSpan(0, length).CopyTo(output);

				return length;
            }
            finally
            {
                Reset();
            }
        }
#endif

        public void Reset()
		{
			bOut.SetLength(0);
		}
	}
}
