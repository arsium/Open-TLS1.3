#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;
using System.Diagnostics;
using System.IO;

namespace Org.BouncyCastle.Utilities.IO
{
	public class TeeInputStream
		: BaseInputStream
	{
		private readonly Stream input, tee;

		public TeeInputStream(Stream input, Stream tee)
		{
			Debug.Assert(input.CanRead);
			Debug.Assert(tee.CanWrite);

			this.input = input;
			this.tee = tee;
		}

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                input.Dispose();
                tee.Dispose();
            }
            base.Dispose(disposing);
        }

        public override int Read(byte[] buffer, int offset, int count)
		{
			int i = input.Read(buffer, offset, count);

			if (i > 0)
			{
				tee.Write(buffer, offset, i);
			}

			return i;
		}

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override int Read(Span<byte> buffer)
        {
            int i = input.Read(buffer);

            if (i > 0)
            {
				tee.Write(buffer[..i]);
            }

            return i;
        }
#endif

        public override int ReadByte()
		{
			int i = input.ReadByte();

			if (i >= 0)
			{
				tee.WriteByte((byte)i);
			}

			return i;
		}
	}
}
