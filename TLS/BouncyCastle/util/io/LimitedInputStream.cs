#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;
using System.IO;

namespace Org.BouncyCastle.Utilities.IO
{
    internal sealed class LimitedInputStream
        : BaseInputStream
    {
        private readonly Stream m_stream;
        private long m_limit;

        internal LimitedInputStream(Stream stream, long limit)
        {
            this.m_stream = stream;
            this.m_limit = limit;
        }

        internal long CurrentLimit => m_limit;

        public override int Read(byte[] buffer, int offset, int count)
        {
            int numRead = m_stream.Read(buffer, offset, count);
            if (numRead > 0)
            {
                if ((m_limit -= numRead) < 0)
                    throw new StreamOverflowException("Data Overflow");
            }
            return numRead;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override int Read(Span<byte> buffer)
        {
            int numRead = m_stream.Read(buffer);
            if (numRead > 0)
            {
                if ((m_limit -= numRead) < 0)
                    throw new StreamOverflowException("Data Overflow");
            }
            return numRead;
        }
#endif

        public override int ReadByte()
        {
            int b = m_stream.ReadByte();
            if (b >= 0)
            {
                if (--m_limit < 0)
                    throw new StreamOverflowException("Data Overflow");
            }
            return b;
        }
    }
}
