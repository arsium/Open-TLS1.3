#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;
#if NETCOREAPP1_0_OR_GREATER || NET45_OR_GREATER || NETSTANDARD1_0_OR_GREATER
using System.Threading;
using System.Threading.Tasks;
#endif

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.IO
{
    public sealed class SignerSink
		: BaseOutputStream
	{
		private readonly ISigner m_signer;

        public SignerSink(ISigner signer)
		{
            m_signer = signer ?? throw new ArgumentNullException(nameof(signer));
		}

		public ISigner Signer => m_signer;

		public override void Write(byte[] buffer, int offset, int count)
		{
			Streams.ValidateBufferArguments(buffer, offset, count);

			if (count > 0)
			{
				m_signer.BlockUpdate(buffer, offset, count);
			}
		}

#if NETCOREAPP1_0_OR_GREATER || NET45_OR_GREATER || NETSTANDARD1_0_OR_GREATER
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return Streams.WriteAsyncDirect(this, buffer, offset, count, cancellationToken);
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
		public override void Write(ReadOnlySpan<byte> buffer)
		{
			if (!buffer.IsEmpty)
			{
				m_signer.BlockUpdate(buffer);
			}
		}

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            return Streams.WriteAsyncDirect(this, buffer, cancellationToken);
        }
#endif

		public override void WriteByte(byte value)
		{
			m_signer.Update(value);
		}
	}
}
