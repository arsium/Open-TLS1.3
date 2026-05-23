#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Digests
{
    public class Gost3411_2012_256Digest : Gost3411_2012Digest
    {
        private readonly static byte[] IV = {
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
        };

        public override string AlgorithmName
        {
            get { return "GOST3411-2012-256"; }
        }

        public Gost3411_2012_256Digest() : base(IV)
        {

        }

        public Gost3411_2012_256Digest(Gost3411_2012_256Digest other) : base(IV)
        {
            Reset(other);
        }

        public override int GetDigestSize()
        {
            return 32;
        }

        public override int DoFinal(byte[] output, int outOff)
        {
			byte[] result = new byte[64];
			base.DoFinal(result, 0);

			Array.Copy(result, 32, output, outOff, 32);

			return 32;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override int DoFinal(Span<byte> output)
        {
            Span<byte> result = stackalloc byte[64];
            base.DoFinal(result);

            result[32..].CopyTo(output);

            return 32;
        }
#endif

        public override IMemoable Copy()
        {
			return new Gost3411_2012_256Digest(this);
        }
    }
}
