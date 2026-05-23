#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Prng
{
    public class X931SecureRandom
        :   SecureRandom
    {
        private readonly bool           mPredictionResistant;
        private readonly SecureRandom   mRandomSource;
        private readonly X931Rng        mDrbg;

        internal X931SecureRandom(SecureRandom randomSource, X931Rng drbg, bool predictionResistant)
            : base(null)
        {
            this.mRandomSource = randomSource;
            this.mDrbg = drbg;
            this.mPredictionResistant = predictionResistant;
        }

        public override void SetSeed(byte[] seed)
        {
            lock (this)
            {
                if (mRandomSource != null)
                {
                    this.mRandomSource.SetSeed(seed);
                }
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override void SetSeed(Span<byte> seed)
        {
            lock (this)
            {
                if (mRandomSource != null)
                {
                    this.mRandomSource.SetSeed(seed);
                }
            }
        }
#endif

        public override void SetSeed(long seed)
        {
            lock (this)
            {
                // this will happen when SecureRandom() is created
                if (mRandomSource != null)
                {
                    this.mRandomSource.SetSeed(seed);
                }
            }
        }

        public override void NextBytes(byte[] bytes)
        {
            NextBytes(bytes, 0, bytes.Length);
        }

        public override void NextBytes(byte[] buf, int off, int len)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            NextBytes(buf.AsSpan(off, len));
#else
            lock (this)
            {
                // check if a reseed is required...
                if (mDrbg.Generate(buf, off, len, mPredictionResistant) < 0)
                {
                    mDrbg.Reseed();
                    mDrbg.Generate(buf, off, len, mPredictionResistant);
                }
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override void NextBytes(Span<byte> buffer)
        {
            lock (this)
            {
                // check if a reseed is required...
                if (mDrbg.Generate(buffer, mPredictionResistant) < 0)
                {
                    mDrbg.Reseed();
                    mDrbg.Generate(buffer, mPredictionResistant);
                }
            }
        }
#endif

        public override byte[] GenerateSeed(int numBytes)
        {
            return EntropyUtilities.GenerateSeed(mDrbg.EntropySource, numBytes);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override void GenerateSeed(Span<byte> seed)
        {
            EntropyUtilities.GenerateSeed(mDrbg.EntropySource, seed);
        }
#endif
    }
}
