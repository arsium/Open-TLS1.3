#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;
using System.Security.Cryptography;

namespace Org.BouncyCastle.Crypto.Prng
{
    public class CryptoApiEntropySourceProvider
        :   IEntropySourceProvider
    {
        private readonly RandomNumberGenerator mRng;
        private readonly bool mPredictionResistant;

        public CryptoApiEntropySourceProvider()
            : this(RandomNumberGenerator.Create(), true)
        {
        }

        public CryptoApiEntropySourceProvider(RandomNumberGenerator rng, bool isPredictionResistant)
        {
            if (rng == null)
                throw new ArgumentNullException("rng");

            mRng = rng;
            mPredictionResistant = isPredictionResistant;
        }

        public IEntropySource Get(int bitsRequired)
        {
            return new CryptoApiEntropySource(mRng, mPredictionResistant, bitsRequired);
        }

        private class CryptoApiEntropySource
            :   IEntropySource
        {
            private readonly RandomNumberGenerator mRng;
            private readonly bool mPredictionResistant;
            private readonly int mEntropySize;

            internal CryptoApiEntropySource(RandomNumberGenerator rng, bool predictionResistant, int entropySize)
            {
                this.mRng = rng;
                this.mPredictionResistant = predictionResistant;
                this.mEntropySize = entropySize;
            }

            #region IEntropySource Members

            bool IEntropySource.IsPredictionResistant
            {
                get { return mPredictionResistant; }
            }

            byte[] IEntropySource.GetEntropy()
            {
                byte[] result = new byte[(mEntropySize + 7) / 8];
                mRng.GetBytes(result);
                return result;
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            int IEntropySource.GetEntropy(Span<byte> output)
            {
                int length = System.Math.Min(output.Length, (mEntropySize + 7) / 8);
                mRng.GetBytes(output[..length]);
                return length;
            }
#endif

            int IEntropySource.EntropySize
            {
                get { return mEntropySize; }
            }

            #endregion
        }
    }
}
