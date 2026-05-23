#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

namespace Org.BouncyCastle.Crypto.Modes
{
    public class EcbBlockCipher
        : IBlockCipherMode
    {
        internal static IBlockCipherMode GetBlockCipherMode(IBlockCipher blockCipher)
        {
            if (blockCipher is IBlockCipherMode blockCipherMode)
                return blockCipherMode;

            return new EcbBlockCipher(blockCipher);
        }

        private readonly IBlockCipher m_cipher;

        public EcbBlockCipher(IBlockCipher cipher)
        {
            m_cipher = cipher ?? throw new ArgumentNullException(nameof(cipher));
        }

        public bool IsPartialBlockOkay => false;

        public string AlgorithmName => m_cipher.AlgorithmName + "/ECB";

        public int GetBlockSize()
        {
            return m_cipher.GetBlockSize();
        }

        public IBlockCipher UnderlyingCipher => m_cipher;

        public void Init(bool forEncryption, ICipherParameters parameters)
        {
            m_cipher.Init(forEncryption, parameters);
        }

        public int ProcessBlock(byte[] inBuf, int inOff, byte[] outBuf, int outOff)
        {
            return m_cipher.ProcessBlock(inBuf, inOff, outBuf, outOff);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            return m_cipher.ProcessBlock(input, output);
        }
#endif

        public void Reset()
        {
        }
    }
}
