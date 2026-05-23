#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Engines
{
    /**
    * this does your basic RSA algorithm.
    */
    public class RsaEngine
		: IAsymmetricBlockCipher
    {
		private readonly IRsa core;

        public RsaEngine()
            : this(new RsaCoreEngine())
        {
        }

        public RsaEngine(IRsa rsa)
        {
            this.core = rsa;
        }

        public virtual string AlgorithmName
        {
            get { return "RSA"; }
        }

		/**
        * initialise the RSA engine.
        *
        * @param forEncryption true if we are encrypting, false otherwise.
        * @param param the necessary RSA key parameters.
        */
        public virtual void Init(
            bool				forEncryption,
            ICipherParameters	parameters)
        {
			core.Init(forEncryption, parameters);
		}

		/**
        * Return the maximum size for an input block to this engine.
        * For RSA this is always one byte less than the key size on
        * encryption, and the same length as the key size on decryption.
        *
        * @return maximum size for an input block.
        */
        public virtual int GetInputBlockSize()
        {
			return core.GetInputBlockSize();
        }

		/**
        * Return the maximum size for an output block to this engine.
        * For RSA this is always one byte less than the key size on
        * decryption, and the same length as the key size on encryption.
        *
        * @return maximum size for an output block.
        */
        public virtual int GetOutputBlockSize()
        {
			return core.GetOutputBlockSize();
        }

		/**
        * Process a single block using the basic RSA algorithm.
        *
        * @param inBuf the input array.
        * @param inOff the offset into the input buffer where the data starts.
        * @param inLen the length of the data to be processed.
        * @return the result of the RSA process.
        * @exception DataLengthException the input block is too large.
        */
        public virtual byte[] ProcessBlock(
            byte[]	inBuf,
            int		inOff,
            int		inLen)
        {
            BigInteger input = core.ConvertInput(inBuf, inOff, inLen);
            BigInteger output = core.ProcessBlock(input);
			return core.ConvertOutput(output);
        }
    }
}
