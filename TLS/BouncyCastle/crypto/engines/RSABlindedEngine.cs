#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Engines
{
    /**
     * this does your basic RSA algorithm with blinding
     */
    public class RsaBlindedEngine
        : IAsymmetricBlockCipher
    {
        private readonly IRsa core;

        private RsaKeyParameters key;
        private SecureRandom random;

        public RsaBlindedEngine()
            : this(new RsaCoreEngine())
        {
        }

        public RsaBlindedEngine(IRsa rsa)
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
        public virtual void Init(bool forEncryption, ICipherParameters param)
        {
            param = ParameterUtilities.GetRandom(param, out var providedRandom);

            core.Init(forEncryption, param);

            this.key = (RsaKeyParameters)param;
            this.random = InitSecureRandom(needed: key is RsaPrivateCrtKeyParameters, providedRandom);
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
        public virtual byte[] ProcessBlock(byte[] inBuf, int inOff, int inLen)
        {
            if (key == null)
                throw new InvalidOperationException("RSA engine not initialised");

            BigInteger input = core.ConvertInput(inBuf, inOff, inLen);
            BigInteger result = ProcessInput(input);
            return core.ConvertOutput(result);
        }

        protected virtual SecureRandom InitSecureRandom(bool needed, SecureRandom provided)
        {
            return needed ? CryptoServicesRegistrar.GetSecureRandom(provided) : null;
        }

        private BigInteger ProcessInput(BigInteger input)
        {
            if (!(key is RsaPrivateCrtKeyParameters crt))
                return core.ProcessBlock(input);

            BigInteger e = crt.PublicExponent;
            BigInteger m = crt.Modulus;

            BigInteger r = BigIntegers.CreateRandomInRange(BigInteger.One, m.Subtract(BigInteger.One), random);
            BigInteger blind = r.ModPow(e, m);
            BigInteger unblind = BigIntegers.ModOddInverse(m, r);

            BigInteger blindedInput = blind.Multiply(input).Mod(m);
            BigInteger blindedResult = core.ProcessBlock(blindedInput);
            return unblind.Multiply(blindedResult).Mod(m);
        }
    }
}
