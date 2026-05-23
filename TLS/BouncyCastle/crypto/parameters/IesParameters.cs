#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /**
     * parameters for using an integrated cipher in stream mode.
     */
    public class IesParameters : ICipherParameters
    {
        private byte[]  derivation;
        private byte[]  encoding;
        private int     macKeySize;

        /**
         * @param derivation the derivation parameter for the KDF function.
         * @param encoding the encoding parameter for the KDF function.
         * @param macKeySize the size of the MAC key (in bits).
         */
        public IesParameters(
            byte[]  derivation,
            byte[]  encoding,
            int     macKeySize)
        {
            this.derivation = derivation;
            this.encoding = encoding;
            this.macKeySize = macKeySize;
        }

        public byte[] GetDerivationV()
        {
            return derivation;
        }

        public byte[] GetEncodingV()
        {
            return encoding;
        }

        public int MacKeySize
        {
			get
			{
				return macKeySize;
			}
        }
    }

}
