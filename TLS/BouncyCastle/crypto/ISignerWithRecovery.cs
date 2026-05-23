#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;
using System.Text;

namespace Org.BouncyCastle.Crypto
{
    /**
     * Signer with message recovery.
     */
    public interface ISignerWithRecovery
        : ISigner
    {
        /**
         * Returns true if the signer has recovered the full message as
         * part of signature verification.
         *
         * @return true if full message recovered.
         */
        bool HasFullMessage();

        /**
         * Returns a reference to what message was recovered (if any).
         *
         * @return full/partial message, null if nothing.
         */
        byte[] GetRecoveredMessage();

		/**
		 * Perform an update with the recovered message before adding any other data. This must
		 * be the first update method called, and calling it will result in the signer assuming
		 * that further calls to update will include message content past what is recoverable.
		 *
		 * @param signature the signature that we are in the process of verifying.
		 * @throws IllegalStateException
		 */
		void UpdateWithRecoveredMessage(byte[] signature);
	}
}
