#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>The interface that basic Diffie-Hellman implementations conform to.</summary>
    public interface IBasicAgreement
    {
        /// <summary>Initialise the agreement engine.</summary>
        void Init(ICipherParameters parameters);

        /// <summary>Return the field size for the agreement algorithm in bytes.</summary>
        int GetFieldSize();

        /// <summary>
        /// Given a public key from a given party calculate the next message in the agreement sequence.
        /// </summary>
        BigInteger CalculateAgreement(ICipherParameters pubKey);
    }
}
