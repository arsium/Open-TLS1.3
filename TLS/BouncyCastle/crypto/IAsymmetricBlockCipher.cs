#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Crypto
{
	/// <remarks>Base interface for a public/private key block cipher.</remarks>
	public interface IAsymmetricBlockCipher
    {
		/// <summary>The name of the algorithm this cipher implements.</summary>
        string AlgorithmName { get; }

		/// <summary>Initialise the cipher.</summary>
		/// <param name="forEncryption">Initialise for encryption if true, for decryption if false.</param>
		/// <param name="parameters">The key or other data required by the cipher.</param>
        void Init(bool forEncryption, ICipherParameters parameters);

		/// <returns>The maximum size, in bytes, an input block may be.</returns>
        int GetInputBlockSize();

		/// <returns>The maximum size, in bytes, an output block will be.</returns>
		int GetOutputBlockSize();

		/// <summary>Process a block.</summary>
		/// <param name="inBuf">The input buffer.</param>
		/// <param name="inOff">The offset into <paramref>inBuf</paramref> that the input block begins.</param>
		/// <param name="inLen">The length of the input block.</param>
		/// <exception cref="InvalidCipherTextException">Input decrypts improperly.</exception>
		/// <exception cref="DataLengthException">Input is too large for the cipher.</exception>
        byte[] ProcessBlock(byte[] inBuf, int inOff, int inLen);
    }
}
