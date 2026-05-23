#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Crypto
{
    /// <remarks>Block cipher engines are expected to conform to this interface.</remarks>
    public interface IBufferedCipher
    {
        /// <summary>The name of the algorithm this cipher implements.</summary>
        string AlgorithmName { get; }

        /// <summary>Initialise the cipher.</summary>
        /// <param name="forEncryption">If true the cipher is initialised for encryption,
        /// if false for decryption.</param>
        /// <param name="parameters">The key and other data required by the cipher.</param>
        void Init(bool forEncryption, ICipherParameters parameters);

        int GetBlockSize();

        int GetOutputSize(int inputLen);

        int GetUpdateOutputSize(int inputLen);

        byte[] ProcessByte(byte input);
        int ProcessByte(byte input, byte[] output, int outOff);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        int ProcessByte(byte input, Span<byte> output);
#endif

        byte[] ProcessBytes(byte[] input);
        byte[] ProcessBytes(byte[] input, int inOff, int length);
        int ProcessBytes(byte[] input, byte[] output, int outOff);
        int ProcessBytes(byte[] input, int inOff, int length, byte[] output, int outOff);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        // TODO[api]
        //byte[] ProcessBytes(ReadOnlySpan<byte> input);
        int ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output);
#endif

        byte[] DoFinal();
        byte[] DoFinal(byte[] input);
        byte[] DoFinal(byte[] input, int inOff, int length);
        int DoFinal(byte[] output, int outOff);
        int DoFinal(byte[] input, byte[] output, int outOff);
        int DoFinal(byte[] input, int inOff, int length, byte[] output, int outOff);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        // TODO[api]
        //byte[] DoFinal(ReadOnlySpan<byte> input);
        int DoFinal(Span<byte> output);
        int DoFinal(ReadOnlySpan<byte> input, Span<byte> output);
#endif

        /// <summary>
        /// Reset the cipher. After resetting the cipher is in the same state
        /// as it was after the last init (if there was one).
        /// </summary>
        void Reset();
    }
}
