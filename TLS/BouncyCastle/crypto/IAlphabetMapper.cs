#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

namespace Org.BouncyCastle.Crypto
{
    /// <summary>Base interface for mapping from an alphabet to a set of indexes.</summary>
    /// <remarks>Suitable for use with FPE.</remarks>
    public interface IAlphabetMapper
    {
        /// <summary>
        /// Return the number of characters in the alphabet.
        /// </summary>
        /// <returns>the radix for the alphabet.</returns>
        int Radix { get; }

        /// <summary>
        /// Return the passed in char[] as a byte array of indexes (indexes
        /// can be more than 1 byte)
        /// </summary>
        /// <returns>an index array.</returns>
        /// <param name="input">characters to be mapped.</param>   
        byte[] ConvertToIndexes(char[] input);

        /// <summary>
        /// Return a char[] for this alphabet based on the indexes passed.
        /// </summary>
        /// <returns>an array of char corresponding to the index values.</returns>
        /// <param name="input">input array of indexes.</param>   
        char[] ConvertToChars(byte[] input);
    }
}
