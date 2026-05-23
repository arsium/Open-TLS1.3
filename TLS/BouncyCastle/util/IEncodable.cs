#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System.IO;

namespace Org.BouncyCastle.Utilities
{
    public interface IEncodable
    {
        /// <summary>Return a byte array representing the implementing object.</summary>
        /// <returns>An encoding of this object as a byte array.</returns>
        /// <exception cref="IOException"/>
        byte[] GetEncoded();

        // TODO[api]
        //void EncodeTo(Stream output);
    }
}
