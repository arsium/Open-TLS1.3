#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System.IO;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Asn1
{
    internal abstract class LimitedInputStream
        : BaseInputStream
    {
        protected readonly Stream m_in;
        private int m_limit;

        internal LimitedInputStream(Stream inStream, int limit)
        {
            m_in = inStream;
            m_limit = limit;
        }

        internal virtual int Limit => m_limit;

        protected void EnableParentEofDetect()
        {
            if (m_in is IndefiniteLengthInputStream indef)
            {
                indef.SetEofOn00(true);
            }
        }
    }
}
