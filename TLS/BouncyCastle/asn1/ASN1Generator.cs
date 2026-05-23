#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;
using System.IO;

namespace Org.BouncyCastle.Asn1
{
    public abstract class Asn1Generator
        : IDisposable
    {
		private Stream m_outStream;

		protected Asn1Generator(Stream outStream)
        {
            m_outStream = outStream ?? throw new ArgumentNullException(nameof(outStream));
        }

        protected abstract void Finish();

		protected Stream OutStream
		{
			get { return m_outStream ?? throw new InvalidOperationException(); }
		}

		public abstract void AddObject(Asn1Encodable obj);

        public abstract void AddObject(Asn1Object obj);

        public abstract Stream GetRawOutputStream();

        #region IDisposable

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (m_outStream != null) 
                {
                    Finish();
                    m_outStream = null;
                }
            }
        }

        #endregion

        internal static int InheritConstructedFlag(int intoTag, int fromTag)
        {
            if ((fromTag & Asn1Tags.Constructed) != 0)
                return intoTag | Asn1Tags.Constructed;

            return intoTag & ~Asn1Tags.Constructed;
        }
    }
}
