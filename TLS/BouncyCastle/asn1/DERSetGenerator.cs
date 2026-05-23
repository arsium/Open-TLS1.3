#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System.IO;

namespace Org.BouncyCastle.Asn1
{
	public class DerSetGenerator
		: DerGenerator
	{
		private readonly MemoryStream _bOut = new MemoryStream();

		public DerSetGenerator(Stream outStream)
			: base(outStream)
		{
		}

		public DerSetGenerator(Stream outStream, int tagNo, bool isExplicit)
			: base(outStream, tagNo, isExplicit)
		{
		}

        protected override void Finish()
        {
            WriteDerEncoded(Asn1Tags.Constructed | Asn1Tags.Set, _bOut.ToArray());
        }

        public override void AddObject(Asn1Encodable obj)
		{
            obj.EncodeTo(_bOut, Asn1Encodable.Der);
		}

        public override void AddObject(Asn1Object obj)
        {
            obj.EncodeTo(_bOut, Asn1Encodable.Der);
        }

        public override Stream GetRawOutputStream()
		{
			return _bOut;
		}
	}
}
