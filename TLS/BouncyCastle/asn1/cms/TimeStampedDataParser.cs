#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Asn1.Cms
{
	public class TimeStampedDataParser
	{
		private DerInteger version;
		private DerIA5String dataUri;
		private MetaData metaData;
		private Asn1OctetStringParser content;
		private Evidence temporalEvidence;
		private Asn1SequenceParser parser;
		
		private TimeStampedDataParser(Asn1SequenceParser parser)
		{
			this.parser = parser;
			this.version = DerInteger.GetInstance(parser.ReadObject());

			Asn1Object obj = parser.ReadObject().ToAsn1Object();

			if (obj is DerIA5String)
			{
				this.dataUri = DerIA5String.GetInstance(obj);
				obj = parser.ReadObject().ToAsn1Object();
			}

            if (//obj is MetaData ||
                obj is Asn1SequenceParser)
			{
				this.metaData = MetaData.GetInstance(obj.ToAsn1Object());
				obj = parser.ReadObject().ToAsn1Object();
			}

			if (obj is Asn1OctetStringParser)
			{
				this.content = (Asn1OctetStringParser)obj;
			}
		}

		public static TimeStampedDataParser GetInstance(object obj)
		{
			if (obj is Asn1Sequence)
				return new TimeStampedDataParser(((Asn1Sequence)obj).Parser);

			if (obj is Asn1SequenceParser)
				return new TimeStampedDataParser((Asn1SequenceParser)obj);

			return null;
		}
		
		public virtual DerIA5String DataUri
		{
			get { return dataUri; }
		}

		public virtual MetaData MetaData
		{
			get { return metaData; }
		}

		public virtual Asn1OctetStringParser Content
		{
			get { return content; }
		}

		public virtual Evidence GetTemporalEvidence()
		{
			if (temporalEvidence == null)
			{
				temporalEvidence = Evidence.GetInstance(parser.ReadObject().ToAsn1Object());
			}

			return temporalEvidence;
		}
	}
}
