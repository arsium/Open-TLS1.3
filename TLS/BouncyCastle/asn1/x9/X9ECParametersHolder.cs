#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.X9
{
	public abstract class X9ECParametersHolder
	{
        private ECCurve m_curve;
        private X9ECParameters m_parameters;

        public ECCurve Curve => Objects.EnsureSingletonInitialized(ref m_curve, this, self => self.CreateCurve());

        public X9ECParameters Parameters =>
            Objects.EnsureSingletonInitialized(ref m_parameters, this, self => self.CreateParameters());

        protected virtual ECCurve CreateCurve() => Parameters.Curve;

        protected abstract X9ECParameters CreateParameters();
	}
}
