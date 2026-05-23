#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

namespace Org.BouncyCastle.Math.EC.Multiplier
{
    /**
     * Class holding precomputation data for the WTNAF (Window
     * <code>&#964;</code>-adic Non-Adjacent Form) algorithm.
     */
    public class WTauNafPreCompInfo
        : PreCompInfo
    {
        /**
         * Array holding the precomputed <code>AbstractF2mPoint</code>s used for the
         * WTNAF multiplication in <code>
         * {@link Org.BouncyCastle.Math.EC.multiplier.WTauNafMultiplier.multiply()
         * WTauNafMultiplier.multiply()}</code>.
         */
        protected AbstractF2mPoint[] m_preComp;

        public virtual AbstractF2mPoint[] PreComp
        {
            get { return m_preComp; }
            set { this.m_preComp = value; }
        }
    }
}
