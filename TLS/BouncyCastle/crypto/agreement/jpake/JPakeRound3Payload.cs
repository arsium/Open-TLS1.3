#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Agreement.JPake
{
    /// <summary>
    /// The payload sent/received during the optional third round of a J-PAKE exchange,
    /// which is for explicit key confirmation.
    ///
    /// Each JPAKEParticipant creates and sends an instance
    /// of this payload to the other JPAKEParticipant.
    /// The payload to send should be created via
    /// JPAKEParticipant#createRound3PayloadToSend(BigInteger)
    ///
    /// Eeach JPAKEParticipant must also validate the payload
    /// received from the other JPAKEParticipant.
    /// The received payload should be validated via
    /// JPAKEParticipant#validateRound3PayloadReceived(JPakeRound3Payload, BigInteger)
    /// </summary>
    public class JPakeRound3Payload
    {
        /// <summary>
        /// The id of the {@link JPAKEParticipant} who created/sent this payload.
        /// </summary>
        private readonly string participantId;

        /// <summary>
        /// The value of MacTag, as computed by round 3.
        /// 
        /// See JPAKEUtil#calculateMacTag(string, string, BigInteger, BigInteger, BigInteger, BigInteger, BigInteger, Org.BouncyCastle.Crypto.Digest)
        /// </summary>
        private readonly BigInteger macTag;

        public JPakeRound3Payload(string participantId, BigInteger magTag)
        {
            this.participantId = participantId;
            this.macTag = magTag;
        }

        public virtual string ParticipantId => participantId;

        public virtual BigInteger MacTag => macTag;
    }
}
