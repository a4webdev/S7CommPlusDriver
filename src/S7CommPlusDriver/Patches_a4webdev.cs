#region License
/******************************************************************************
 * S7CommPlusDriver - a4webdev fork patch
 *
 * #184 (TiaCommander): expose read-only CPU diagnostics that the protocol
 * already carries but upstream keeps internal - CPU identity/firmware
 * (captured at connect, see Legitimation.cs), effective/active protection
 * level, and the CPU operating state (RUN/STOP). Read-only; no new writes.
 *
 * LGPL-3.0-or-later, (C) 2023 Thomas Wiens. Modifications (C) 2026 a4webdev.
 /****************************************************************************/
#endregion

using System;
using System.Collections.Generic;

namespace S7CommPlusDriver
{
    public partial class S7CommPlusConnection
    {
        // Captured during Connect()/legitimate() from the session-version string.
        // Example CpuSystemVersion: "1;6ES7 215-1HG40-0XB0;V4.5"
        public string CpuSystemVersion { get; internal set; }
        public string CpuOrderNumber { get; internal set; }      // "6ES7 215-1HG40-0XB0"
        public string CpuFirmwareVersion { get; internal set; }  // "V4.5"
        public uint EffectiveProtectionLevelValue { get; internal set; } // set in legitimate()

        /// <summary>
        /// Read a single unsigned-integer attribute of an object via GetVarSubstreamed,
        /// mirroring the pattern legitimate() uses for the protection level.
        /// </summary>
        private int ReadUIntAttribute(uint inObjectId, uint address, out uint value)
        {
            value = 0;
            // #192 S6 RANGE GUARD. GetVarSubstreamedRequest.Address is a UInt16,
            // so any attribute id >= 65536 silently TRUNCATES and the CPU answers
            // res=0 with a plausible but WRONG value. A wrong answer is worse than
            // an error, so reject it before any result can be trusted.
            if (address > UInt16.MaxValue) return S7Consts.errIsoInvalidPDU;
            var req = new GetVarSubstreamedRequest(ProtocolVersion.V2);
            // #212: integrity ids arrived with secure communication, so a CPU that
            // cannot encrypt does not expect one and will not answer a request carrying
            // it. Same correction as ReadAttributes below.
            req.WithIntegrityId = !PlaintextSessionActive;
            req.InObjectId = inObjectId;
            req.SessionId = m_SessionId;
            req.Address = (ushort)address;
            int res = SendS7plusFunctionObject(req);
            if (res != 0) return res;
            m_LastError = 0;
            WaitForNewS7plusReceived(m_ReadTimeout);
            if (m_LastError != 0) return m_LastError;
            var resp = GetVarSubstreamedResponse.DeserializeFromPdu(m_ReceivedPDU);
            if (resp == null) return S7Consts.errIsoInvalidPDU;
            var vu = resp.Value as ValueUDInt;
            if (vu != null) { value = vu.GetValue(); return 0; }
            var vd = resp.Value as ValueDInt;
            if (vd != null) { value = (uint)vd.GetValue(); return 0; }
            var vi = resp.Value as ValueInt;
            if (vi != null) { value = (uint)vi.GetValue(); return 0; }
            var vui = resp.Value as ValueUInt;
            if (vui != null) { value = vui.GetValue(); return 0; }
            return S7Consts.errIsoInvalidPDU;
        }

        /// <summary>#184: effective + active protection level (0 = full access).</summary>
        public int GetProtectionLevels(out uint effective, out uint active)
        {
            effective = 0; active = 0;
            // #212: a CPU that refused encryption does not implement these attributes
            // (1842/1843), and asking anyway is not harmless - the same firmware closes
            // the connection on an unsupported SystemLimits read. Since the bridge calls
            // this on EVERY connect, issuing them here would break the session before
            // the caller ever gets to read anything.
            //
            // ProtectionLevelKnown is already false in this state (Legitimation skips the
            // read), so callers report "unknown" rather than mistaking 0 for full access.
            if (PlaintextSessionActive) return 0;
            int r1 = ReadUIntAttribute(m_SessionId, (uint)Ids.EffectiveProtectionLevel, out effective);
            if (r1 != 0) return r1;
            return ReadUIntAttribute(m_SessionId, (uint)Ids.ActiveProtectionLevel, out active);
        }

        /// <summary>
        /// #184: CPU operating state via the exec-unit object. Returns the raw
        /// protocol value; caller maps to RUN/STOP/STARTUP. May return an error
        /// if the attribute is not readable on this firmware - recorded, not hidden.
        ///
        /// ⚠ #221: THIS READS THE *REQUESTED* STATE (attribute 2167), NOT THE ACTUAL
        /// ONE. #184 spike5 measured it returning 0 on a running CPU and recorded the
        /// actual-state id as unknown. It is now known - see
        /// GetPlcOperatingStateActual below. Kept because it is the write-side
        /// counterpart and its enum (0x03 = RUN, 0x01 = STOP) is what a mode COMMAND
        /// carries; do not use it to answer "is the PLC running".
        /// </summary>
        public int GetPlcOperatingState(out uint state)
        {
            return ReadUIntAttribute((uint)Ids.NativeObjects_theCPUexecUnit_Rid,
                                     (uint)Ids.CPUexecUnit_operatingStateReq, out state);
        }

        /// <summary>
        /// #221: the ACTUAL CPU operating state (attribute 3486 on the exec-unit
        /// object). This is the one that answers "is the PLC running".
        ///
        /// Located by packet capture, not by guessing: TIA's own reconnect burst
        /// against a plaintext CPU carries this attribute in its response, and its
        /// value tracked an operator-driven RUN -> STOP -> RUN with the mode command
        /// sitting between the two reads. Full evidence and the rejected candidates
        /// are in TiaCommander agents/research/findings/221-spike1-opstate.md.
        ///
        /// RAW VALUE ONLY - mapping is the caller's business, deliberately, so a
        /// firmware that answers with an unexpected value surfaces as "unknown"
        /// rather than being silently coerced into RUN or STOP.
        ///
        ///   0x08 = RUN      0x04 = STOP
        ///
        /// ⚠ The REQUEST enum is DIFFERENT (0x03 = RUN, 0x01 = STOP). Reusing one
        /// mapping for both paths produces code that compiles and lies.
        ///
        /// Read-only. Returns an S7Consts error if the attribute is not readable on
        /// this firmware - which is a real possibility and must be reported, never
        /// defaulted.
        /// </summary>
        /// <summary>
        /// #221 RETRACTED - DO NOT USE, and do not "fix" it by guessing another id.
        ///
        /// This shipped briefly reading a supposed attribute 3486. THERE IS NO
        /// ATTRIBUTE 3486. The id came from misreading `9b 1e` in a captured response
        /// as a varuint attribute id, when those bytes are item framing:
        ///     9b = item return code, 1e = item reference 30, 00 = PValue flags,
        ///     08 = Datatype.DInt, then the value (8 = RUN, 4 = STOP).
        ///
        /// Both routes below were MEASURED to return nothing on V3.0.2 AND V4.6, which
        /// is the correct outcome for a request naming an attribute that does not exist.
        ///
        /// WHAT IS ACTUALLY ESTABLISHED: the operating state arrives as an ITEM in a
        /// GetMultiVariables (0x054c) response and in Notifications (0x33), addressed by
        /// an ItemAddress - SymbolCrc / AccessArea / AccessSubArea / LID list - not by an
        /// attribute id. Implementing it means building that ItemAddress, which is not
        /// yet decoded. See TiaCommander agents/research/findings/221-spike1-opstate.md.
        ///
        /// Kept, returning an error, so the negative result is not rediscovered. It never
        /// returns a default: callers must render UNKNOWN, because a CPU whose state
        /// could not be read is not a stopped CPU.
        /// </summary>
        [Obsolete("#221: reads a nonexistent attribute. The operating state is addressed by ItemAddress, not by attribute id - see 221-spike1-opstate.md.")]
        public int GetPlcOperatingStateActual(out uint state)
        {
            state = 0;
            return S7Consts.errIsoInvalidPDU;
        }

        /// <summary>
        /// #221: recover the operating state from a raw GetMultiVariables response or
        /// Notification PDU, given the ITEM REFERENCE the request asked under.
        ///
        /// Wire shape, confirmed against captures and against Notification.cs's own item
        /// loop:
        ///     9b &lt;itemref VLQ&gt; 00 08 &lt;value&gt;
        ///     ^^                ^^ ^^ ^^
        ///     |                 |  |  +-- 8 = RUN, 4 = STOP
        ///     |                 |  +----- Datatype.DInt
        ///     |                 +-------- PValue flags
        ///     +-------------------------- item return code (VLQ item ref follows)
        ///
        /// THE ITEM REFERENCE IS CHOSEN BY THE REQUESTER. TIA used 30; that number means
        /// nothing to another client, so it is a parameter here rather than a constant -
        /// hardcoding 30 would be copying a coincidence.
        ///
        /// A scan rather than a full deserialize: #192 showed the shipped deserializer
        /// silently drops about half of such a response, so scanning the bytes we
        /// positively identified is narrower and honest about its scope.
        ///
        /// Returns false when the pattern is absent. The caller must then report UNKNOWN
        /// and must never fall back to a default state.
        /// </summary>
        internal static bool TryScanOperatingState(byte[] pdu, byte itemRef, out uint state)
        {
            state = 0;
            if (pdu == null || pdu.Length < 5) return false;
            for (int i = 0; i + 4 < pdu.Length; i++)
            {
                if (pdu[i] == 0x9B && pdu[i + 1] == itemRef && pdu[i + 2] == 0x00 && pdu[i + 3] == 0x08)
                {
                    state = pdu[i + 4];
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Read raw attribute values from a system object.
        ///
        /// Generic transport hook: issues a GetMultiVariables addressed by
        /// attribute id against a LinkId, and hands back the response PDU
        /// unparsed. Interpreting the payload is the caller's business - this
        /// method deliberately knows nothing about any particular object.
        ///
        /// Exists as a driver method rather than in a consumer because
        /// SendS7plusFunctionObject, WaitForNewS7plusReceived and m_ReceivedPDU
        /// are private; an external assembly cannot reach them.
        ///
        /// Read-only. Never throws.
        /// </summary>
        /// <param name="linkId">Object to read from.</param>
        /// <param name="attributeIds">Attribute ids to request.</param>
        /// <param name="responsePdu">Raw response PDU, or null on failure.</param>
        /// <returns>0 on success, otherwise an S7Consts error code.</returns>
        public int ReadAttributes(uint linkId, List<uint> attributeIds, out byte[] responsePdu)
        {
            responsePdu = null;
            if (attributeIds == null || attributeIds.Count == 0) return S7Consts.errIsoInvalidPDU;

            try
            {
                var req = new GetMultiVariablesAttrRequest(ProtocolVersion.V2);
                // Integrity ids arrived with secure communication, so a CPU that cannot
                // do TLS does not expect one. Measured: against firmware V3.0 our request
                // was byte-identical to the engineering tool's except for one extra byte,
                // the integrity-id VLQ, and the CPU never answered. The tool sends no
                // integrity id at all to that CPU.
                req.WithIntegrityId = !PlaintextSessionActive;
                req.LinkId = linkId;
                req.AttributeIds = attributeIds;

                int res = SendS7plusFunctionObject(req);
                if (res != 0) return res;

                m_LastError = 0;
                WaitForNewS7plusReceived(m_ReadTimeout);
                if (m_LastError != 0) return m_LastError;

                // SnapshotReceivedPdu() is defined in Patches_a4webdev_Spike192.cs
                responsePdu = SnapshotReceivedPdu();
                if (responsePdu == null || responsePdu.Length == 0)
                    return S7Consts.errIsoInvalidPDU;

                return 0;
            }
            catch (Exception)
            {
                return S7Consts.errIsoInvalidPDU;
            }
        }

    }
}
