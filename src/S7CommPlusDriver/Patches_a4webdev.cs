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
            int r1 = ReadUIntAttribute(m_SessionId, (uint)Ids.EffectiveProtectionLevel, out effective);
            if (r1 != 0) return r1;
            return ReadUIntAttribute(m_SessionId, (uint)Ids.ActiveProtectionLevel, out active);
        }

        /// <summary>
        /// #184: CPU operating state via the exec-unit object. Returns the raw
        /// protocol value; caller maps to RUN/STOP/STARTUP. May return an error
        /// if the attribute is not readable on this firmware - recorded, not hidden.
        /// </summary>
        public int GetPlcOperatingState(out uint state)
        {
            return ReadUIntAttribute((uint)Ids.NativeObjects_theCPUexecUnit_Rid,
                                     (uint)Ids.CPUexecUnit_operatingStateReq, out state);
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
