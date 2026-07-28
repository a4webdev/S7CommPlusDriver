#region License
/******************************************************************************
 * S7CommPlusDriver - a4webdev fork, #192 SPIKE INSTRUMENT (read-only)
 *
 * Exists ONLY so the #192 discovery spike can exercise ExploreRequest with
 * ExploreParents = 1. The field is serialized by the upstream driver
 * (Core/ExploreRequest.cs) but is hardwired to 0 at all five call sites, and
 * SendS7plusFunctionObject / WaitForNewS7plusReceived / m_ReceivedPDU are all
 * PRIVATE - so a spike EXE referencing the DLL cannot reach it. A partial class
 * inside the assembly is the only way in without editing upstream call sites.
 *
 * READ-ONLY: this sends Explore requests and returns what came back. It writes
 * nothing to the PLC and changes no existing behaviour. Nothing in the product
 * calls it.
 *
 * Hardening required by the #192 plan and implemented here:
 *   - the raw response PDU is captured for EVERY probe, so a decode failure is
 *     recoverable rather than lost (S3);
 *   - deserialization is wrapped, because PValue.Deserialize throws
 *     NotImplementedException on unimplemented datatype/flag combos and
 *     PObject.AddAttribute/AddObject use Dictionary.Add, which throws on a
 *     duplicate attribute id or duplicate (ClassId, RelationId);
 *   - a timeout is reported DISTINCTLY from an error, because the read path
 *     dequeues with no request correlation: a late response to a timed-out
 *     probe is handed to the NEXT call, so the caller must reconnect.
 *
 * LGPL-3.0-or-later, (C) 2023 Thomas Wiens. Modifications (C) 2026 a4webdev.
 /****************************************************************************/
#endregion

using System;
using System.Collections.Generic;
using System.IO;

namespace S7CommPlusDriver
{
    /// <summary>#192: outcome of one Explore probe. Never throws to the caller.</summary>
    public class SpikeExploreResult
    {
        public uint ExploreId;
        public byte ExploreParents;
        public int ResultCode;                 // 0 = ok
        public bool TimedOut;                  // caller MUST reconnect if true
        public string Error;                   // null when ok
        public byte[] RawPdu;                  // captured for EVERY probe (S3)
        public List<PObject> Objects = new List<PObject>();

        public bool Ok { get { return ResultCode == 0 && Error == null; } }
    }

    public partial class S7CommPlusConnection
    {
        /// <summary>
        /// #192 spike instrument: one Explore round trip with an explicit
        /// ExploreParents value and an empty AddressList. Returns a result
        /// object; never throws.
        /// </summary>
        public SpikeExploreResult SpikeExplore(uint exploreId, byte exploreParents, byte childsRecursive)
        {
            var outcome = new SpikeExploreResult
            {
                ExploreId = exploreId,
                ExploreParents = exploreParents
            };

            try
            {
                var req = new ExploreRequest(ProtocolVersion.V2);
                req.ExploreId = exploreId;
                req.ExploreRequestId = Ids.None;
                req.ExploreChildsRecursive = childsRecursive;
                req.ExploreParents = exploreParents;   // <- the whole point

                int res = SendS7plusFunctionObject(req);
                if (res != 0) { outcome.ResultCode = res; outcome.Error = "send failed"; return outcome; }

                m_LastError = 0;
                WaitForNewS7plusReceived(m_ReadTimeout);
                if (m_LastError != 0)
                {
                    outcome.ResultCode = m_LastError;
                    outcome.TimedOut = true;
                    outcome.Error = "no response within " + m_ReadTimeout + " ms - RECONNECT before the next probe";
                    return outcome;
                }

                // Capture the raw PDU BEFORE attempting to decode it (S3): a
                // decode failure with no bytes is unrecoverable data loss.
                outcome.RawPdu = SnapshotReceivedPdu();

                var resp = ExploreResponse.DeserializeFromPdu(m_ReceivedPDU, true);
                if (resp == null) { outcome.ResultCode = S7Consts.errIsoInvalidPDU; outcome.Error = "ExploreResponse.DeserializeFromPdu returned null"; return outcome; }

                int chk = checkResponseWithIntegrity(req, resp);
                if (chk != 0) { outcome.ResultCode = chk; outcome.Error = "integrity check failed"; return outcome; }

                if (resp.Objects != null) outcome.Objects = resp.Objects;
                return outcome;
            }
            catch (Exception ex)
            {
                // PValue.Deserialize NotImplementedException, PObject duplicate-key
                // ArgumentException, anything else. One bad object must never end
                // the run - that is how a crash gets misread as "not reachable".
                outcome.ResultCode = -1;
                outcome.Error = ex.GetType().Name + ": " + ex.Message;
                return outcome;
            }
        }

        /// <summary>#192: copy the received PDU without disturbing its position.</summary>
        private byte[] SnapshotReceivedPdu()
        {
            try
            {
                if (m_ReceivedPDU == null) return null;
                long pos = m_ReceivedPDU.Position;
                byte[] bytes = m_ReceivedPDU.ToArray();
                m_ReceivedPDU.Position = pos;
                return bytes;
            }
            catch { return null; }
        }
    }
}
