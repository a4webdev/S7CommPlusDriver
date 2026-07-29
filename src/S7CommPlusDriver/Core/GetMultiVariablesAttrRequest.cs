#region License
/******************************************************************************
 * S7CommPlusDriver
 *
 * Copyright (C) 2023 Thomas Wiens, th.wiens@gmx.de
 * Modifications (C) 2026 a4webdev.
 *
 * This file is part of S7CommPlusDriver.
 *
 * S7CommPlusDriver is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 /****************************************************************************/
#endregion

using System;
using System.Collections.Generic;
using System.IO;

namespace S7CommPlusDriver
{
    /// <summary>
    /// GetMultiVariables addressed by ATTRIBUTE ID against a LinkId, rather
    /// than by ItemAddress.
    ///
    /// The standard <see cref="GetMultiVariablesRequest"/> serializes every
    /// address through <see cref="ItemAddress"/>, which always contributes
    /// 4 + LID.Count fields (see ItemAddress.GetNumberOfFields). That form
    /// cannot express the shorter addressing used when reading the attributes
    /// of a system object, where each address is a single VLQ and the LinkId
    /// identifies the object:
    ///
    ///     34 | &lt;LinkId:u32&gt; | &lt;count:vlq&gt; | &lt;fields:vlq&gt;
    ///        | &lt;attrId:vlq&gt; ... | objectqualifier | integrityid
    ///
    /// Verified against S7-1200 firmware V3.0.2 (plaintext) and V4.5 (TLS).
    /// </summary>
    class GetMultiVariablesAttrRequest : IS7pRequest
    {
        byte TransportFlags = 0x34;

        /// <summary>Object the attributes are read from. 0 for ordinary variable reads.</summary>
        public UInt32 LinkId = 0;

        /// <summary>Attribute ids to read, one VLQ field each.</summary>
        public List<UInt32> AttributeIds = new List<UInt32>();

        public uint SessionId { get; set; }
        public byte ProtocolVersion { get; set; }
        public ushort FunctionCode { get => Functioncode.GetMultiVariables; }
        public ushort SequenceNumber { get; set; }
        public uint IntegrityId { get; set; }
        public bool WithIntegrityId { get; set; }

        public GetMultiVariablesAttrRequest(byte protocolVersion)
        {
            ProtocolVersion = protocolVersion;
            WithIntegrityId = true;
        }

        public byte GetProtocolVersion()
        {
            return ProtocolVersion;
        }

        public int Serialize(Stream buffer)
        {
            int ret = 0;
            ret += S7p.EncodeByte(buffer, Opcode.Request);
            ret += S7p.EncodeUInt16(buffer, 0);                               // Reserved
            ret += S7p.EncodeUInt16(buffer, FunctionCode);
            ret += S7p.EncodeUInt16(buffer, 0);                               // Reserved
            ret += S7p.EncodeUInt16(buffer, SequenceNumber);
            ret += S7p.EncodeUInt32(buffer, SessionId);
            ret += S7p.EncodeByte(buffer, TransportFlags);

            // Request set
            ret += S7p.EncodeUInt32(buffer, LinkId);
            ret += S7p.EncodeUInt32Vlq(buffer, (UInt32)AttributeIds.Count);   // item count
            ret += S7p.EncodeUInt32Vlq(buffer, (UInt32)AttributeIds.Count);   // field count: one per item
            foreach (UInt32 id in AttributeIds)
            {
                ret += S7p.EncodeUInt32Vlq(buffer, id);
            }
            ret += S7p.EncodeObjectQualifier(buffer);

            if (WithIntegrityId)
            {
                ret += S7p.EncodeUInt32Vlq(buffer, IntegrityId);
            }
            // Fill
            ret += S7p.EncodeUInt32(buffer, 0);

            return ret;
        }
    }
}
