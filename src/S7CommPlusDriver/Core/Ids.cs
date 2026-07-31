#region License
/******************************************************************************
 * S7CommPlusDriver
 * 
 * Copyright (C) 2023 Thomas Wiens, th.wiens@gmx.de
 *
 * This file is part of S7CommPlusDriver.
 *
 * S7CommPlusDriver is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 /****************************************************************************/
#endregion

namespace S7CommPlusDriver
{
    public static class Ids
    {
        public const int None = 0;
        public const int NativeObjects_thePLCProgram_Rid = 3;
        public const int NativeObjects_theAlarmSubsystem_Rid = 8;
        public const int NativeObjects_theCPUexecUnit_Rid = 52;
        public const int NativeObjects_theIArea_Rid = 80;
        public const int NativeObjects_theQArea_Rid = 81;
        public const int NativeObjects_theMArea_Rid = 82;
        public const int NativeObjects_theS7Counters_Rid = 83;
        public const int NativeObjects_theS7Timers_Rid = 84;
        public const int ObjectRoot = 201;
        public const int GetNewRIDOnServer = 211;
        public const int ObjectVariableTypeParentObject = 229;
        public const int ObjectVariableTypeName = 233;
        public const int ClassSubscriptions = 255;
        public const int ClassServerSessionContainer = 284;
        public const int ObjectServerSessionContainer = 285;
        public const int ClassServerSession = 287;
        public const int ObjectNullServerSession = 288;
        public const int ServerSessionClientRID = 300;
        public const int ServerSessionRequest = 303;
        public const int ServerSessionResponse = 304;
        public const int ServerSessionVersion = 306;
        public const int LID_SessionVersionSystemPAOMString = 319;
        public const int ClassTypeInfo = 511;
        public const int ClassOMSTypeInfoContainer = 534;
        public const int ObjectOMSTypeInfoContainer = 537;
        public const int TextLibraryClassRID = 606;
        public const int TextLibraryOffsetArea = 608;
        public const int TextLibraryStringArea = 609;
        public const int ClassSubscription = 1001;
        public const int SubscriptionMissedSendings = 1002;
        public const int SubscriptionSubsystemError = 1003;
        public const int SubscriptionReferenceTriggerAndTransmitMode = 1005;
        public const int SystemLimits = 1037;
        public const int SubscriptionRouteMode = 1040;
        public const int SubscriptionActive = 1041;
        public const int Legitimate = 1846;
        public const int SubscriptionReferenceList = 1048;
        public const int SubscriptionCycleTime = 1049;
        public const int SubscriptionDelayTime = 1050;
        public const int SubscriptionDisabled = 1051;
        public const int SubscriptionCount = 1052;
        public const int SubscriptionCreditLimit = 1053;
        public const int SubscriptionTicks = 1054;
        public const int FreeItems = 1081;
        public const int SubscriptionFunctionClassId = 1082;
        public const int Filter = 1246;
        public const int FilterOperation = 1247;
        public const int AddressCount = 1249;
        public const int Address = 1250;
        public const int FilterValue = 1251;
        public const int ObjectQualifier = 1256;
        public const int ParentRID = 1257;
        public const int CompositionAID = 1258;
        public const int KeyQualifier = 1259;
        public const int TI_TComSize = 1502;
        public const int EffectiveProtectionLevel = 1842;
        public const int ActiveProtectionLevel = 1843;
        public const int CPUexecUnit_operatingStateReq = 2167;
        public const int PLCProgram_Class_Rid = 2520;
        public const int Block_BlockNumber = 2521;
        public const int DataInterface_InterfaceDescription = 2544;
        public const int DataInterface_LineComments = 2546;
        public const int DB_ValueInitial = 2548;
        public const int DB_ValueActual = 2550;
        public const int DB_InitialChanged = 2551;
        public const int DB_Class_Rid = 2574;
        public const int AlarmSubscriptionRef_AlarmDomain = 2659;
        public const int AlarmSubscriptionRef_itsAlarmSubsystem = 2660;
        public const int AlarmSubscriptionRef_Class_Rid = 2662;
        public const int AlarmSubsystem_itsUpdateRelevantDAI = 2667;
        public const int DAI_CPUAlarmID = 2670;
        public const int DAI_AllStatesInfo = 2671;
        public const int DAI_AlarmDomain = 2672;
        public const int DAI_Coming = 2673;
        public const int DAI_Going = 2677;
        public const int DAI_Class_Rid = 2681;
        public const int DAI_AlarmTexts_Rid = 2715;
        public const int AS_CGS_AllStatesInfo = 3474;
        public const int AS_CGS_Timestamp = 3475;
        public const int AS_CGS_AssociatedValues = 3476;
        // a4webdev #221: the CPU operating state. READ THE WHOLE COMMENT before using it.
        //
        // 3486 is a LID, not an attribute id. It is reached through an ItemAddress:
        //
        //     SymbolCrc     = 0
        //     AccessArea    = 52    NativeObjects_theCPUexecUnit_Rid
        //     AccessSubArea = 2237  CPUexecUnit_OperatingStateSubArea
        //     LID           = { 3486 }
        //
        // Values: 8 = RUN, 4 = STOP. The WRITE enum is different (03 = RUN, 01 = STOP) -
        // see CPUexecUnit_operatingStateReq. Reusing one mapping for both paths produces
        // code that compiles and lies.
        //
        // The same value is also delivered as member 3486 of struct 3481.
        //
        // HISTORY, because this id has now been wrong twice in opposite directions:
        //   1. It was first published as an ATTRIBUTE id. That was wrong - ReadAttributes
        //      addresses by attribute id and can never reach a LID, which is exactly why
        //      reads against it measured nothing on BOTH V3.0.2 and V4.6.
        //   2. It was then RETRACTED as "there is no 3486", on the grounds that the bytes
        //      `9b 1e` were item framing (code 0x9b + item ref 30). THAT retraction was
        //      itself wrong. In the #221 captures every top-level item uses code 0x92 with
        //      a raw UInt32 ref - 101 items, 101 times 0x92, never 0x9b - and the `9b 1e`
        //      bytes sit INSIDE a Datatype.Struct value, where ValueStruct.Deserialize
        //      reads them as a VLQ member id terminated by 0. They are the id 3486.
        //
        // So: the VALUE was always right; the ADDRESSING MODE was wrong. Do not delete this
        // constant again, and do not read it with ReadAttributes.
        //
        // Derived independently of those bytes, from TIA's own subscription-create frame
        // (CreateObject 0x04ca, attribute SubscriptionReferenceList 1048), parsed against
        // Subscriptions/Subscription.cs :: GetSubscriptionListArray, self-checked by the
        // array's declared element count and by each record's own field count. Identical in
        // all 6 such frames across all 8 captures.
        //
        // Full evidence: TiaCommander agents/research/findings/221-itemaddress-decode.md
        public const int CPUexecUnit_OperatingStateSubArea = 2237;
        public const int CPUexecUnit_OperatingStateLID = 3486;
        public const int CPUexecUnit_OperatingStateStruct = 3481;

        public const int AS_CGS_AckTimestamp = 3646;
        public const int ControllerArea_ValueInitial = 3735;
        public const int ControllerArea_ValueActual = 3736;
        public const int ControllerArea_RuntimeModified = 3737;
        public const int DAI_MessageType = 4079;
        public const int ASObjectES_Comment = 4288;
        public const int AlarmSubscriptionRef_AlarmDomain2 = 7731;
        public const int DAI_HmiInfo = 7813;
        public const int MultipleSTAI_Class_Rid = 7854;
        public const int MultipleSTAI_STAIs = 7859;
        public const int DAI_SequenceCounter = 7917;
        public const int AlarmSubscriptionRef_AlarmTextLanguages_Rid = 8181;
        public const int AlarmSubscriptionRef_SendAlarmTexts_Rid = 8173;
        public const int ReturnValue = 40305;
        public const int LID_LegitimationPayloadStruct = 40400;
        public const int LID_LegitimationPayloadType = 40401;
        public const int LID_LegitimationPayloadUsername = 40402;
        public const int LID_LegitimationPayloadPassword = 40403;

        public const int TI_BOOL = 0x02000000 + 1;
        public const int TI_BYTE = 0x02000000 + 2;
        public const int TI_CHAR = 0x02000000 + 3;
        public const int TI_WORD = 0x02000000 + 4;
        public const int TI_INT = 0x02000000 + 5;
        public const int TI_DWORD = 0x02000000 + 6;
        public const int TI_DINT = 0x02000000 + 7;
        public const int TI_REAL = 0x02000000 + 8;
        public const int TI_STRING = 0x02000000 + 19;
        public const int TI_LREAL = 0x02000000 + 48;
        public const int TI_USINT = 0x02000000 + 52;
        public const int TI_UINT = 0x02000000 + 53;
        public const int TI_UDINT = 0x02000000 + 54;
        public const int TI_SINT = 0x02000000 + 55;
        public const int TI_WCHAR = 0x02000000 + 61;
        public const int TI_WSTRING = 0x02000000 + 62;
        public const int TI_STRING_START = 0x020a0000;  // Start for String[0]
        public const int TI_STRING_END = 0x020affff;    // End (String[65535])
        public const int TI_WSTRING_START = 0x020b0000; // Start for WString[0]
        public const int TI_WSTRING_END = 0x020bffff;   // End (WString[65535])
    }
}
