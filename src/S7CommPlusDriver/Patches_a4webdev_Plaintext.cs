#region License
/******************************************************************************
 * S7CommPlusDriver - a4webdev fork patch
 *
 * Plaintext (non-TLS) S7CommPlus session, opt-in.
 *
 * A CPU below the secure-communication floor (S7-1200 < V4.3, S7-1500 < V2.9)
 * REFUSES the InitSsl request: it answers with functioncode Error2 (0x05a9)
 * instead of InitSsl (0x05b3). Upstream treats that as fatal, so those CPUs are
 * unreachable even though the protocol above the transport is identical.
 *
 * They are not, in fact, unreachable. The engineering tool offers InitSsl to the
 * same CPU, is refused the same way, and then simply CARRIES ON IN THE CLEAR -
 * CreateObject, session setup and every subsequent request are plain
 * S7CommPlus over TPKT/COTP with no TLS record anywhere in the exchange.
 *
 * So this is a transport-layer branch, not a new protocol. S7Client already
 * contains the plaintext path and already uses it: with m_SslActive false,
 * Send() goes to SendIsoPacket() and the receive thread delivers straight to
 * OnDataReceived - which is exactly how the InitSsl request itself is sent
 * before TLS is ever activated. The only change needed is to NOT call
 * SslActivate() when the CPU has told us it cannot.
 *
 * OPT-IN, DEFAULT OFF, AND NEVER AN AUTOMATIC FALLBACK. An automatic downgrade
 * would strip TLS from a CPU that supports it, triggered by a single response
 * byte an attacker on the path can forge. The caller must ask for this
 * explicitly, and it is only honoured when the CPU actually refused.
 *
 * LGPL-3.0-or-later, (C) 2023 Thomas Wiens. Modifications (C) 2026 a4webdev.
 /****************************************************************************/
#endregion

using System;
using System.IO;

namespace S7CommPlusDriver
{
    public partial class S7CommPlusConnection
    {
        /// <summary>
        /// Opt in to continuing WITHOUT encryption when the CPU refuses InitSsl.
        /// Default false.
        ///
        /// Set this only for a CPU known to be below the secure-communication
        /// floor. It does not weaken a CPU that supports TLS: the plaintext path
        /// is taken only after that CPU has answered InitSsl with Error2, and a
        /// CPU capable of TLS does not send that.
        ///
        /// It is still a downgrade, so it is never selected on the driver's own
        /// initiative - hence a property the caller must set rather than a
        /// silent fallback.
        /// </summary>
        public bool AllowPlaintextSession { get; set; }

        /// <summary>
        /// True once a session has actually continued unencrypted. Distinct from
        /// <see cref="AllowPlaintextSession"/>, which is only permission: a
        /// modern CPU accepts InitSsl, so permission stays granted while this
        /// stays false and the session is fully encrypted.
        ///
        /// Callers that care whether their traffic is protected must read THIS,
        /// not the permission flag.
        /// </summary>
        public bool PlaintextSessionActive { get; private set; }

        /// <summary>
        /// Whether the effective protection level was actually read from the CPU.
        /// True on any CPU that implements attribute EffectiveProtectionLevel (1842).
        ///
        /// A pre-V4.3 CPU does not implement it, so the value stays at its default of
        /// 0 - which would otherwise be indistinguishable from a genuine reading of
        /// "full access, no password". Callers that display or reason about protection
        /// must check this first and report "unknown" rather than "unprotected".
        ///
        /// Defaults to true so existing callers on supported firmware are unaffected;
        /// only the plaintext path clears it.
        /// </summary>
        public bool ProtectionLevelKnown { get; internal set; } = true;

        /// <summary>
        /// Read the functioncode out of a response PDU without consuming it, so
        /// Connect() can tell "the CPU refused InitSsl" apart from "the response
        /// was malformed". InitSslResponse.DeserializeFromPdu returns null for
        /// both, and that conflation is what made a refusal indistinguishable
        /// from a protocol error.
        ///
        /// Layout, matching DeserializeFromPdu's own prologue: the protocol
        /// version is written to the stream first, then opcode, then a reserved
        /// word, then the functioncode.
        ///   [0]      ProtocolVersion
        ///   [1]      Opcode
        ///   [2..3]   Reserved
        ///   [4..5]   Functioncode
        /// The stream position is restored to 0 before returning either way.
        /// </summary>
        private static bool TryPeekResponseFunctioncode(MemoryStream pdu, out UInt16 function)
        {
            function = 0;
            if (pdu == null) return false;
            try
            {
                pdu.Position = 0;
                if (pdu.Length < 6) return false;

                byte protocolVersion, opcode;
                UInt16 reserved;
                S7p.DecodeByte(pdu, out protocolVersion);
                S7p.DecodeByte(pdu, out opcode);
                if (opcode != Opcode.Response) return false;
                S7p.DecodeUInt16(pdu, out reserved);
                S7p.DecodeUInt16(pdu, out function);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
            finally
            {
                try { pdu.Position = 0; } catch (Exception) { }
            }
        }

        /// <summary>
        /// Decide what a failed InitSslResponse deserialization means.
        /// Returns true when the session may continue in the clear, and sets
        /// <see cref="PlaintextSessionActive"/> as a side effect.
        ///
        /// Kept here rather than inline in Connect() so the upstream method
        /// carries one readable branch instead of the whole rationale.
        /// </summary>
        private bool TryContinueWithoutEncryption()
        {
            UInt16 function;
            bool refused = TryPeekResponseFunctioncode(m_ReceivedPDU, out function)
                           && function == Functioncode.Error2;

            if (!refused)
            {
                // Not a refusal - a genuinely malformed or unexpected response.
                // Nothing to fall back to.
                return false;
            }

            if (!AllowPlaintextSession)
            {
                Console.WriteLine("S7CommPlusConnection - Connect: the CPU REFUSED InitSsl (Error2 0x"
                    + function.ToString("X04") + "). It is below the secure-communication floor "
                    + "(S7-1200 < V4.3 / S7-1500 < V2.9). Set AllowPlaintextSession = true to "
                    + "continue UNENCRYPTED against this CPU.");
                return false;
            }

            PlaintextSessionActive = true;
            Console.WriteLine("S7CommPlusConnection - Connect: the CPU REFUSED InitSsl (Error2 0x"
                + function.ToString("X04") + "). AllowPlaintextSession is set, so this session "
                + "CONTINUES WITHOUT ENCRYPTION. Traffic is readable on the wire.");
            return true;
        }
    }
}
