#pragma once
#include <Windows.h>
#include <iostream>
#include "memcury.h"

// Forward-declare the Hook() helper defined in dllmain.cpp
void Hook(void* Target, void* Detour);

// ---------------------------------------------------------------------------
// FOodleHandlerComponent::Incoming -- identity replacement
//
// Original behaviour: decompresses the incoming packet payload in-place using
// OodleNetwork1UDP_Decode, shrinking the FBitReader's view to the
// decompressed data.
//
// Replaced with: immediate return, leaving the FBitReader bitstream exactly
// as received. Small ack-only packets already bypass Oodle's size threshold
// (net.OodleMinSizeForCompression=19) and arrive uncompressed -- this hook
// handles the larger data-carrying packets (NMT_Hello bunches etc.) that
// would otherwise arrive as compressed garbage.
//
// Calling convention (x64 __thiscall == __fastcall):
//   RCX = this  (FOodleHandlerComponent*)
//   RDX = Packet (FBitReader&)
// ---------------------------------------------------------------------------
inline void __fastcall OodleIncoming_Hook(void* /*thisPtr*/, void* /*packet*/)
{
    // Intentionally empty -- packet passes through unmodified.
}

// ---------------------------------------------------------------------------
// FOodleHandlerComponent::Outgoing -- identity replacement
//
// Original behaviour: compresses the outgoing packet payload in-place using
// OodleNetwork1UDP_Encode and writes a compression header bit into the
// FBitWriter stream.
//
// Replaced with: immediate return. The standalone server has no matching
// Oodle state and never writes a compression marker bit, so skipping
// compression keeps the wire format symmetric.
//
// Calling convention:
//   RCX = this  (FOodleHandlerComponent*)
//   RDX = Packet (FBitWriter&)
//   R8  = Traits (FOutPacketTraits&)
// ---------------------------------------------------------------------------
inline void __fastcall OodleOutgoing_Hook(void* /*thisPtr*/, void* /*packet*/,
                                          void* /*traits*/)
{
    // Intentionally empty -- packet passes through unmodified.
    //
    // FALLBACK: if the standalone rejects packets because it expects a
    // compression header bit, write a single 0 bit instead of skipping.
}

// ---------------------------------------------------------------------------
// InitializeOodleBypass
//
// Locates FOodleHandlerComponent::Incoming and ::Outgoing via sigscan and
// replaces both with identity stubs. Call this from Main() in dllmain.cpp
// alongside InitializeAESBypass().
//
// Signatures derived from Fortnite 17.50 (UE 4.26.1) FortniteClient-Win64-Shipping.exe
//
// Incoming prologue  (sub_144143130):
//   48 89 5C 24 ??         mov  [rsp+arg_8], rbx
//   48 89 6C 24 ??         mov  [rsp+arg_10], rbp
//   56 57 41 54 41 55 41 56  push rsi/rdi/r12/r13/r14
//   48 83 EC 30            sub  rsp, 0x30          (frame size distinguishes Incoming)
//   80 79 28 00            cmp  byte [rcx+0x28], 0 (state check)
//
// Outgoing prologue  (sub_144144608):
//   48 89 5C 24 ??         mov  [rsp+arg_8], rbx
//   48 89 6C 24 ??         mov  [rsp+arg_10], rbp
//   48 89 74 24 ??         mov  [rsp+arg_18], rsi
//   57 41 54 41 55 41 56 41 57  push rdi/r12/r13/r14/r15
//   48 83 EC 40            sub  rsp, 0x40          (larger frame for compression scratch)
//   80 79 28 00            cmp  byte [rcx+0x28], 0
//
// If either sig drifts in a later patch, re-derive from the IAT xrefs in IDA:
//   OodleNetwork1UDP_Decode  -> one caller = Incoming
//   OodleNetwork1UDP_Encode  -> one caller = Outgoing
// ---------------------------------------------------------------------------
inline bool InitializeOodleBypass()
{
    const __int64 incomingAddr = Memcury::Scanner::FindPattern(
        "48 89 5C 24 ? 48 89 6C 24 ? "
        "56 57 41 54 41 55 41 56 "
        "48 83 EC 30 "
        "80 79 28 00"
    ).Get();

    if (!incomingAddr)
    {
        std::cout << "[OodleBypass] sigscan failed for FOodleHandlerComponent::Incoming\n";
        return false;
    }

    const __int64 outgoingAddr = Memcury::Scanner::FindPattern(
        "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? "
        "57 41 54 41 55 41 56 41 57 "
        "48 83 EC 40 "
        "80 79 28 00"
    ).Get();

    if (!outgoingAddr)
    {
        std::cout << "[OodleBypass] sigscan failed for FOodleHandlerComponent::Outgoing\n";
        return false;
    }

    std::cout << "[OodleBypass] Incoming @ " << reinterpret_cast<void*>(incomingAddr) << '\n';
    std::cout << "[OodleBypass] Outgoing @ " << reinterpret_cast<void*>(outgoingAddr) << '\n';

    Hook(reinterpret_cast<void*>(incomingAddr), OodleIncoming_Hook);
    Hook(reinterpret_cast<void*>(outgoingAddr), OodleOutgoing_Hook);

    std::cout << "[OodleBypass] Oodle compress/decompress hooks installed.\n";
    return true;
}
