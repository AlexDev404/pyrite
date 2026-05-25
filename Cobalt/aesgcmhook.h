#pragma once
#include <Windows.h>
#include <iostream>
#include "memcury.h"

// Forward-declare the Hook() helper defined in dllmain.cpp
void Hook(void* Target, void* Detour);

// ---------------------------------------------------------------------------
// FAESGCMHandlerComponent::Incoming -- identity replacement
//
// Original behaviour: decrypts the incoming packet payload in-place using
// AES-GCM and advances the FBitReader position past the encryption header.
//
// Replaced with: immediate return, leaving the FBitReader bitstream exactly
// as received. The standalone server does not run UE4's PacketHandler chain
// and never writes an encryption marker bit, so this stays symmetric.
//
// Calling convention (x64 __thiscall == __fastcall):
//   RCX = this  (FAESGCMHandlerComponent*)
//   RDX = Packet (FBitReader&)
// ---------------------------------------------------------------------------
inline void __fastcall AESIncoming_Hook(void* /*thisPtr*/, void* /*packet*/)
{
    // Intentionally empty -- packet passes through unmodified.
}

// ---------------------------------------------------------------------------
// FAESGCMHandlerComponent::Outgoing -- identity replacement
//
// Original behaviour: encrypts the outgoing packet payload in-place and
// writes a 1-bit "encrypted" marker into the FBitWriter stream.
//
// Replaced with: immediate return. Without the encryption marker bit the
// standalone server (which does not run an AES handler) will read PackedHeader
// directly after the magic+handshake preamble.
//
// Calling convention:
//   RCX = this  (FAESGCMHandlerComponent*)
//   RDX = Packet (FBitWriter&)
//   R8  = Traits (FOutPacketTraits&)
// ---------------------------------------------------------------------------
inline void __fastcall AESOutgoing_Hook(void* /*thisPtr*/, void* /*packet*/,
                                        void* /*traits*/)
{
    // Intentionally empty -- packet passes through unmodified.
    //
    // FALLBACK: if the client disconnects immediately after handshake with no
    // 24-byte packets appearing, Fortnite has a "drop if marker bit absent"
    // check. In that case replace this body with a single WriteBit(0) call
    // to write a 0 marker bit instead of skipping entirely. Don't change
    // this preemptively -- only if you see that specific disconnect pattern.
}

// ---------------------------------------------------------------------------
// InitializeAESBypass
//
// Locates FAESGCMHandlerComponent::Incoming and ::Outgoing via sigscan and
// replaces both with identity stubs. Call this from Main() in dllmain.cpp
// after InitializeExitHook() and before any network activity begins.
//
// Signatures derived from Fortnite 17.50 (UE 4.26.1) -- FortniteClient-Win64-Shipping.exe
//
// Incoming prologue (sub_143f5fb68):
//   48 89 5C 24 10            mov  [rsp+0x10], rbx
//   55 56 57 41 54 41 55      push rbp/rsi/rdi/r12/r13
//   41 56 41 57               push r14/r15
//   48 8D 6C 24 D9            lea  rbp, [rsp-0x27]   <- frame cookie; D9 is unique to Incoming
//   48 81 EC 90 00 00 00      sub  rsp, 0x90
//
// Outgoing prologue (sub_143f6003c):
//   identical save sequence, then:
//   48 8D 6C 24 B0            lea  rbp, [rsp-0x50]   <- B0 distinguishes Outgoing from Incoming
//   48 81 EC 50 01 00 00      sub  rsp, 0x150         <- larger frame (crypto scratch space)
//
// If either sig drifts in a later 17.x patch, re-derive from the two strings
// that anchor these functions:
//   Incoming: u"FAESGCMHandlerComponent::Incoming: received encrypted packet before key was set, ignoring."
//   Outgoing: u"FAESGCMHandlerComponent::Outgoing: failed to write encryption bit."
// Both survive in the .rdata of shipping builds.
// ---------------------------------------------------------------------------
inline bool InitializeAESBypass()
{
    // -----------------------------------------------------------------------
    // Locate Incoming
    // -----------------------------------------------------------------------
    const __int64 incomingAddr = Memcury::Scanner::FindPattern(
        "48 89 5C 24 10 55 56 57 41 54 41 55 41 56 41 57 "
        "48 8D 6C 24 D9 "           // lea rbp, [rsp-0x27]  -- frame size unique to Incoming
        "48 81 EC 90 00 00 00"      // sub rsp, 0x90
    ).Get();

    if (!incomingAddr)
    {
        std::cout << "[AESBypass] sigscan failed for FAESGCMHandlerComponent::Incoming\n";
        return false;
    }

    // -----------------------------------------------------------------------
    // Locate Outgoing
    // -----------------------------------------------------------------------
    const __int64 outgoingAddr = Memcury::Scanner::FindPattern(
        "48 89 5C 24 10 55 56 57 41 54 41 55 41 56 41 57 "
        "48 8D 6C 24 B0 "           // lea rbp, [rsp-0x50]  -- frame size unique to Outgoing
        "48 81 EC 50 01 00 00"      // sub rsp, 0x150
    ).Get();

    if (!outgoingAddr)
    {
        std::cout << "[AESBypass] sigscan failed for FAESGCMHandlerComponent::Outgoing\n";
        return false;
    }

    std::cout << "[AESBypass] Incoming @ " << reinterpret_cast<void*>(incomingAddr) << '\n';
    std::cout << "[AESBypass] Outgoing @ " << reinterpret_cast<void*>(outgoingAddr) << '\n';

    Hook(reinterpret_cast<void*>(incomingAddr), AESIncoming_Hook);
    Hook(reinterpret_cast<void*>(outgoingAddr), AESOutgoing_Hook);

    std::cout << "[AESBypass] AES-GCM encrypt/decrypt hooks installed.\n";
    return true;
}
