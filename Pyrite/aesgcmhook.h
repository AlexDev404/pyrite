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
// as received.
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
// Replaced with: immediate return.
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
    // FALLBACK: if client disconnects immediately after handshake with no
    // 24-byte packets appearing, replace this body with WriteBit(0).
}

// ---------------------------------------------------------------------------
// InitializeAESBypass
//
// Locates FAESGCMHandlerComponent::Incoming and ::Outgoing via sigscan and
// replaces both with identity stubs.
//
// Signatures derived from Fortnite 17.50 (UE 4.26.1) FortniteClient-Win64-Shipping.exe
// Functions confirmed at sub_143F5FB68 (Incoming) and sub_143F6003C (Outgoing).
//
// Previous sig was too generic and grabbed an unrelated function with the
// same push sequence (runtime offset 0xCC8304 instead of 0x3F5FB68). The new
// sigs extend into the unique function body where register choices diverge:
//
// Incoming distinctive bytes:
//   48 8D 6C 24 D9        lea rbp, [rsp-0x27]    frame cookie D9 unique to Incoming
//   48 81 EC 90 00 00 00  sub rsp, 0x90
//   48 8B 01              mov rax, [rcx]         vtable load
//   48 8D 1D ?? ?? ?? ??  lea rbx, [rel STAT_PacketHandler_AESGCM_Decrypt]
//   45 33 ED              xor r13d, r13d         r13 (vs r15 in Outgoing)
//   48 8B FA              mov rdi, rdx
//
// Outgoing distinctive bytes:
//   48 8D 6C 24 B0        lea rbp, [rsp-0x50]    frame cookie B0 unique to Outgoing
//   48 81 EC 50 01 00 00  sub rsp, 0x150
//   48 8B 01              mov rax, [rcx]
//   4C 8D 25 ?? ?? ?? ??  lea r12, [rel STAT_PacketHandler_AESGCM_Encrypt]
//   45 33 FF              xor r15d, r15d         r15 (vs r13 in Incoming)
//   48 8B DA              mov rbx, rdx
// ---------------------------------------------------------------------------
inline bool InitializeAESBypass()
{
    const __int64 incomingAddr = Memcury::Scanner::FindPattern(
        "48 89 5C 24 10 55 56 57 41 54 41 55 41 56 41 57 " // save rbx/rbp, push rsi-r15
        "48 8D 6C 24 D9 "                                  // lea rbp, [rsp-0x27]
        "48 81 EC 90 00 00 00 "                            // sub rsp, 0x90
        "48 8B 01 "                                        // mov rax, [rcx]
        "48 8D 1D ? ? ? ? "                                // lea rbx, [rel STAT_Decrypt]
        "45 33 ED "                                        // xor r13d, r13d
        "48 8B FA"                                         // mov rdi, rdx
    ).Get();

    if (!incomingAddr)
    {
        std::cout << "[AESBypass] sigscan failed for FAESGCMHandlerComponent::Incoming\n";
        return false;
    }

    const __int64 outgoingAddr = Memcury::Scanner::FindPattern(
        "48 89 5C 24 10 55 56 57 41 54 41 55 41 56 41 57 " // prologue
        "48 8D 6C 24 B0 "                                  // lea rbp, [rsp-0x50]
        "48 81 EC 50 01 00 00 "                            // sub rsp, 0x150
        "48 8B 01 "                                        // mov rax, [rcx]
        "4C 8D 25 ? ? ? ? "                                // lea r12, [rel STAT_Encrypt]
        "45 33 FF "                                        // xor r15d, r15d
        "48 8B DA"                                         // mov rbx, rdx
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
