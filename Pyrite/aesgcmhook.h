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
// ---------------------------------------------------------------------------
// OpenSSL GCM wrappers -- belt-and-suspenders bypass
//
// Even with FAESGCMHandlerComponent::Outgoing/Incoming neutered, some packet
// paths reach the lower-level wrappers directly:
//   sub_143F60EAC = STAT_OpenSSL_AES256_GCM_Encrypt wrapper
//   sub_143F60B44 = STAT_OpenSSL_AES256_GCM_Decrypt wrapper
//
// Both return their output-buffer pointer (rdx == the 2nd arg) in rax, so
// the detour returns that to keep callers happy.
// ---------------------------------------------------------------------------
inline void* __fastcall OpenSSLEncrypt_Hook(void* /*ctx*/, void* outBuf,
                                            void* /*a3*/, void* /*a4*/)
{
    return outBuf;  // mimic the function's normal "return r14 (rdx)" tail.
}

inline void* __fastcall OpenSSLDecrypt_Hook(void* /*ctx*/, void* outBuf,
                                            void* /*a3*/, void* /*a4*/)
{
    return outBuf;  // mimic the function's normal "return rsi (rdx)" tail.
}

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

    // ----- Lower-level OpenSSL wrappers --------------------------------------
    // Encrypt (sub_143F60EAC): 3 rsp-relative saves before pushes, frame 0x60,
    // zeroes r15d. All immediate displacements wildcarded.
    const __int64 sslEncryptAddr = Memcury::Scanner::FindPattern(
        "48 89 5C 24 ? "                           // mov [rsp+disp8], rbx
        "4C 89 44 24 ? "                           // mov [rsp+disp8], r8
        "48 89 4C 24 ? "                           // mov [rsp+disp8], rcx
        "55 56 57 41 54 41 55 41 56 41 57 "        // push rbp/rsi/rdi/r12-r15
        "? ? ? "                                   // mov rbp, rsp
        "48 83 EC 60 "                             // sub rsp, 0x60   (Encrypt frame)
        "4C 8B 65 ? "                              // mov r12, [rbp+disp8]
        "48 8D 3D ? ? ? ? "                        // lea rdi, [STAT_Encrypt]
        "45 33 FF"                                 // xor r15d, r15d  (Encrypt)
    ).Get();

    // Decrypt (sub_143F60B44): 2 rsp-relative saves before pushes, frame 0x50,
    // zeroes edi.
    const __int64 sslDecryptAddr = Memcury::Scanner::FindPattern(
        "48 89 5C 24 ? "                           // mov [rsp+disp8], rbx
        "48 89 4C 24 ? "                           // mov [rsp+disp8], rcx
        "55 56 57 41 54 41 55 41 56 41 57 "        // push rbp/rsi/rdi/r12-r15
        "? ? ? "                                   // mov rbp, rsp
        "48 83 EC 50 "                             // sub rsp, 0x50   (Decrypt frame)
        "48 8B 45 ? "                              // mov rax, [rbp+disp8]
        "4C 8D 3D ? ? ? ? "                        // lea r15, [STAT_Decrypt]
        "4C 8B 6D ? "                              // mov r13, [rbp+disp8]
        "48 8D 4D ? "                              // lea rcx, [rbp+disp8]
        "33 FF"                                    // xor edi, edi   (Decrypt)
    ).Get();

    if (sslEncryptAddr)
    {
        std::cout << "[AESBypass] OpenSSL_Encrypt @ "
                  << reinterpret_cast<void*>(sslEncryptAddr) << '\n';
        Hook(reinterpret_cast<void*>(sslEncryptAddr), OpenSSLEncrypt_Hook);
    }
    else
    {
        std::cout << "[AESBypass] sigscan failed for OpenSSL AES256_GCM_Encrypt\n";
    }

    if (sslDecryptAddr)
    {
        std::cout << "[AESBypass] OpenSSL_Decrypt @ "
                  << reinterpret_cast<void*>(sslDecryptAddr) << '\n';
        Hook(reinterpret_cast<void*>(sslDecryptAddr), OpenSSLDecrypt_Hook);
    }
    else
    {
        std::cout << "[AESBypass] sigscan failed for OpenSSL AES256_GCM_Decrypt\n";
    }

    std::cout << "[AESBypass] AES-GCM encrypt/decrypt hooks installed.\n";
    return true;
}
