#pragma once
// ---------------------------------------------------------------------------
// Pyrite LogNetTraffic verbosity flip.
//
// FLogCategoryBase layout (Engine/Source/Runtime/Core/Public/Logging/LogCategory.h):
//   +0x00  ELogVerbosity::Type Verbosity        (uint8 -- runtime threshold)
//   +0x01  ELogVerbosity::Type DefaultVerbosity (uint8)
//   +0x02  ELogVerbosity::Type CompileTimeVerbosity (uint8)
//   ...
//
// Category struct addresses came from Binja by walking each registrar
// function (sub_140a9c010, sub_140a9c060, sub_140a9c150) and reading the
// LEA into RCX before the call to FLogCategoryBase::ctor. Image base
// 0x140000000.
// ---------------------------------------------------------------------------
#include <Windows.h>
#include <cstdint>
#include <cstdio>

namespace LogHook
{
    constexpr uintptr_t RVA_LogNet           = 0x099AA288;
    constexpr uintptr_t RVA_LogNetDormancy   = 0x099AA2D8;
    constexpr uintptr_t RVA_LogNetTraffic    = 0x099AA2B8;
    constexpr uintptr_t RVA_LogHandshake     = 0x099AF240;
    constexpr uintptr_t RVA_PacketHandlerLog = 0x099A81C0;

    enum ELogVerbosity : uint8_t
    {
        Verbose     = 6,
        VeryVerbose = 7,
    };

    inline void Bump(const char* name, uintptr_t rva, uint8_t newV)
    {
        auto base = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));
        auto* cat = reinterpret_cast<uint8_t*>(base + rva);
        DWORD oldProt = 0;
        VirtualProtect(cat, 4, PAGE_READWRITE, &oldProt);
        uint8_t oldV   = cat[0];
        uint8_t oldDef = cat[1];
        uint8_t oldCT  = cat[2];
        cat[0] = newV;
        VirtualProtect(cat, 4, oldProt, &oldProt);
        std::printf("[loghook] %s @ %p: V=%u->%u Default=%u Compile=%u\n",
                    name, cat, oldV, newV, oldDef, oldCT);
    }
}

inline bool InitializeLogVerbosityFlip()
{
    LogHook::Bump("LogNet",           LogHook::RVA_LogNet,           LogHook::VeryVerbose);
    LogHook::Bump("LogNetTraffic",    LogHook::RVA_LogNetTraffic,    LogHook::VeryVerbose);
    LogHook::Bump("LogNetDormancy",   LogHook::RVA_LogNetDormancy,   LogHook::VeryVerbose);
    LogHook::Bump("LogHandshake",     LogHook::RVA_LogHandshake,     LogHook::VeryVerbose);
    LogHook::Bump("PacketHandlerLog", LogHook::RVA_PacketHandlerLog, LogHook::VeryVerbose);
    return true;
}
