#pragma once
// ---------------------------------------------------------------------------
// Pyrite bunch tracing hooks.
//
// Two hooks, both on Fortnite 17.50 UNetConnection internals:
//   - ReceivedRawPacket(this, void* Data, int32 Count): outer entry,
//     called once per UDP recvfrom. Trivially verifiable against WSCAP logs.
//   - ReceivedPacket(this, FBitReader& Reader, bool bIsReinjected): inner
//     entry, called after PacketHandler chain. Dumps the FBitReader struct
//     raw so we can identify the right offsets for buffer/Num/Pos.
//
// Function locations are hardcoded as RVAs from Binja analysis (image base
// 0x140000000):
//   ReceivedPacket    @ 0x00F79464
//   ReceivedRawPacket @ 0x012C3304
// ---------------------------------------------------------------------------
#include <Windows.h>
#include <cstdint>
#include <cstdio>
#include <MinHook/MinHook.h>

namespace BunchHook
{
    constexpr uintptr_t RVA_ReceivedPacket    = 0x00F79464;
    constexpr uintptr_t RVA_ReceivedRawPacket = 0x012C3304;
    // FName-from-bit-stream read. Found via HLIL of sub_140F79464:
    //   zmm1_3, zmm2_2 = sub_140e715d0(arg2, &var_2c0, zmm2_1, zmm0_1, zmm1_2)
    // Real signature is (FArchive*, FName*) — the zmm regs are compiler
    // pass-through artifacts.
    constexpr uintptr_t RVA_FNameRead = 0x00E715D0;

    // FBitReader struct offsets, per HLIL (arg2 treated as qword-indexed):
    //   arg2[0x13] (= byte +0x98) -> Buffer.Data
    //   arg2[0x15] (= byte +0xA8) -> Num bits
    //   arg2[0x16] (= byte +0xB0) -> Pos bits
    constexpr size_t FBR_BUFFER_OFFSET = 0x98;
    constexpr size_t FBR_NUM_OFFSET    = 0xA8;
    constexpr size_t FBR_POS_OFFSET    = 0xB0;

    inline int64_t GetReaderPos(void* r) { return *reinterpret_cast<int64_t*>(reinterpret_cast<uint8_t*>(r) + FBR_POS_OFFSET); }
    inline int64_t GetReaderNum(void* r) { return *reinterpret_cast<int64_t*>(reinterpret_cast<uint8_t*>(r) + FBR_NUM_OFFSET); }

    using ReceivedPacket_t    = void (__fastcall *)(void* thisConn, void* bitReader, bool bIsReinjected);
    using ReceivedRawPacket_t = void (__fastcall *)(void* thisConn, void* data, int32_t count);
    using FNameRead_t         = void* (__fastcall *)(void* thisAr, void* outName);

    inline ReceivedPacket_t    ReceivedPacket_Orig    = nullptr;
    inline ReceivedRawPacket_t ReceivedRawPacket_Orig = nullptr;
    inline FNameRead_t         FNameRead_Orig         = nullptr;

    inline thread_local bool g_InRecv = false;
    inline thread_local bool g_InRaw  = false;
    inline thread_local void* g_ActiveReader = nullptr; // populated while inside ReceivedPacket

    // -----------------------------------------------------------------------
    // ReceivedRawPacket detour: dump (data, count). Direct comparison against
    // WSCAP recvfrom logs confirms we hit the right function.
    // -----------------------------------------------------------------------
    inline void __fastcall ReceivedRawPacket_Detour(void* thisConn, void* data, int32_t count)
    {
        if (g_InRaw) { ReceivedRawPacket_Orig(thisConn, data, count); return; }
        g_InRaw = true;

        std::printf("[rawpkt] conn=%p data=%p count=%d bytes:", thisConn, data, count);
        if (data && count > 0 && count < 4096)
        {
            auto* b = reinterpret_cast<uint8_t*>(data);
            for (int i = 0; i < count; ++i) std::printf(" %02X", b[i]);
        }
        std::printf("\n");
        std::fflush(stdout);

        ReceivedRawPacket_Orig(thisConn, data, count);
        g_InRaw = false;
    }

    // -----------------------------------------------------------------------
    // ReceivedPacket detour: dump the first 0x40 bytes of the FBitReader at
    // ENTER (when Reader is populated) and LEAVE (after Fortnite's parser
    // consumed bits). Diffing the dumps tells us:
    //   - Buffer pointer offset (the address of packet bytes)
    //   - Buffer Num offset (byte count)
    //   - Num bits offset (total bits = Count * 8 - trailing-magic)
    //   - Pos bits offset (read position, advances by parsed bunch sizes)
    // -----------------------------------------------------------------------
    inline void DumpStruct(const char* tag, void* p)
    {
        auto* base = reinterpret_cast<uint8_t*>(p);
        std::printf("[recvpkt] %s p=%p Pos=%lld Num=%lld\n",
                    tag, p,
                    (long long)GetReaderPos(p),
                    (long long)GetReaderNum(p));
        // Dump out to 0xC0 so we can see Pos (at 0xB0) and a bit beyond.
        for (int i = 0; i < 0xC0; i += 8)
        {
            uint64_t q = *reinterpret_cast<uint64_t*>(base + i);
            std::printf("[recvpkt]   +0x%02X: %016llX\n",
                        i, (unsigned long long)q);
        }
        std::fflush(stdout);
    }

    inline void __fastcall ReceivedPacket_Detour(void* thisConn, void* bitReader, bool bIsReinjected)
    {
        if (g_InRecv) { ReceivedPacket_Orig(thisConn, bitReader, bIsReinjected); return; }
        g_InRecv = true;
        g_ActiveReader = bitReader;

        int64_t entryPos = GetReaderPos(bitReader);
        int64_t totalNum = GetReaderNum(bitReader);
        std::printf("[recvpkt] ENTER Pos=%lld Num=%lld (bitsLeft=%lld)\n",
                    (long long)entryPos, (long long)totalNum,
                    (long long)(totalNum - entryPos));
        std::fflush(stdout);

        ReceivedPacket_Orig(thisConn, bitReader, bIsReinjected);

        int64_t exitPos = GetReaderPos(bitReader);
        std::printf("[recvpkt] LEAVE Pos=%lld (consumed %lld bits)\n",
                    (long long)exitPos, (long long)(exitPos - entryPos));
        std::fflush(stdout);

        g_ActiveReader = nullptr;
        g_InRecv = false;
    }

    // -----------------------------------------------------------------------
    // FName-read detour. Only logs when called from inside ReceivedPacket
    // (g_ActiveReader matches). Captures the bit position delta — this tells
    // us how many wire bits the FName actually consumed.
    // -----------------------------------------------------------------------
    inline void* __fastcall FNameRead_Detour(void* thisAr, void* outName)
    {
        const bool relevant = (g_InRecv && thisAr == g_ActiveReader);
        int64_t posBefore = relevant ? GetReaderPos(thisAr) : 0;

        void* ret = FNameRead_Orig(thisAr, outName);

        if (relevant)
        {
            int64_t posAfter = GetReaderPos(thisAr);
            // outName layout for FName is typically: u32 ComparisonIndex, u32 Number
            uint32_t cmpIdx = outName ? *reinterpret_cast<uint32_t*>(outName) : 0;
            uint32_t number = outName ? *reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(outName) + 4) : 0;
            std::printf("[fnamerd] Pos %lld -> %lld (took %lld bits) name.cmp=%u name.num=%u\n",
                        (long long)posBefore, (long long)posAfter,
                        (long long)(posAfter - posBefore),
                        (unsigned)cmpIdx, (unsigned)number);
            std::fflush(stdout);
        }
        return ret;
    }

    // -----------------------------------------------------------------------
    inline bool Install()
    {
        HMODULE mod = GetModuleHandleA(nullptr);
        auto base = reinterpret_cast<uintptr_t>(mod);

        void* recvPacketAddr    = reinterpret_cast<void*>(base + RVA_ReceivedPacket);
        void* recvRawPacketAddr = reinterpret_cast<void*>(base + RVA_ReceivedRawPacket);
        void* fnameReadAddr     = reinterpret_cast<void*>(base + RVA_FNameRead);

        std::printf("[bunchhook] module base=%p\n", mod);
        std::printf("[bunchhook] ReceivedPacket    @ %p (RVA 0x%llX)\n",
                    recvPacketAddr, (unsigned long long)RVA_ReceivedPacket);
        std::printf("[bunchhook] ReceivedRawPacket @ %p (RVA 0x%llX)\n",
                    recvRawPacketAddr, (unsigned long long)RVA_ReceivedRawPacket);
        std::printf("[bunchhook] FNameRead         @ %p (RVA 0x%llX)\n",
                    fnameReadAddr, (unsigned long long)RVA_FNameRead);

        MH_Initialize();

        auto installOne = [](const char* name, void* target, void* detour, void** ppOrig) -> bool {
            MH_STATUS s = MH_CreateHook(target, detour, ppOrig);
            if (s != MH_OK && s != MH_ERROR_ALREADY_CREATED) {
                std::printf("[bunchhook] %s: MH_CreateHook failed (%d)\n", name, (int)s);
                return false;
            }
            s = MH_EnableHook(target);
            if (s != MH_OK) {
                std::printf("[bunchhook] %s: MH_EnableHook failed (%d)\n", name, (int)s);
                return false;
            }
            std::printf("[bunchhook] %s: trampoline -> %p\n", name, *ppOrig);
            return true;
        };

        bool ok = true;
        ok &= installOne("ReceivedRawPacket",
                         recvRawPacketAddr,
                         reinterpret_cast<void*>(&ReceivedRawPacket_Detour),
                         reinterpret_cast<void**>(&ReceivedRawPacket_Orig));
        ok &= installOne("ReceivedPacket",
                         recvPacketAddr,
                         reinterpret_cast<void*>(&ReceivedPacket_Detour),
                         reinterpret_cast<void**>(&ReceivedPacket_Orig));
        ok &= installOne("FNameRead",
                         fnameReadAddr,
                         reinterpret_cast<void*>(&FNameRead_Detour),
                         reinterpret_cast<void**>(&FNameRead_Orig));
        return ok;
    }
}

inline bool InitializeBunchHook() { return BunchHook::Install(); }
