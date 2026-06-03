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

    // FName::AppendString(const FName*, FString&) — resolves ComparisonIndex to string.
    // RVA from Dumpspace OFFSET_APPENDSTRING / CppSDK Basic.hpp Offsets::AppendString.
    constexpr uintptr_t RVA_AppendString = 0x00E8B130;

    // UNetConnection::Driver offset (CppSDK Engine_classes.hpp UNetConnection +0x58)
    constexpr size_t OFF_NetConn_Driver = 0x58;
    // UNetDriver::NetDriverName offset (CppSDK Engine_classes.hpp UNetDriver +0x190)
    constexpr size_t OFF_NetDriver_Name = 0x190;
    // FName-from-bit-stream read. Found via HLIL of sub_140F79464:
    //   zmm1_3, zmm2_2 = sub_140e715d0(arg2, &var_2c0, zmm2_1, zmm0_1, zmm1_2)
    // Real signature is (FArchive*, FName*) — the zmm regs are compiler
    // pass-through artifacts.
    constexpr uintptr_t RVA_FNameRead = 0x00E715D0;

    // FBitReader virtual method implementations (vtable+0x150/0x160/0x168).
    // Hooking the impls (not the vtable) gives us a full bit-by-bit transcript
    // of every read inside UNetConnection::ReceivedPacket.
    constexpr uintptr_t RVA_SerializeBits      = 0x010AB330;
    constexpr uintptr_t RVA_SerializeInt       = 0x00CD4D30;
    constexpr uintptr_t RVA_SerializeIntPacked = 0x00F74234;

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
    using SerializeBits_t      = void (__fastcall *)(void* thisAr, void* dest, int64_t lengthBits);
    using SerializeInt_t       = void (__fastcall *)(void* thisAr, uint32_t* outValue, uint32_t valueMax);
    using SerializeIntPacked_t = void (__fastcall *)(void* thisAr, uint32_t* outValue);

    inline ReceivedPacket_t      ReceivedPacket_Orig      = nullptr;
    inline ReceivedRawPacket_t   ReceivedRawPacket_Orig   = nullptr;
    inline FNameRead_t           FNameRead_Orig           = nullptr;
    inline SerializeBits_t       SerializeBits_Orig       = nullptr;
    inline SerializeInt_t        SerializeInt_Orig        = nullptr;
    inline SerializeIntPacked_t  SerializeIntPacked_Orig  = nullptr;

    inline thread_local bool g_InRecv = false;
    inline thread_local bool g_InRaw  = false;
    inline thread_local void* g_ActiveReader = nullptr; // populated while inside ReceivedPacket

    // FName::AppendString function pointer, resolved once at Install() time.
    using AppendString_t = void (__fastcall *)(const void* fname, void* outFString);
    inline AppendString_t AppendString_Fn = nullptr;

    // Resolve an FName (8-byte struct: ComparisonIndex u32 + Number u32) to a
    // narrow string via the game's own FName::AppendString.  Returns a static
    // thread-local buffer — caller must consume/copy before next call.
    inline const char* ResolveFName(const void* fnamePtr)
    {
        static thread_local char narrowBuf[256];
        narrowBuf[0] = '\0';

        if (!AppendString_Fn || !fnamePtr) return narrowBuf;

        // Build a minimal stack FString (TArray<wchar_t>): { Data*, NumElements, MaxElements }
        wchar_t wideBuf[128] = {};
        struct { wchar_t* Data; int32_t Num; int32_t Max; } tempStr = { wideBuf, 0, 128 };

        AppendString_Fn(fnamePtr, &tempStr);

        // Convert wchar_t → char (ASCII-safe for driver names)
        int32_t len = tempStr.Num > 0 ? tempStr.Num - 1 : 0; // exclude null terminator
        if (len > 255) len = 255;
        for (int32_t i = 0; i < len; ++i)
            narrowBuf[i] = (wideBuf[i] < 128) ? static_cast<char>(wideBuf[i]) : '?';
        narrowBuf[len] = '\0';
        return narrowBuf;
    }

    // Read the NetDriverName string from a UNetConnection's Driver pointer.
    inline const char* GetDriverNameFromConn(void* thisConn)
    {
        if (!thisConn) return "???";
        void* driver = *reinterpret_cast<void**>(
            reinterpret_cast<uintptr_t>(thisConn) + OFF_NetConn_Driver);
        if (!driver) return "NoDriver";
        void* fnamePtr = reinterpret_cast<void*>(
            reinterpret_cast<uintptr_t>(driver) + OFF_NetDriver_Name);
        const char* name = ResolveFName(fnamePtr);
        return (name[0] != '\0') ? name : "EmptyName";
    }

    // -----------------------------------------------------------------------
    // Shadow bit reader + packet decoder.
    // Decodes one raw game packet field-by-field using our current layout
    // understanding (Binja sub_140F79464 for Fortnite 17.50 / EngineNetVer=18).
    // Run before the original so results are visible even if the original crashes.
    // -----------------------------------------------------------------------
    struct SBR // Shadow Bit Reader
    {
        const uint8_t* buf;
        int64_t pos;
        int64_t num;
        bool err = false;

        SBR(const uint8_t* data, int64_t numBits) : buf(data), pos(0), num(numBits) {}

        uint8_t ReadBit()
        {
            if (pos >= num) { err = true; return 0; }
            uint8_t v = (buf[pos >> 3] >> (pos & 7)) & 1;
            ++pos;
            return v;
        }

        uint32_t ReadBitsLE(int n) // n ≤ 32, LSB-first
        {
            uint32_t v = 0;
            for (int i = 0; i < n && !err; ++i)
                v |= (uint32_t)ReadBit() << i;
            return v;
        }

        // UE4 ReadInt(Max): reads ceil(log2(Max)) bits (bit-saving bounded int)
        uint32_t ReadInt(uint32_t Max)
        {
            uint32_t v = 0;
            for (uint32_t mask = 1; mask < Max && !err; mask <<= 1)
                if (ReadBit()) v |= mask;
            return v;
        }

        // UE4 SerializeIntPacked: each byte = [bit0=continue][bits1-7=data]
        uint32_t ReadSIP()
        {
            uint32_t val = 0;
            for (int it = 0, shift = 0; it < 5 && !err; ++it, shift += 7)
            {
                if (pos + 8 > num) { err = true; break; }
                const uint8_t* src = buf + (pos >> 3);
                uint32_t used = pos & 7;
                uint32_t left = 8 - used;
                uint8_t m0 = uint8_t((1u << left) - 1u);
                uint8_t m1 = uint8_t((1u << used) - 1u);
                uint32_t nxt = (used != 0) ? 1 : 0;
                uint8_t byte = ((src[0] >> used) & m0) | ((src[nxt] & m1) << (left & 7));
                pos += 8;
                uint8_t cont = byte & 1;
                val |= (uint32_t)(byte >> 1) << shift;
                if (!cont) break;
            }
            return val;
        }

        // Skip num_bytes of SerializeBits (UE4 byte-aligned serialization)
        void SkipBytes(int n) { for (int i = 0; i < n*8 && !err; ++i) ReadBit(); }
    };

    inline void ShadowDecodePacket(const uint8_t* data, int32_t count)
    {
        if (count < 4 || count >= 4096) return;

        // --- find stop bit (highest set bit in last non-zero byte, MSB-first scan) ---
        int64_t numBits = (int64_t)count * 8;
        for (int i = count - 1; i >= 0; --i)
        {
            if (data[i] == 0) { numBits -= 8; continue; }
            for (int b = 7; b >= 0; --b)
            {
                if (data[i] & (1u << b)) { numBits = (int64_t)i * 8 + b; break; }
            }
            break;
        }

        SBR r(data, numBits);
        std::printf("[shadow] --- decoding %d bytes (%lld bits) ---\n",
                    count, (long long)numBits);

        // --- MagicHeader (4 bits, 0b0111 LSB-first) ---
        uint32_t magic = r.ReadBitsLE(4);
        if ((magic & 0xF) != 0x7)
        {
            std::printf("[shadow]   magic=0x%X (not a game packet, skipping)\n", magic);
            std::fflush(stdout);
            return;
        }

        // --- PacketNotify packed header (32 bits raw LE) ---
        // Layout: bits[0..3]=HWC-1, bits[4..17]=AckedSeq, bits[18..31]=Seq
        uint32_t hdr = r.ReadBitsLE(32);
        uint32_t hwc  = (hdr & 0xF) + 1;
        uint32_t ack  = (hdr >> 4)  & 0x3FFF;
        uint32_t seq  = (hdr >> 18) & 0x3FFF;
        std::printf("[shadow]   PacketNotify: Seq=%u AckedSeq=%u HistoryWords=%u\n",
                    seq, ack, hwc);

        // --- History words (hwc × 32 bits) ---
        for (uint32_t i = 0; i < hwc && !r.err; ++i)
            r.ReadBitsLE(32);

        // --- PacketInfo (EngineNetVer>=14): bHasFT + jitter + bHasServerFrameTimeByte + byte ---
        uint8_t bHasFT = r.ReadBit();
        uint32_t jitter = 0;
        if (bHasFT) jitter = r.ReadInt(1024);
        uint8_t bHasSFT = r.ReadBit();
        uint8_t sftByte = 0;
        if (bHasSFT) sftByte = (uint8_t)r.ReadBitsLE(8);
        std::printf("[shadow]   PacketInfo: bHasFT=%u jitter=%u bHasSFT=%u sft=%u  pos=%lld bitsLeft=%lld\n",
                    bHasFT, jitter, bHasSFT, sftByte, (long long)r.pos, (long long)(r.num - r.pos));

        // --- Bunch loop ---
        int bunchIdx = 0;
        while (!r.err && (r.num - r.pos) >= 22)
        {
            int64_t bunchStart = r.pos;
            std::printf("[shadow]   Bunch[%d] start pos=%lld bitsLeft=%lld\n",
                        bunchIdx, (long long)r.pos, (long long)(r.num - r.pos));

            // Bunch flag layout (empirically derived, client6/server6 gap analysis):
            //   bOpen=0          → 2 bits (bOpen + bReliable)
            //   bOpen=1,Close=0  → 3 bits (bOpen + bClose + bReliable)
            //   bOpen=1,Close=1  → 5 bits (bOpen + bClose + CloseReason(2) + bReliable)
            // bIsReplicationPaused is NOT in the wire format.
            uint8_t bOpen        = r.ReadBit();
            uint8_t bClose       = 0;
            uint32_t closeReason = 0;
            if (bOpen)
            {
                bClose = r.ReadBit();
                if (bClose)
                    closeReason = r.ReadInt(4); // ReadInt(4) = 2 bits
            }
            uint8_t bReliable = r.ReadBit(); // unconditional

            std::printf("[shadow]     bOpen=%u bClose=%u closeReason=%u bReliable=%u  pos=%lld\n",
                        bOpen, bClose, closeReason, bReliable, (long long)r.pos);

            // ChIndex (EngineNetVer>=3 → SerializeIntPacked)
            int64_t preChIdx = r.pos;
            uint32_t chIndex = r.ReadSIP();
            std::printf("[shadow]     ChIndex=%u (read %lld bits)  pos=%lld\n",
                        chIndex, (long long)(r.pos - preChIdx), (long long)r.pos);

            // ReadA / ReadB / ReadC
            uint8_t bHasPMExports = r.ReadBit();
            uint8_t bHasMBMGuids  = r.ReadBit();
            uint8_t bPartial      = r.ReadBit();
            std::printf("[shadow]     bHasPMExports=%u bHasMBMGuids=%u bPartial=%u  pos=%lld\n",
                        bHasPMExports, bHasMBMGuids, bPartial, (long long)r.pos);

            // ChSequence gated on bReliable
            uint32_t chSeq = 0;
            if (bReliable)
            {
                chSeq = r.ReadInt(1024);
                std::printf("[shadow]     ChSequence=%u  pos=%lld\n",
                            chSeq, (long long)r.pos);
            }

            // bPartial extras
            uint8_t bPartialInitial = 0, bPartialFinal = 0;
            if (bPartial)
            {
                bPartialInitial = r.ReadBit();
                bPartialFinal   = r.ReadBit();
                std::printf("[shadow]     bPartialInitial=%u bPartialFinal=%u  pos=%lld\n",
                            bPartialInitial, bPartialFinal, (long long)r.pos);
            }

            // ChName: gated on bOpen || bReliable, EngineNetVer>=6 → FName path (no ChType)
            if (bOpen || bReliable)
            {
                uint8_t bHardcoded = r.ReadBit();
                std::printf("[shadow]     FName: bHardcoded=%u  pos=%lld\n",
                            bHardcoded, (long long)r.pos);
                if (bHardcoded)
                {
                    int64_t preIdx = r.pos;
                    uint32_t nameIdx = r.ReadSIP();
                    std::printf("[shadow]     FName: index=%u (read %lld bits)  pos=%lld\n",
                                nameIdx, (long long)(r.pos - preIdx), (long long)r.pos);
                }
                else
                {
                    // String FName: SaveNum (32-bit LE) + chars + Number (32-bit LE)
                    int32_t saveNum = (int32_t)r.ReadBitsLE(32);
                    std::printf("[shadow]     FName: string SaveNum=%d  pos=%lld\n",
                                saveNum, (long long)r.pos);
                    int32_t absLen = saveNum < 0 ? -saveNum : saveNum;
                    if (absLen > 512 || r.err)
                    {
                        std::printf("[shadow]     FName: SaveNum out of range — aborting bunch\n");
                        break;
                    }
                    // skip chars (saveNum>0 → ANSI bytes, saveNum<0 → UTF-16 shorts)
                    if (saveNum > 0) r.SkipBytes(saveNum);
                    else if (saveNum < 0) { for (int i = 0; i < -saveNum && !r.err; ++i) r.ReadBitsLE(16); }
                    r.ReadBitsLE(32); // ChNameNumber
                }
            }

            // BunchDataBits = ReadInt(MaxPacket * 8). MaxPacket=1024 → max=8192.
            int64_t preBDB = r.pos;
            uint32_t bdb = r.ReadInt(8192);
            std::printf("[shadow]     BDB=%u (read %lld bits)  pos=%lld  bitsLeft=%lld\n",
                        bdb, (long long)(r.pos - preBDB),
                        (long long)r.pos, (long long)(r.num - r.pos));

            if (r.err || bdb > (uint32_t)(r.num - r.pos))
            {
                std::printf("[shadow]     BDB invalid or error — stopping\n");
                break;
            }

            // Skip payload
            for (uint32_t i = 0; i < bdb && !r.err; ++i) r.ReadBit();
            std::printf("[shadow]     payload skipped  pos=%lld\n", (long long)r.pos);
            ++bunchIdx;
        }

        std::printf("[shadow]   done: %d bunches, final pos=%lld num=%lld err=%d\n",
                    bunchIdx, (long long)r.pos, (long long)r.num, (int)r.err);
        std::fflush(stdout);
    }

    // -----------------------------------------------------------------------
    // ReceivedRawPacket detour: dump (data, count). Direct comparison against
    // WSCAP recvfrom logs confirms we hit the right function.
    // -----------------------------------------------------------------------
    inline void __fastcall ReceivedRawPacket_Detour(void* thisConn, void* data, int32_t count)
    {
        if (g_InRaw) { ReceivedRawPacket_Orig(thisConn, data, count); return; }
        g_InRaw = true;

        const char* drvName = GetDriverNameFromConn(thisConn);
        std::printf("[rawpkt][%s] conn=%p data=%p count=%d bytes:", drvName, thisConn, data, count);
        if (data && count > 0 && count < 4096)
        {
            auto* b = reinterpret_cast<uint8_t*>(data);
            for (int i = 0; i < count; ++i) std::printf(" %02X", b[i]);
        }
        std::printf("\n");
        std::fflush(stdout);

        if (data && count > 0 && count < 4096)
            ShadowDecodePacket(reinterpret_cast<const uint8_t*>(data), count);

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
    // FBitReader primitive read detours. Each logs Pos before and after, gated
    // on (g_InRecv && thisAr == g_ActiveReader) so we get a complete transcript
    // of every read inside UNetConnection::ReceivedPacket — without flooding the
    // log with reads from replication, RPCs, or other code paths.
    // -----------------------------------------------------------------------
    inline void __fastcall SerializeBits_Detour(void* thisAr, void* dest, int64_t lengthBits)
    {
        const bool relevant = (g_InRecv && thisAr == g_ActiveReader);
        const int64_t posBefore = relevant ? GetReaderPos(thisAr) : 0;
        SerializeBits_Orig(thisAr, dest, lengthBits);
        if (relevant)
        {
            const int64_t posAfter = GetReaderPos(thisAr);
            std::printf("[bit] SerializeBits   Pos %5lld -> %5lld (req=%lld bits)\n",
                        (long long)posBefore, (long long)posAfter, (long long)lengthBits);
            std::fflush(stdout);
        }
    }

    inline void __fastcall SerializeInt_Detour(void* thisAr, uint32_t* outValue, uint32_t valueMax)
    {
        const bool relevant = (g_InRecv && thisAr == g_ActiveReader);
        const int64_t posBefore = relevant ? GetReaderPos(thisAr) : 0;
        SerializeInt_Orig(thisAr, outValue, valueMax);
        if (relevant)
        {
            const int64_t posAfter = GetReaderPos(thisAr);
            const uint32_t v = outValue ? *outValue : 0;
            std::printf("[bit] SerializeInt    Pos %5lld -> %5lld (max=%u) val=%u\n",
                        (long long)posBefore, (long long)posAfter,
                        (unsigned)valueMax, (unsigned)v);
            std::fflush(stdout);
        }
    }

    inline void __fastcall SerializeIntPacked_Detour(void* thisAr, uint32_t* outValue)
    {
        const bool relevant = (g_InRecv && thisAr == g_ActiveReader);
        const int64_t posBefore = relevant ? GetReaderPos(thisAr) : 0;
        SerializeIntPacked_Orig(thisAr, outValue);
        if (relevant)
        {
            const int64_t posAfter = GetReaderPos(thisAr);
            const uint32_t v = outValue ? *outValue : 0;
            std::printf("[bit] SerializeIntPck Pos %5lld -> %5lld           val=%u\n",
                        (long long)posBefore, (long long)posAfter, (unsigned)v);
            std::fflush(stdout);
        }
    }

    // -----------------------------------------------------------------------
    inline bool Install()
    {
        HMODULE mod = GetModuleHandleA(nullptr);
        auto base = reinterpret_cast<uintptr_t>(mod);

        void* recvPacketAddr      = reinterpret_cast<void*>(base + RVA_ReceivedPacket);
        void* recvRawPacketAddr   = reinterpret_cast<void*>(base + RVA_ReceivedRawPacket);
        void* fnameReadAddr       = reinterpret_cast<void*>(base + RVA_FNameRead);
        void* serializeBitsAddr   = reinterpret_cast<void*>(base + RVA_SerializeBits);
        void* serializeIntAddr    = reinterpret_cast<void*>(base + RVA_SerializeInt);
        void* serializeIntPckAddr = reinterpret_cast<void*>(base + RVA_SerializeIntPacked);

        // Resolve FName::AppendString — not hooked, just called directly.
        AppendString_Fn = reinterpret_cast<AppendString_t>(base + RVA_AppendString);

        std::printf("[bunchhook] module base=%p\n", mod);
        std::printf("[bunchhook] FName::AppendString @ %p (RVA 0x%llX)\n",
                    reinterpret_cast<void*>(AppendString_Fn), (unsigned long long)RVA_AppendString);
        std::printf("[bunchhook] ReceivedPacket      @ %p (RVA 0x%llX)\n",
                    recvPacketAddr, (unsigned long long)RVA_ReceivedPacket);
        std::printf("[bunchhook] ReceivedRawPacket   @ %p (RVA 0x%llX)\n",
                    recvRawPacketAddr, (unsigned long long)RVA_ReceivedRawPacket);
        std::printf("[bunchhook] FNameRead           @ %p (RVA 0x%llX)\n",
                    fnameReadAddr, (unsigned long long)RVA_FNameRead);
        std::printf("[bunchhook] SerializeBits       @ %p (RVA 0x%llX)\n",
                    serializeBitsAddr, (unsigned long long)RVA_SerializeBits);
        std::printf("[bunchhook] SerializeInt        @ %p (RVA 0x%llX)\n",
                    serializeIntAddr, (unsigned long long)RVA_SerializeInt);
        std::printf("[bunchhook] SerializeIntPacked  @ %p (RVA 0x%llX)\n",
                    serializeIntPckAddr, (unsigned long long)RVA_SerializeIntPacked);

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
        ok &= installOne("SerializeBits",
                         serializeBitsAddr,
                         reinterpret_cast<void*>(&SerializeBits_Detour),
                         reinterpret_cast<void**>(&SerializeBits_Orig));
        ok &= installOne("SerializeInt",
                         serializeIntAddr,
                         reinterpret_cast<void*>(&SerializeInt_Detour),
                         reinterpret_cast<void**>(&SerializeInt_Orig));
        ok &= installOne("SerializeIntPacked",
                         serializeIntPckAddr,
                         reinterpret_cast<void*>(&SerializeIntPacked_Detour),
                         reinterpret_cast<void**>(&SerializeIntPacked_Orig));
        return ok;
    }
}

inline bool InitializeBunchHook() { return BunchHook::Install(); }
