// Pyrite -- minimal AES-bypass loader for Fortnite 17.50 (UE 4.26.1).
//
// Forked from the Cobalt loader (which also did HTTPS redirection + exit-popup
// hooks via curlhook.h/exithook.h). Pyrite strips those out and adds Oodle
// compression bypass alongside the AES-GCM bypass so the standalone server
// can see plaintext PacketHandler bunches.

#include <Windows.h>
#include <iostream>
#include "memcury.h"
#include "aesgcmhook.h"
#include "oodlehook.h"
#include <MinHook/MinHook.h>

// Single Hook() entry-point used by aesgcmhook.h. Kept as a thin wrapper
// over MinHook so we can switch backends later if needed.
void Hook(void* Target, void* Detour)
{
#ifdef USE_MINHOOK
    MH_CreateHook(Target, Detour, nullptr);
    MH_EnableHook(Target);
#else
    Memcury::VEHHook::AddHook(Target, Detour);
#endif
}

DWORD WINAPI Main(LPVOID)
{
    AllocConsole();
    FILE* fptr;
    freopen_s(&fptr, "CONOUT$", "w+", stdout);

    std::cout << "Pyrite (AES-bypass build) initializing\n";

#ifdef USE_MINHOOK
    MH_Initialize();
#else
    Memcury::VEHHook::Init();
#endif

    if (!InitializeAESBypass())
    {
        std::cout << "[AESBypass] Failed -- packets will stay encrypted.\n";
        MessageBoxA(0, "Failed to install AES bypass hooks!", "Pyrite", MB_ICONERROR);
        return 0;
    }

    if (!InitializeOodleBypass())
    {
        std::cout << "[OodleBypass] Failed -- packets will stay compressed.\n";
    }

    std::cout << "Pyrite ready.\n";
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID /*lpReserved*/)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(0, 0, Main, 0, 0, 0);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
