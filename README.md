# Pyrite

Forked from [Cobalt](https://github.com/Milxnor/Cobalt) and trimmed down for use as the AES-GCM + Oodle bypass loader paired with the Project-Reboot-3.0 standalone server.

The original Cobalt's SSL bypass / URL redirection / exit-popup hooks (curlhook.h, exithook.h) are kept in the tree but not initialized from `dllmain.cpp` — Pyrite only installs `InitializeAESBypass()` and `InitializeOodleBypass()` so the standalone can see plaintext PacketHandler bunches.

# Credits

Cobalt (original loader) - https://github.com/Milxnor/Cobalt<br>
Memcury - https://github.com/kem0x/Memcury<br>
Neonite++ for the signatures and curl hook - https://github.com/PeQuLeaks/NeonitePP-Fixed/tree/1.4<br>
