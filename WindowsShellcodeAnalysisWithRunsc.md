# Shellcode Analysis via runsc

Shellcode are chunks of binaries that are executed in memory space with executable rights. In Windows, the common execution vector will be _VirtualAlloc_ or _NTAllocateVirtualMemory_. A good way to anlyze shellcode will be to emulate this in runsc32/64 to learn about its behavior, before rerun it and hook it to a debugger for further analysis.


## Extract payload from shellcode

1. Load shellcode from runsc32/64.
2. Start x32dbg/x64dbg.
3. Attach process (runsc32/64) to x32dbg/x64dbg.
4. Set breakpoint at VirtualAlloc in the console ```setBPX VirtualAlloc``` or try _NTAllocateVirtualMemory_ if the first doesn't work.
5. Run till breakpoint at VirtualAlloc, then run till user code exit.
6. Follow in dump to follow the memory space allocated.
7. Either (1) step through the code manually and observe in dump when the code changes after call function, or (2) run until next breakpoint.
8. Right-click at the dump, and Follow in Memory Map. The region usually will have executable permission with MZ header, but I came across some without executable permission, or other shellcode as well.
9. Right-click at the region and Dump Memory to File.


## Analyze shellcode

1. Load shellcode from runsc32/64.
2. Start x32dbg/x64dbg.
3. Attach process (runsc32/64) to x32dbg/x64dbg.
4. (1) inspect the memory region for strings/reference call, or (2) set breakpoint at suspect API (e.g hton/some others for network connection).
5. Sometimes, it is obfuscated into another payload and will have to follow the above (step 4) and set breakpoint at VirtualAlloc to see if there are any other payload that can be extracted.
