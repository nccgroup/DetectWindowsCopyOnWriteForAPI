Call Stack Enumerator for Microsoft Windows
======================
Enumerates the call stack and associated symbols for each thread. This will help detect threads which are running code not from a module due to the instruction pointer being somewhere unexpected. Caveat will be JIT (Just In Time) compiled code.

Example of it running showing a suspicious call stack
```
[i] [25852][20616][MEMGUARD.exe] Frame 0 - 0x0000018DA14C0001 -> . ??
[i] [25852][20616][MEMGUARD.exe] Frame 1 - 0x00007FFF5DF88A3C -> C:\WINDOWS\SYSTEM32\ntdll.dll.RtlDeleteAce
[i] [25852][20616][MEMGUARD.exe] Frame 2 - 0x00007FFF5DF61276 -> C:\WINDOWS\SYSTEM32\ntdll.dll.RtlRaiseException
[i] [25852][20616][MEMGUARD.exe] Frame 3 - 0x00007FFF5DFB0BFE -> C:\WINDOWS\SYSTEM32\ntdll.dll.KiUserExceptionDispatcher
[i] [25852][20616][MEMGUARD.exe] Frame 4 - 0x00007FFF2BF11427 -> C:\WINDOWS\SYSTEM32\VCRUNTIME140D.dll.memcpy
[i] [25852][20616][MEMGUARD.exe] Frame 5 - 0x00007FF6549D2128 -> C:\Data\NCC\!Code\Slop\MEMGUARD\x64\Debug\MEMGUARD.exe.main
[i] [25852][20616][MEMGUARD.exe] Frame 6 - 0x00007FF6549D2E49 -> C:\Data\NCC\!Code\Slop\MEMGUARD\x64\Debug\MEMGUARD.exe.invoke_main 
[i] [25852][20616][MEMGUARD.exe] Frame 7 - 0x00007FF6549D2CEE -> C:\Data\NCC\!Code\Slop\MEMGUARD\x64\Debug\MEMGUARD.exe.__scrt_common_main_seh
[i] [25852][20616][MEMGUARD.exe] Frame 8 - 0x00007FF6549D2BAE -> C:\Data\NCC\!Code\Slop\MEMGUARD\x64\Debug\MEMGUARD.exe.__scrt_common_main
[i] [25852][20616][MEMGUARD.exe] Frame 9 - 0x00007FF6549D2ED9 -> C:\Data\NCC\!Code\Slop\MEMGUARD\x64\Debug\MEMGUARD.exe.mainCRTStartup
[i] [25852][20616][MEMGUARD.exe] Frame 10 - 0x00007FFF5D327034 -> C:\WINDOWS\System32\KERNEL32.DLL.BaseThreadInitThunk
[i] [25852][20616][MEMGUARD.exe] Frame 11 - 0x00007FFF5DF62651 -> C:\WINDOWS\SYSTEM32\ntdll.dll.RtlUserThreadStart
[i] [25852][20616][MEMGUARD.exe] -----
[i] [25852][9896][MEMGUARD.exe] Frame 0 - 0x00007FFF5DFB07C4 -> C:\WINDOWS\SYSTEM32\ntdll.dll.ZwWaitForWorkViaWorkerFactory
[i] [25852][9896][MEMGUARD.exe] Frame 1 - 0x00007FFF5DF62DC7 -> C:\WINDOWS\SYSTEM32\ntdll.dll.TpReleaseCleanupGroupMembers
[i] [25852][9896][MEMGUARD.exe] Frame 2 - 0x00007FFF5D327034 -> C:\WINDOWS\System32\KERNEL32.DLL.BaseThreadInitThunk
[i] [25852][9896][MEMGUARD.exe] Frame 3 - 0x00007FFF5DF62651 -> C:\WINDOWS\SYSTEM32\ntdll.dll.RtlUserThreadStart
[i] [25852][9896][MEMGUARD.exe] -----
[i] [25852][6452][MEMGUARD.exe] Frame 0 - 0x00007FFF5DFB07C4 -> C:\WINDOWS\SYSTEM32\ntdll.dll.ZwWaitForWorkViaWorkerFactory
[i] [25852][6452][MEMGUARD.exe] Frame 1 - 0x00007FFF5DF62DC7 -> C:\WINDOWS\SYSTEM32\ntdll.dll.TpReleaseCleanupGroupMembers
[i] [25852][6452][MEMGUARD.exe] Frame 2 - 0x00007FFF5D327034 -> C:\WINDOWS\System32\KERNEL32.DLL.BaseThreadInitThunk
[i] [25852][6452][MEMGUARD.exe] Frame 3 - 0x00007FFF5DF62651 -> C:\WINDOWS\SYSTEM32\ntdll.dll.RtlUserThreadStart
[i] [25852][6452][MEMGUARD.exe] -----
``` 
The above was produced with by this code:
```

    LPVOID myMalHandler = NULL;
    myMalHandler = VirtualAlloc(NULL, 1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memset(myMalHandler, 0xcc, 1000);
    HANDLE hHal = AddVectoredExceptionHandler(false, (PVECTORED_EXCEPTION_HANDLER)myMalHandler);
```
Then causing an exception. 

In an unscientific sample set of one host searching for the output `. ??` in the result we only saw the following - one of which was the test case:
```
[i] [5516][7280][cb.exe] Frame 0 - 0x00007FF74E50EF77 -> C:\WINDOWS\CarbonBlack\cb.exe. ??  
[i] [5516][7280][cb.exe] Frame 1 - 0x00007FF74E50FC51 -> C:\WINDOWS\CarbonBlack\cb.exe. ??  
[i] [5516][7280][cb.exe] Frame 2 - 0x00007FF74E4A1AA2 -> C:\WINDOWS\CarbonBlack\cb.exe. ??  
[i] [24212][21104][MEMGUARD.exe] Frame 0 - 0x000002CF87690000 -> . ??  
```
Example command line is below:
```
C:\Data\NCC\!Code\Git.Public\DetectWindowsCopyOnWriteForAPI\d-cow\x64\Release>d-nonmodulecallstack.exe | findstr /N /R /C:". ??"
[!] [0][UNKNOWN] Failed to OpenProcess - 87
[!] [4][UNKNOWN] Failed to OpenProcess - 5
[!] [56][UNKNOWN] Failed to OpenProcess - 5
[!] [108][UNKNOWN] Failed to OpenProcess - 5
[!] [576][UNKNOWN] Failed to OpenProcess - 5
[!] [868][UNKNOWN] Failed to OpenProcess - 5
[!] [660][UNKNOWN] Failed to OpenProcess - 5
[!] [856][UNKNOWN] Failed to OpenProcess - 5
[!] [1040][UNKNOWN] Failed to OpenProcess - 5
[!] [4016][UNKNOWN] Failed to OpenProcess - 5
[!] [6608][UNKNOWN] Failed to OpenProcess - 5
[!] [9996][UNKNOWN] Failed to OpenProcess - 5
[!] [7468][UNKNOWN] Failed to OpenProcess - 5
[!] [14732][UNKNOWN] Failed to OpenProcess - 5
[!] [6676][UNKNOWN] Failed to OpenProcess - 5
[!] [25616][UNKNOWN] Failed to OpenProcess - 5
[!] [26024][UNKNOWN] Failed to OpenProcess - 5
26126:[i] [24212][21104][MEMGUARD.exe] Frame 0 - 0x000002CF87690000 -> . ??
[!] [23700][UNKNOWN] Failed to OpenProcess - 87
```