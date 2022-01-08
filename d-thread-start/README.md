Thread Starting Function Enumerator for Windows
======================
Enumerates the address and which module the starting address of each thread points to. This will help detect when threat actors allocate memory for their payload and use that address as the start address to `CreateThread` or `CreateRemoteThrear` etc. 

Example of it running:
```
[i] Running..
[!] [0][UNKNOWN] Failed to OpenProcess - 87
[i] [4][UNKNOWN] not analysed 31
[i] [56][UNKNOWN] not analysed 31
[i] [108][UNKNOWN] not analysed 31
[i] [576][C:\Windows\System32\smss.exe] not analysed 5
[i] [868][C:\Windows\System32\csrss.exe] not analysed 5
[i] [660][C:\Windows\System32\wininit.exe] not analysed 5
[i] [856][C:\Windows\System32\csrss.exe] not analysed 5
[i] [1040][C:\Windows\System32\services.exe] not analysed 5
[i] [1064][C:\Windows\System32\LsaIso.exe] not analysed 998
[i] [1072][lsass.exe] Start Address of Thread 7ff7276920d0 in lsass.exe
[i] [1072][lsass.exe] Start Address of Thread 7fff5b27d610 in lsasrv.dll
[i] [1072][lsass.exe] Start Address of Thread 7fff5df62ad0 in ntdll.dll
[i] [1072][lsass.exe] Start Address of Thread 7fff5d2aafb0 in msvcrt.dll
[i] [1072][lsass.exe] Start Address of Thread 7fff5df62ad0 in ntdll.dll
[i] [1072][lsass.exe] Start Address of Thread 7fff5b6f50d0 in ucrtbase.dll
[i] [1072][lsass.exe] Start Address of Thread 7fff5df62ad0 in ntdll.dll
[i] [1072][lsass.exe] Start Address of Thread 7fff5df62ad0 in ntdll.dll
[i] [1072][lsass.exe] Start Address of Thread 7fff5df62ad0 in ntdll.dll
[i] [1072][lsass.exe] Start Address of Thread 7fff5df62ad0 in ntdll.dll
[i] [1072][lsass.exe] Start Address of Thread 7fff5df62ad0 in ntdll.dll
[i] [1128][winlogon.exe] Start Address of Thread 7ff7ad798e60 in winlogon.exe
[i] [1128][winlogon.exe] Start Address of Thread 7fff5df62ad0 in ntdll.dll
[i] [1128][winlogon.exe] Start Address of Thread 7fff5df62ad0 in ntdll.dll
[i] [1128][winlogon.exe] Start Address of Thread 7fff5df62ad0 in ntdll.dll
[i] [1128][winlogon.exe] Start Address of Thread 7fff5df62ad0 in ntdll.dll
[i] [1128][winlogon.exe] Start Address of Thread 7fff5df62ad0 in ntdll.dll
[i] [1128][winlogon.exe] Start Address of Thread 7fff5df62ad0 in ntdll.dll
[i] [1248][svchost.exe] Start Address of Thread 7ff715494e80 in svchost.exe
[i] [1248][svchost.exe] Start Address of Thread 7fff5df62ad0 in ntdll.dll
[i] [1248][svchost.exe] Start Address of Thread 7fff57178ac0 in DAB.dll
[i] [1248][svchost.exe] Start Address of Thread 7fff5941efd0 in psmserviceexthost.dll
[i] [1248][svchost.exe] Start Address of Thread 7fff5df62ad0 in ntdll.dll
[i] [1248][svchost.exe] Start Address of Thread 7fff5df62ad0 in ntdll.dll
[i] [1248][svchost.exe] Start Address of Thread 7fff3ed51c90 in msiltcfg.dll
[i] [1248][svchost.exe] Start Address of Thread 7fff5df62ad0 in ntdll.dll
[i] [1248][svchost.exe] Start Address of Thread 7fff5df62ad0 in ntdll.dll
[i] [1248][svchost.exe] Start Address of Thread 7fff5df62ad0 in ntdll.dll
[i] [1248][svchost.exe] Start Address of Thread 7fff5df62ad0 in ntdll.dll
[i] [1248][svchost.exe] Start Address of Thread 7fff5df62ad0 in ntdll.dll
[i] [1248][svchost.exe] Start Address of Thread 7fff5df62ad0 in ntdll.dll
[i] [1248][svchost.exe] Start Address of Thread 7fff5df62ad0 in ntdll.dll
[i] [1248][svchost.exe] Start Address of Thread 7fff5df62ad0 in ntdll.dll
[i] [1248][svchost.exe] Start Address of Thread 7fff5df62ad0 in ntdll.dll
[i] [1248][svchost.exe] Start Address of Thread 7fff5df62ad0 in ntdll.dll
[i] [1248][svchost.exe] Start Address of Thread 7fff5cadadd0 in combase.dll
[i] [1248][svchost.exe] Start Address of Thread 7fff5df62ad0 in ntdll.dll
[i] [1248][svchost.exe] Start Address of Thread 7fff5df62ad0 in ntdll.dll
```