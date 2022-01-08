Hardware Debug Register Enumerator for Windows 
======================
Enumerates which threads have hardware debug registers set. This will help detect where VEHs are being used to do function hooking to avoid copy on write detection (d-cow). This tool (d-dr-registers) is complemented by d-vehimplant to detect the other half of the technique. 

Example of it running

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
[i] [4016][UNKNOWN] not analysed 31
[i] [6608][C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2111.5-0\MsMpEng.exe] not analysed 5
[i] [9996][C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2111.5-0\NisSrv.exe] not analysed 5
[i] [7468][C:\Windows\System32\SecurityHealthService.exe] not analysed 5
[i] [14732][C:\Windows\System32\SgrmBroker.exe] not analysed 5
[i] [6676][C:\Windows\System32\svchost.exe] not analysed 5
[i] [16612][C:\Windows\System32\svchost.exe] not analysed 5
[i] [20076][MEMGUARD.exe] has a thread (10208) with debug registers set - 7fff5e074570 0 0 0
[i] [20076][MEMGUARD.exe] has a thread (13564) with debug registers set - 7fff5e074570 0 0 0
[i] [20076][MEMGUARD.exe] has a thread (9832) with debug registers set - 7fff5e074570 0 0 0
[i] [20076][MEMGUARD.exe] has a thread (24988) with debug registers set - 7fff5e074570 0 0 0
[i] [20628][C:\Windows\System32\svchost.exe] not analysed 5
[i] Total of 359 processes - didn't open 17
```