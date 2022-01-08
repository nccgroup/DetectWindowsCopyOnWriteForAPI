Critical Section Count Enumerator for Windows
======================
Enumerates how many critical sections a process has. This will help detect processes which have had an implant injected causing a significant variance in the total number of expected Critical Sections. 

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
[i] [1072][lsass.exe] has 513 Critical Sections
[i] [1128][winlogon.exe] has 20 Critical Sections
[i] [1248][svchost.exe] has 33 Critical Sections
[i] [1260][fontdrvhost.exe] has 4 Critical Sections
[i] [1268][fontdrvhost.exe] has 6 Critical Sections
[i] [1388][svchost.exe] has 21 Critical Sections
[i] [1432][svchost.exe] has 64 Critical Sections
[i] [1508][dwm.exe] has 33 Critical Sections
[i] [1544][WUDFHost.exe] has 37 Critical Sections
[i] [1612][WUDFHost.exe] has 6 Critical Sections
[i] [1680][svchost.exe] has 51 Critical Sections
[i] [1688][svchost.exe] has 2 Critical Sections
[i] [1760][svchost.exe] has 2 Critical Sections
[i] [1776][svchost.exe] has 5 Critical Sections
[i] [1824][svchost.exe] has 7 Critical Sections
[i] [1832][svchost.exe] has 8 Critical Sections
[i] [1856][svchost.exe] has 14 Critical Sections
[i] [1868][svchost.exe] has 4 Critical Sections
[i] [1900][svchost.exe] has 8 Critical Sections
[i] [1992][svchost.exe] has 11 Critical Sections
[i] [1816][svchost.exe] has 17 Critical Sections
[i] [2072][IntelCpHDCPSvc.exe] has 7 Critical Sections
[i] [2080][svchost.exe] has 4 Critical Sections
[i] [2136][svchost.exe] has 8 Critical Sections
[i] [2192][svchost.exe] has 3 Critical Sections
[i] [2216][svchost.exe] has 3 Critical Sections
[i] [2236][WUDFHost.exe] has 9 Critical Sections
[i] [2288][svchost.exe] has 20 Critical Sections
[i] [2584][svchost.exe] has 3 Critical Sections
[i] [2596][IntelCpHeciSvc.exe] has 6 Critical Sections
[i] [2608][WUDFHost.exe] has 9 Critical Sections
[i] [2624][svchost.exe] has 10 Critical Sections
[i] [2924][svchost.exe] has 2 Critical Sections
[i] [2936][WUDFHost.exe] has 9 Critical Sections
[i] [2988][svchost.exe] has 13 Critical Sections
[i] [3024][svchost.exe] has 17 Critical Sections
[i] [2544][svchost.exe] has 8 Critical Sections
[i] [2312][spaceman.exe] has 5 Critical Sections
[i] [3104][svchost.exe] has 8 Critical Sections
[i] [3204][svchost.exe] has 24 Critical Sections
[i] [3212][svchost.exe] has 12 Critical Sections
[i] [3240][svchost.exe] has 8 Critical Sections
[i] [3260][svchost.exe] has 24 Critical Sections
[i] [3312][svchost.exe] has 7 Critical Sections
[i] [3424][svchost.exe] has 21 Critical Sections
[i] [3488][svchost.exe] has 19 Critical Sections
[i] [3508][svchost.exe] has 19 Critical Sections
[i] [3532][svchost.exe] has 13 Critical Sections
[i] [3708][vmms.exe] has 18 Critical Sections
[i] [3856][dashost.exe] has 25 Critical Sections
[i] [3932][svchost.exe] has 6 Critical Sections
[i] [3940][svchost.exe] has 10 Critical Sections
```