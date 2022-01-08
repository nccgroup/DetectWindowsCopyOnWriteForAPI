Vectored Exception Handler Enumerator for Windows
======================
This will enumerate which Vectored Exception Handlers are present for a process and which module they point to. This will help detect where VEH is used to do function hooking to avoid copy on write detection (d-cow). This tool (d-vehimplant) is complemented by d-dr-registers to detect the other half of the technique.

This is known to work in Windows 10 x64, the key function which is fragile is the VEH linked list enumerator. This uses a heuristic to do so and thus may break if NTDLL changes materialy
```
ULONGLONG GetVEHOffset() {
	HMODULE ntdll = LoadLibraryA("ntdll.dll");

	ULONGLONG procAddress = (ULONGLONG)GetProcAddress(ntdll, "RtlRemoveVectoredExceptionHandler");
	BYTE* Buffer = (BYTE*)(GetProcAddress(ntdll, "RtlRemoveVectoredExceptionHandler"));

	fwprintf(stdout, _TEXT("[i] RtlRemoveVectoredExceptionHandler [%llx]\n"), (procAddress));


	DWORD dwCount = 0;
	DWORD dwOffset = 0;
	for (dwCount = 0; dwCount < 60; dwCount++) {

		if ((*(Buffer + dwCount) == 0x4c) && (*(Buffer + dwCount + 1) == 0x8d) && (*(Buffer + dwCount + 2) == 0x25)) {
			memcpy(&dwOffset, (Buffer + dwCount + 3), 4);
			break;
		}
	}

	// ptr return by GetProcAddress + the seek until our pattern + the instruction to load the RVA
	fwprintf(stdout, _TEXT("[i] LdrpVectorHandlerList [%llx]\n"), ((LONGLONG)Buffer + dwCount + 7 + dwOffset));
	
	return ((LONGLONG)Buffer + dwCount + 7 + dwOffset);
}
```

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
[i] [5660][com.docker.service] is using VEH - Vectored Exception Handler
[i] RtlRemoveVectoredExceptionHandler [7fff5df92070]
[i] LdrpVectorHandlerList [7fff5e08f3e8]
[d] [5660][com.docker.service] VEH handler(decoded) 0x00007FFF3C3F5230 which is in clr.dll
[d] [5660][com.docker.service] # of VEH: 1
[i] [6608][C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2111.5-0\MsMpEng.exe] not analysed 5
[i] [9996][C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2111.5-0\NisSrv.exe] not analysed 5
[i] [7468][C:\Windows\System32\SecurityHealthService.exe] not analysed 5
[i] [15288][slack.exe] is using VEH - Vectored Exception Handler
[i] RtlRemoveVectoredExceptionHandler [7fff5df92070]
[i] LdrpVectorHandlerList [7fff5e08f3e8]
[d] [15288][slack.exe] VEH handler(decoded) 0x00007FF753B7EE20 which is in slack.exe
[d] [15288][slack.exe] # of VEH: 1
[i] [14732][C:\Windows\System32\SgrmBroker.exe] not analysed 5
[i] [6676][C:\Windows\System32\svchost.exe] not analysed 5
[i] [13084][msedgewebview2.exe] is using VEH - Vectored Exception Handler
[i] RtlRemoveVectoredExceptionHandler [7fff5df92070]
[i] LdrpVectorHandlerList [7fff5e08f3e8]
[d] [13084][msedgewebview2.exe] VEH handler(decoded) 0x00007FFEDE523880 which is in msedge.dll
[d] [13084][msedgewebview2.exe] # of VEH: 1
[i] [15580][msedgewebview2.exe] is using VEH - Vectored Exception Handler
[i] RtlRemoveVectoredExceptionHandler [7fff5df92070]
[i] LdrpVectorHandlerList [7fff5e08f3e8]
[d] [15580][msedgewebview2.exe] VEH handler(decoded) 0x00007FFEDE523880 which is in msedge.dll
[d] [15580][msedgewebview2.exe] # of VEH: 1
[i] [15508][msedge.exe] is using VEH - Vectored Exception Handler
[i] RtlRemoveVectoredExceptionHandler [7fff5df92070]
[i] LdrpVectorHandlerList [7fff5e08f3e8]
[d] [15508][msedge.exe] VEH handler(decoded) 0x00007FFEDE523880 which is in msedge.dll
[d] [15508][msedge.exe] # of VEH: 1
[i] [16612][C:\Windows\System32\svchost.exe] not analysed 5
[i] [15304][OUTLOOK.EXE] is using VEH - Vectored Exception Handler
[i] RtlRemoveVectoredExceptionHandler [7fff5df92070]
[i] LdrpVectorHandlerList [7fff5e08f3e8]
[d] [15304][OUTLOOK.EXE] VEH handler(decoded) 0x00007FFF3C3F5230 which is in clr.dll
[d] [15304][OUTLOOK.EXE] VEH handler(decoded) 0x00007FFF025BA7A0 which is in InkObj.dll
[d] [15304][OUTLOOK.EXE] VEH handler(decoded) 0x00007FFF33FE3450 which is in rtscom.dll
[d] [15304][OUTLOOK.EXE] # of VEH: 3
```

