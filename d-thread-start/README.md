Thread Starting Function Enumerator for Windows
======================
Enumerates the address and which module the starting address of each thread points to. This will help detect when threat actors allocate memory for their payload and use that address as the start address to `CreateThread` or `CreateRemoteThrear` etc. 

Example of it finding the result of CreateRemoteThread from memory:
```
[i] [14808][MEMGUARD.exe] Start Address of Thread 2210ff00000 in UnknownModule->UnknownFunction
```

Example of it running:
```
[i] Running..
[i] [4][UNKNOWN] not analysed 31
[i] [56][UNKNOWN] not analysed 31
[i] [108][UNKNOWN] not analysed 31
[i] [568][C:\Windows\System32\smss.exe] not analysed 5
[i] [936][C:\Windows\System32\csrss.exe] not analysed 5
[i] [672][C:\Windows\System32\wininit.exe] not analysed 5
[i] [968][C:\Windows\System32\csrss.exe] not analysed 5
[i] [1052][C:\Windows\System32\services.exe] not analysed 5
[i] [1072][C:\Windows\System32\LsaIso.exe] not analysed 998
[i] [1084][lsass.exe] Start Address of Thread 7ff6a47020d0 in C:\WINDOWS\system32\lsass.exe->LsaImpersonateKsecCaller
[i] [1084][lsass.exe] Start Address of Thread 7ffb700e0cf0 in C:\WINDOWS\system32\lsasrv.dll->LsaIFree_LSAPR_TRANSLATED_NAMES
[i] [1084][lsass.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1084][lsass.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [1084][lsass.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1084][lsass.exe] Start Address of Thread 7ffb705250d0 in C:\WINDOWS\System32\ucrtbase.dll->o__beginthread
[i] [1084][lsass.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1084][lsass.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1084][lsass.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1084][lsass.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1084][lsass.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1084][lsass.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1084][lsass.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1084][lsass.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1084][lsass.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [1200][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][svchost.exe] Start Address of Thread 7ffb6afa8ac0 in c:\windows\system32\DAB.dll->DabInitialize
[i] [1200][svchost.exe] Start Address of Thread 7ffb6dcdefd0 in C:\WINDOWS\SYSTEM32\psmserviceexthost.dll->PsmCrmSessionUserNotification
[i] [1200][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][svchost.exe] Start Address of Thread 7ffb41861c90 in C:\WINDOWS\SYSTEM32\msiltcfg.dll->RestartMsi
[i] [1200][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [1200][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1228][fontdrvhost.exe] Start Address of Thread 7ff78e3326a0 in C:\WINDOWS\system32\fontdrvhost.exe->UnknownFunction
[i] [1228][fontdrvhost.exe] Start Address of Thread 7ff78e32de80 in C:\WINDOWS\system32\fontdrvhost.exe->UnknownFunction
[i] [1228][fontdrvhost.exe] Start Address of Thread 7ff78e32de80 in C:\WINDOWS\system32\fontdrvhost.exe->UnknownFunction
[i] [1228][fontdrvhost.exe] Start Address of Thread 7ff78e32de80 in C:\WINDOWS\system32\fontdrvhost.exe->UnknownFunction
[i] [1228][fontdrvhost.exe] Start Address of Thread 7ff78e32de80 in C:\WINDOWS\system32\fontdrvhost.exe->UnknownFunction
[i] [1228][fontdrvhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1308][WUDFHost.exe] Start Address of Thread 7ff745b60d40 in C:\Windows\System32\WUDFHost.exe->UnknownFunction
[i] [1308][WUDFHost.exe] Start Address of Thread 7ffb6d6bb6e0 in c:\windows\system32\drivers\umdf\surfacepenpairing.dll->UnknownFunction
[i] [1308][WUDFHost.exe] Start Address of Thread 7ffb5fa90100 in c:\windows\system32\drivers\umdf\sensorshid.dll->UnknownFunction
[i] [1308][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1308][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1308][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1308][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1308][WUDFHost.exe] Start Address of Thread 7ffb28efaae0 in c:\windows\system32\drivers\umdf\surfacedockfwupdate.dll->UnknownFunction
[i] [1308][WUDFHost.exe] Start Address of Thread 7ffb28f03210 in c:\windows\system32\drivers\umdf\surfacedockfwupdate.dll->UnknownFunction
[i] [1308][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1308][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1316][winlogon.exe] Start Address of Thread 7ff71b898e60 in C:\WINDOWS\system32\winlogon.exe->UnknownFunction
[i] [1316][winlogon.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1316][winlogon.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1316][winlogon.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1316][winlogon.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1388][fontdrvhost.exe] Start Address of Thread 7ff78e3326a0 in C:\WINDOWS\system32\fontdrvhost.exe->UnknownFunction
[i] [1388][fontdrvhost.exe] Start Address of Thread 7ff78e32de80 in C:\WINDOWS\system32\fontdrvhost.exe->UnknownFunction
[i] [1388][fontdrvhost.exe] Start Address of Thread 7ff78e32de80 in C:\WINDOWS\system32\fontdrvhost.exe->UnknownFunction
[i] [1388][fontdrvhost.exe] Start Address of Thread 7ff78e32de80 in C:\WINDOWS\system32\fontdrvhost.exe->UnknownFunction
[i] [1388][fontdrvhost.exe] Start Address of Thread 7ff78e32de80 in C:\WINDOWS\system32\fontdrvhost.exe->UnknownFunction
[i] [1388][fontdrvhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1448][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [1448][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [1448][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1448][svchost.exe] Start Address of Thread 7ffb41861c90 in C:\WINDOWS\SYSTEM32\msiltcfg.dll->RestartMsi
[i] [1448][svchost.exe] Start Address of Thread 7ffb6e026570 in c:\windows\system32\rpcss.dll->UnknownFunction
[i] [1448][svchost.exe] Start Address of Thread 7ffb6e026570 in c:\windows\system32\rpcss.dll->UnknownFunction
[i] [1448][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1448][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1448][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1448][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1448][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1448][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1448][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1448][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1448][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1484][WUDFHost.exe] Start Address of Thread 7ff745b60d40 in C:\Windows\System32\WUDFHost.exe->UnknownFunction
[i] [1484][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1484][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1484][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1484][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1484][WUDFHost.exe] Start Address of Thread 7ffb6df4f630 in c:\windows\system32\drivers\umdf\esif_umdf2.dll->UnknownFunction
[i] [1484][WUDFHost.exe] Start Address of Thread 7ffb6def1aa0 in c:\windows\system32\drivers\umdf\esif_umdf2.dll->UnknownFunction
[i] [1484][WUDFHost.exe] Start Address of Thread 7ffb6def1aa0 in c:\windows\system32\drivers\umdf\esif_umdf2.dll->UnknownFunction
[i] [1484][WUDFHost.exe] Start Address of Thread 7ffb6c6a7a30 in C:\WINDOWS\system32\Intel\DPTF\dptf.dll->EsifServices::sendCommand
[i] [1484][WUDFHost.exe] Start Address of Thread 7ffb6df4f630 in c:\windows\system32\drivers\umdf\esif_umdf2.dll->UnknownFunction
[i] [1484][WUDFHost.exe] Start Address of Thread 7ffb6c6a7a30 in C:\WINDOWS\system32\Intel\DPTF\dptf.dll->EsifServices::sendCommand
[i] [1484][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1544][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [1544][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1544][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1544][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1544][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1544][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [1544][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1544][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1544][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1664][dwm.exe] Start Address of Thread 7ff6908e3160 in C:\WINDOWS\system32\dwm.exe->UnknownFunction
[i] [1664][dwm.exe] Start Address of Thread 7ffb6d5cbb60 in C:\WINDOWS\SYSTEM32\dwmredir.dll->DwmRedirectionManagerInitialize
[i] [1664][dwm.exe] Start Address of Thread 7ffb6c99f410 in C:\WINDOWS\system32\dwmcore.dll->MilTransport_Release
[i] [1664][dwm.exe] Start Address of Thread 7ffb6ca48db0 in C:\WINDOWS\system32\dwmcore.dll->MilTransport_AddRef
[i] [1664][dwm.exe] Start Address of Thread 7ffb6ca48d70 in C:\WINDOWS\system32\dwmcore.dll->MilCompositionEngine_Initialize
[i] [1664][dwm.exe] Start Address of Thread 7ffb6ca48d00 in C:\WINDOWS\system32\dwmcore.dll->MilCompositionEngine_Initialize
[i] [1664][dwm.exe] Start Address of Thread 7ffb6ca48b50 in C:\WINDOWS\system32\dwmcore.dll->MilCompositionEngine_Initialize
[i] [1664][dwm.exe] Start Address of Thread 7ffb6d50b2c0 in C:\WINDOWS\SYSTEM32\udwm.dll->UnknownFunction
[i] [1664][dwm.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1664][dwm.exe] Start Address of Thread 7ffb6038f930 in C:\Windows\System32\Windows.Gaming.Input.dll->DllGetClassObject
[i] [1664][dwm.exe] Start Address of Thread 7ffb60818860 in C:\WINDOWS\SYSTEM32\ism.dll->CreateSystemInputHost
[i] [1664][dwm.exe] Start Address of Thread 7ffb5f765e90 in C:\Windows\System32\DispBroker.dll->DispBrokerTraceLogCallback
[i] [1664][dwm.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1664][dwm.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1708][WUDFHost.exe] Start Address of Thread 7ff745b60d40 in C:\Windows\System32\WUDFHost.exe->UnknownFunction
[i] [1708][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1708][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1708][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1708][WUDFHost.exe] Start Address of Thread 7ffb6c909414 in c:\windows\system32\drivers\umdf\sarproxy.dll->UnknownFunction
[i] [1708][WUDFHost.exe] Start Address of Thread 7ffb6c90c190 in c:\windows\system32\drivers\umdf\sarproxy.dll->UnknownFunction
[i] [1708][WUDFHost.exe] Start Address of Thread 7ffb6c906a34 in c:\windows\system32\drivers\umdf\sarproxy.dll->UnknownFunction
[i] [1708][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1708][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1708][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1808][WUDFHost.exe] Start Address of Thread 7ff745b60d40 in C:\Windows\System32\WUDFHost.exe->UnknownFunction
[i] [1808][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1808][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1808][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1808][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1808][WUDFHost.exe] Start Address of Thread 7ffb6af50de0 in c:\windows\system32\drivers\umdf\iddcx.dll->UnknownFunction
[i] [1808][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1956][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [1956][svchost.exe] Start Address of Thread 7ffb6a910d40 in c:\windows\system32\termsrv.dll->SvchostPushServiceGlobals
[i] [1956][svchost.exe] Start Address of Thread 7ffb6a95df70 in c:\windows\system32\termsrv.dll->SvchostPushServiceGlobals
[i] [1956][svchost.exe] Start Address of Thread 7ffb6a945610 in c:\windows\system32\termsrv.dll->SvchostPushServiceGlobals
[i] [1956][svchost.exe] Start Address of Thread 7ffb6933a7a0 in C:\WINDOWS\system32\rdpcorets.dll->DllGetClassObject
[i] [1956][svchost.exe] Start Address of Thread 7ffb69224030 in C:\WINDOWS\system32\RDPBASE.dll->CRdpFIPSEncryption_CreateInstance
[i] [1956][svchost.exe] Start Address of Thread 7ffb69224030 in C:\WINDOWS\system32\RDPBASE.dll->CRdpFIPSEncryption_CreateInstance
[i] [1956][svchost.exe] Start Address of Thread 7ffb69224030 in C:\WINDOWS\system32\RDPBASE.dll->CRdpFIPSEncryption_CreateInstance
[i] [1956][svchost.exe] Start Address of Thread 7ffb69224030 in C:\WINDOWS\system32\RDPBASE.dll->CRdpFIPSEncryption_CreateInstance
[i] [1956][svchost.exe] Start Address of Thread 7ffb69224030 in C:\WINDOWS\system32\RDPBASE.dll->CRdpFIPSEncryption_CreateInstance
[i] [1956][svchost.exe] Start Address of Thread 7ffb69224030 in C:\WINDOWS\system32\RDPBASE.dll->CRdpFIPSEncryption_CreateInstance
[i] [1956][svchost.exe] Start Address of Thread 7ffb69224030 in C:\WINDOWS\system32\RDPBASE.dll->CRdpFIPSEncryption_CreateInstance
[i] [1956][svchost.exe] Start Address of Thread 7ffb69224030 in C:\WINDOWS\system32\RDPBASE.dll->CRdpFIPSEncryption_CreateInstance
[i] [1956][svchost.exe] Start Address of Thread 7ffb69224030 in C:\WINDOWS\system32\RDPBASE.dll->CRdpFIPSEncryption_CreateInstance
[i] [1956][svchost.exe] Start Address of Thread 7ffb69224030 in C:\WINDOWS\system32\RDPBASE.dll->CRdpFIPSEncryption_CreateInstance
[i] [1956][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1956][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [1956][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1956][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1956][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1984][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [1984][svchost.exe] Start Address of Thread 7ffb6a5a53d0 in c:\windows\system32\wevtsvc.dll->ServiceMain
[i] [1984][svchost.exe] Start Address of Thread 7ffb6a5aae10 in c:\windows\system32\wevtsvc.dll->ServiceMain
[i] [1984][svchost.exe] Start Address of Thread 7ffb6a5aae10 in c:\windows\system32\wevtsvc.dll->ServiceMain
[i] [1984][svchost.exe] Start Address of Thread 7ffb6a5aae10 in c:\windows\system32\wevtsvc.dll->ServiceMain
[i] [1984][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1984][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1984][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1992][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [1992][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1992][svchost.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [1992][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1992][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2004][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2004][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1784][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [1784][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1784][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1784][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1784][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1788][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [1788][svchost.exe] Start Address of Thread 7ffb6a3b2510 in c:\windows\system32\btagservice.dll->ServiceMain
[i] [1788][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2056][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2056][svchost.exe] Start Address of Thread 7ffb6a4ef3a0 in c:\windows\system32\bthavctpsvc.dll->DllGetClassObject
[i] [2056][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2056][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2056][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2084][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2084][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [2084][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2084][svchost.exe] Start Address of Thread 7ffb6a05d310 in C:\WINDOWS\SYSTEM32\Microsoft.Bluetooth.Service.dll->UnknownFunction
[i] [2084][svchost.exe] Start Address of Thread 7ffb6a065330 in C:\WINDOWS\SYSTEM32\Microsoft.Bluetooth.Service.dll->UnknownFunction
[i] [2084][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2084][svchost.exe] Start Address of Thread 7ffb6a4a7880 in c:\windows\system32\bthserv.dll->ServiceMain
[i] [2084][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2084][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2084][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2092][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2092][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2092][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2192][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2192][svchost.exe] Start Address of Thread 7ffb56959d00 in C:\WINDOWS\system32\WlanRadioManager.dll->DllGetClassObject
[i] [2192][svchost.exe] Start Address of Thread 7ffb6c88eac0 in C:\Windows\System32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [2192][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2192][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2252][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2252][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2252][svchost.exe] Start Address of Thread 7ffb66891890 in C:\WINDOWS\SYSTEM32\cmintegrator.dll->UnknownFunction
[i] [2252][svchost.exe] Start Address of Thread 7ffb69b82020 in c:\windows\system32\wcmsvc.dll->CdeGetProfileList
[i] [2252][svchost.exe] Start Address of Thread 7ffb6c88eac0 in C:\Windows\System32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [2252][svchost.exe] Start Address of Thread 7ffb6c8ca130 in C:\Windows\System32\wlanapi.dll->WlanVerifyProfileIpConfiguration
[i] [2252][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2252][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2252][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2252][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2252][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2252][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2264][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2264][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [2264][svchost.exe] Start Address of Thread 7ffb6970d6c0 in C:\WINDOWS\system32\dhcpcore6.dll->Dhcpv6Main
[i] [2264][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2264][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2264][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2264][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2264][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2264][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2516][IntelCpHDCPSvc.exe] Start Address of Thread 7ff6cf73ec10 in C:\WINDOWS\System32\DriverStore\FileRepository\64kb8682.inf_amd64_170ccd25b9699b84\IntelCpHDCPSvc.exe->UnknownFunction
[i] [2516][IntelCpHDCPSvc.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [2516][IntelCpHDCPSvc.exe] Start Address of Thread 7ff6cf726f80 in C:\WINDOWS\System32\DriverStore\FileRepository\64kb8682.inf_amd64_170ccd25b9699b84\IntelCpHDCPSvc.exe->UnknownFunction
[i] [2516][IntelCpHDCPSvc.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2528][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][svchost.exe] Start Address of Thread 7ffb5f3068e0 in C:\WINDOWS\SYSTEM32\SensorsNativeApi.V2.dll->SensorGetFifoMaxSizeV2
[i] [2528][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2632][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2632][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [2632][svchost.exe] Start Address of Thread 7ffb68681b80 in c:\windows\system32\hidserv.dll->ServiceMain
[i] [2632][svchost.exe] Start Address of Thread 7ffb686822c0 in c:\windows\system32\hidserv.dll->ServiceMain
[i] [2632][svchost.exe] Start Address of Thread 7ffb68682600 in c:\windows\system32\hidserv.dll->ServiceMain
[i] [2632][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2632][svchost.exe] Start Address of Thread 7ffb68682600 in c:\windows\system32\hidserv.dll->ServiceMain
[i] [2632][svchost.exe] Start Address of Thread 7ffb68682600 in c:\windows\system32\hidserv.dll->ServiceMain
[i] [2632][svchost.exe] Start Address of Thread 7ffb68682600 in c:\windows\system32\hidserv.dll->ServiceMain
[i] [2632][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2664][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2664][svchost.exe] Start Address of Thread 7ffb6847ff50 in c:\windows\system32\nlasvc.dll->UnknownFunction
[i] [2664][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [2664][svchost.exe] Start Address of Thread 7ffb683b1760 in C:\WINDOWS\System32\ssdpapi.dll->RegisterServiceEx
[i] [2664][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2664][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2672][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2672][svchost.exe] Start Address of Thread 7ffb684ffef0 in c:\windows\system32\umrdp.dll->SvchostPushServiceGlobals
[i] [2672][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2672][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2832][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2832][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [2832][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2832][svchost.exe] Start Address of Thread 7ffb67ad0870 in C:\WINDOWS\system32\taskcomp.dll->IsRegistering
[i] [2832][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2832][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2832][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2832][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2832][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2832][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2832][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2968][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2968][svchost.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [2968][svchost.exe] Start Address of Thread 7ffb677f6680 in c:\windows\system32\tabsvc.dll->UnknownFunction
[i] [2968][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3068][IntelCpHeciSvc.exe] Start Address of Thread 7ff7445c83b0 in C:\WINDOWS\System32\DriverStore\FileRepository\64kb8682.inf_amd64_170ccd25b9699b84\IntelCpHeciSvc.exe->UnknownFunction
[i] [3068][IntelCpHeciSvc.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [3068][IntelCpHeciSvc.exe] Start Address of Thread 7ff7445b7dd0 in C:\WINDOWS\System32\DriverStore\FileRepository\64kb8682.inf_amd64_170ccd25b9699b84\IntelCpHeciSvc.exe->UnknownFunction
[i] [3068][IntelCpHeciSvc.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2996][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2996][svchost.exe] Start Address of Thread 7ffb5387d020 in C:\WINDOWS\system32\dafBth.dll->DllCanUnloadNow
[i] [2996][svchost.exe] Start Address of Thread 7ffb5387d020 in C:\WINDOWS\system32\dafBth.dll->DllCanUnloadNow
[i] [2996][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2996][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3168][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3168][svchost.exe] Start Address of Thread 7ffb669dc220 in c:\windows\system32\netprofmsvc.dll->ServiceMain
[i] [3168][svchost.exe] Start Address of Thread 7ffb669db2d0 in c:\windows\system32\netprofmsvc.dll->ServiceMain
[i] [3168][svchost.exe] Start Address of Thread 7ffb669d5380 in c:\windows\system32\netprofmsvc.dll->UnknownFunction
[i] [3168][svchost.exe] Start Address of Thread 7ffb6c88eac0 in C:\Windows\System32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [3168][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3168][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3168][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3168][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3168][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [3168][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3168][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3168][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3204][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3204][svchost.exe] Start Address of Thread 7ffb669736f0 in c:\windows\system32\certprop.dll->UnknownFunction
[i] [3204][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3204][svchost.exe] Start Address of Thread 7ffb669736f0 in c:\windows\system32\certprop.dll->UnknownFunction
[i] [3204][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3228][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3228][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3288][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3288][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3288][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3288][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [3344][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3344][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [3344][svchost.exe] Start Address of Thread 7ffb6f179160 in C:\WINDOWS\system32\AUTHZ.dll->AuthzInitializeResourceManagerEx
[i] [3344][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3344][svchost.exe] Start Address of Thread 7ffb56f92e40 in C:\WINDOWS\system32\wbem\ncprov.dll->UnknownFunction
[i] [3344][svchost.exe] Start Address of Thread 7ffb60c43ca0 in C:\WINDOWS\SYSTEM32\NCObjAPI.DLL->WmiAddObjectProp
[i] [3344][svchost.exe] Start Address of Thread 7ffb60c43ca0 in C:\WINDOWS\SYSTEM32\NCObjAPI.DLL->WmiAddObjectProp
[i] [3344][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3344][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3344][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3344][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [3344][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3360][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3360][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3360][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3360][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3360][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3360][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3360][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3360][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3404][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3404][svchost.exe] Start Address of Thread 7ffb666311f0 in c:\windows\system32\dnsrslvr.dll->ServiceMain
[i] [3404][svchost.exe] Start Address of Thread 7ffb66633530 in c:\windows\system32\dnsrslvr.dll->ServiceMain
[i] [3404][svchost.exe] Start Address of Thread 7ffb666333a0 in c:\windows\system32\dnsrslvr.dll->ServiceMain
[i] [3404][svchost.exe] Start Address of Thread 7ffb66633e40 in c:\windows\system32\dnsrslvr.dll->ServiceMain
[i] [3404][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3404][svchost.exe] Start Address of Thread 7ffb6662eec0 in c:\windows\system32\dnsrslvr.dll->Reg_DoRegisterAdapter
[i] [3404][svchost.exe] Start Address of Thread 7ffb6662e010 in c:\windows\system32\dnsrslvr.dll->Reg_DoRegisterAdapter
[i] [3404][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3404][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3404][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3404][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3404][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3404][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3412][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3412][svchost.exe] Start Address of Thread 7ffb666b5350 in c:\windows\system32\wkssvc.dll->SvchostPushServiceGlobals
[i] [3412][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3412][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3412][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3628][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3628][svchost.exe] Start Address of Thread 7ffb62eb4d00 in c:\windows\system32\sessenv.dll->UnknownFunction
[i] [3628][svchost.exe] Start Address of Thread 7ffb62ebace0 in c:\windows\system32\sessenv.dll->ServiceMain
[i] [3628][svchost.exe] Start Address of Thread 7ffb62d37d40 in C:\WINDOWS\System32\RdvVmTransport.dll->RdvTransport_TerminateInstance
[i] [3628][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3628][svchost.exe] Start Address of Thread 7ffb62eba7a0 in c:\windows\system32\sessenv.dll->ServiceMain
[i] [3628][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3636][spaceman.exe] Start Address of Thread 7ff6b5a9d950 in C:\WINDOWS\system32\spaceman.exe->UnknownFunction
[i] [3636][spaceman.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3636][spaceman.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3680][vmms.exe] Start Address of Thread 7ff6db030010 in C:\WINDOWS\system32\vmms.exe->UnknownFunction
[i] [3680][vmms.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [3680][vmms.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [3680][vmms.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [3680][vmms.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [3680][vmms.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3680][vmms.exe] Start Address of Thread 7ffb69224030 in C:\WINDOWS\system32\RDPBASE.dll->CRdpFIPSEncryption_CreateInstance
[i] [3680][vmms.exe] Start Address of Thread 7ffb69224030 in C:\WINDOWS\system32\RDPBASE.dll->CRdpFIPSEncryption_CreateInstance
[i] [3680][vmms.exe] Start Address of Thread 7ffb69224030 in C:\WINDOWS\system32\RDPBASE.dll->CRdpFIPSEncryption_CreateInstance
[i] [3680][vmms.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [3680][vmms.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3680][vmms.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3712][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3712][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [3712][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3824][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3824][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [3824][svchost.exe] Start Address of Thread 7ffb62b18830 in c:\windows\system32\usermgr.dll->UnknownFunction
[i] [3824][svchost.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [3824][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3824][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3824][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3824][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3832][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3832][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [3832][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [3832][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [3832][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3832][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3992][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3992][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3992][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4048][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [4048][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4048][svchost.exe] Start Address of Thread 7ffb621ce880 in C:\WINDOWS\System32\ES.DLL->ServiceMain
[i] [4048][svchost.exe] Start Address of Thread 7ffb621cd300 in C:\WINDOWS\System32\ES.DLL->ServiceMain
[i] [4048][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4048][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4056][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [4056][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [4056][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4056][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4056][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4072][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [4072][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [4072][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4072][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3804][UNKNOWN] not analysed 31
[i] [2492][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2492][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2492][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3924][WUDFHost.exe] Start Address of Thread 7ff745b60d40 in C:\Windows\System32\WUDFHost.exe->UnknownFunction
[i] [3924][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3924][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3924][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3924][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3924][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4132][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [4132][svchost.exe] Start Address of Thread 7ffb6f179160 in C:\WINDOWS\system32\AUTHZ.dll->AuthzInitializeResourceManagerEx
[i] [4132][svchost.exe] Start Address of Thread 7ffb6f179160 in C:\WINDOWS\system32\AUTHZ.dll->AuthzInitializeResourceManagerEx
[i] [4132][svchost.exe] Start Address of Thread 7ffb6f179160 in C:\WINDOWS\system32\AUTHZ.dll->AuthzInitializeResourceManagerEx
[i] [4132][svchost.exe] Start Address of Thread 7ffb56422f10 in c:\windows\system32\mpssvc.dll->ServiceMain
[i] [4132][svchost.exe] Start Address of Thread 7ffb618937d0 in c:\windows\system32\bfe.dll->BfeGetDirectDispatchTable
[i] [4132][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4132][svchost.exe] Start Address of Thread 7ffb56428ab0 in c:\windows\system32\mpssvc.dll->ServiceMain
[i] [4132][svchost.exe] Start Address of Thread 7ffb5641f8e0 in c:\windows\system32\mpssvc.dll->UnknownFunction
[i] [4132][svchost.exe] Start Address of Thread 7ffb56427f40 in c:\windows\system32\mpssvc.dll->ServiceMain
[i] [4132][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4132][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4132][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4132][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4164][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [4164][svchost.exe] Start Address of Thread 7ffb61b25520 in c:\windows\system32\audioendpointbuilder.dll->UnknownFunction
[i] [4164][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4164][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4184][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [4184][svchost.exe] Start Address of Thread 7ffb61730080 in c:\windows\system32\fntcache.dll->UnknownFunction
[i] [4184][svchost.exe] Start Address of Thread 7ffb61761e80 in c:\windows\system32\fntcache.dll->ServiceMain
[i] [4184][svchost.exe] Start Address of Thread 7ffb61730080 in c:\windows\system32\fntcache.dll->UnknownFunction
[i] [4184][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4184][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4372][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [4372][svchost.exe] Start Address of Thread 7ffb6d4165d0 in C:\WINDOWS\system32\CoreMessaging.dll->SvchostPushServiceGlobals
[i] [4372][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4488][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [4488][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4508][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [4508][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4564][dashost.exe] Start Address of Thread 7ff70e81ea20 in C:\WINDOWS\system32\dashost.exe->UnknownFunction
[i] [4564][dashost.exe] Start Address of Thread 7ffb683b1760 in C:\WINDOWS\System32\ssdpapi.dll->RegisterServiceEx
[i] [4564][dashost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4564][dashost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4564][dashost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4564][dashost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4660][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [4660][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4660][svchost.exe] Start Address of Thread 7ffb5f231910 in c:\windows\system32\ssdpsrv.dll->SvchostPushServiceGlobals
[i] [4660][svchost.exe] Start Address of Thread 7ffb5f2363e0 in c:\windows\system32\ssdpsrv.dll->SvchostPushServiceGlobals
[i] [4660][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4660][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4660][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4660][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4660][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4740][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [4740][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [4740][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4740][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4740][svchost.exe] Start Address of Thread 7ffb5ec7cfd0 in c:\windows\system32\sensrsvc.dll->UnknownFunction
[i] [4740][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4740][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4740][svchost.exe] Start Address of Thread 7ffb5d8a1f60 in C:\WINDOWS\System32\RotMgr.dll->UnknownFunction
[i] [4740][svchost.exe] Start Address of Thread 7ffb5f3068e0 in C:\WINDOWS\SYSTEM32\SensorsNativeApi.V2.dll->SensorGetFifoMaxSizeV2
[i] [4740][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4772][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [4772][svchost.exe] Start Address of Thread 7ffb5ecadf60 in c:\windows\system32\sensorservice.dll->ServiceMain
[i] [4772][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4772][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4772][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4772][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4772][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5056][vmcompute.exe] Start Address of Thread 7ff636c65800 in C:\WINDOWS\system32\vmcompute.exe->ORSetKeySecurity
[i] [5056][vmcompute.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [5056][vmcompute.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2648][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2648][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2648][svchost.exe] Start Address of Thread 7ffb576e7d10 in c:\windows\system32\audiosrv.dll->ServiceMain
[i] [2648][svchost.exe] Start Address of Thread 7ffb576e9710 in c:\windows\system32\audiosrv.dll->ServiceMain
[i] [2648][svchost.exe] Start Address of Thread 7ffb57625b70 in c:\windows\system32\AUDIOSRVPOLICYMANAGER.dll->ActivatePolicyManager
[i] [2648][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2648][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2648][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2648][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2648][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2648][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2648][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [5252][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [5252][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5252][svchost.exe] Start Address of Thread 7ffb6c88eac0 in C:\Windows\System32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [5252][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5252][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5316][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [5316][svchost.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [5316][svchost.exe] Start Address of Thread 7ffb56972710 in C:\WINDOWS\SYSTEM32\wlgpclnt.dll->GenerateWLANPolicy
[i] [5316][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5316][svchost.exe] Start Address of Thread 7ffb6c88eac0 in C:\Windows\System32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [5316][svchost.exe] Start Address of Thread 7ffb568a17e0 in C:\WINDOWS\SYSTEM32\wifinetworkmanager.dll->DllGetClassObject
[i] [5316][svchost.exe] Start Address of Thread 7ffb6f179160 in C:\WINDOWS\system32\AUTHZ.dll->AuthzInitializeResourceManagerEx
[i] [5316][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5316][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5316][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5316][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5316][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5316][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5316][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5316][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5316][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5468][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [5468][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [5468][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5468][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [5468][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5512][spoolsv.exe] Start Address of Thread 7ff7df9e30c0 in C:\WINDOWS\System32\spoolsv.exe->PrvSplProcessSessionEvent
[i] [5512][spoolsv.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [5512][spoolsv.exe] Start Address of Thread 7ff7df9fec30 in C:\WINDOWS\System32\spoolsv.exe->PrvRouterInstallPrinterDriverPackageFromConnection
[i] [5512][spoolsv.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5512][spoolsv.exe] Start Address of Thread 7ffb3d63015c in C:\WINDOWS\System32\HPMPM081.DLL->InitializePrintMonitorUI
[i] [5512][spoolsv.exe] Start Address of Thread 7ffb3d62a7b0 in C:\WINDOWS\System32\HPMPM081.DLL->InitializePrintMonitorUI
[i] [5512][spoolsv.exe] Start Address of Thread 7ffb3d733500 in C:\WINDOWS\System32\PrintIsolationProxy.dll->Ordinal401
[i] [5512][spoolsv.exe] Start Address of Thread 7ffb3d7eb920 in C:\WINDOWS\System32\localspl.dll->InitializePrintMonitor2
[i] [5512][spoolsv.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5512][spoolsv.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5512][spoolsv.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5616][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [5616][svchost.exe] Start Address of Thread 7ffb566677a0 in c:\windows\system32\wbiosrvc.dll->OutOfProcessExceptionEventDebuggerLaunchCallback
[i] [5616][svchost.exe] Start Address of Thread 7ffb566677a0 in c:\windows\system32\wbiosrvc.dll->OutOfProcessExceptionEventDebuggerLaunchCallback
[i] [5616][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [5616][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5616][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [5616][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5616][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5616][svchost.exe] Start Address of Thread 7ffb559bdaa0 in C:\WINDOWS\system32\FaceProcessor.dll->FileInputManager_SendInfraredFrameData
[i] [5616][svchost.exe] Start Address of Thread 7ffb559bd9b0 in C:\WINDOWS\system32\FaceProcessor.dll->FileInputManager_SendInfraredFrameData
[i] [5616][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5616][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5776][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [5776][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [5776][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5776][svchost.exe] Start Address of Thread 7ffb625862a0 in C:\WINDOWS\system32\sscore.dll->SsCoreUnlockVolumes
[i] [5776][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5776][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5784][cb.exe] Start Address of Thread 7ff70a9fee30 in C:\WINDOWS\CarbonBlack\cb.exe->UnknownFunction
[i] [5784][cb.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [5784][cb.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5784][cb.exe] Start Address of Thread 7ff70a871a80 in C:\WINDOWS\CarbonBlack\cb.exe->UnknownFunction
[i] [5784][cb.exe] Start Address of Thread 7ff70a871a80 in C:\WINDOWS\CarbonBlack\cb.exe->UnknownFunction
[i] [5784][cb.exe] Start Address of Thread 7ff70a871a80 in C:\WINDOWS\CarbonBlack\cb.exe->UnknownFunction
[i] [5784][cb.exe] Start Address of Thread 7ff70a871a80 in C:\WINDOWS\CarbonBlack\cb.exe->UnknownFunction
[i] [5784][cb.exe] Start Address of Thread 7ff70a871a80 in C:\WINDOWS\CarbonBlack\cb.exe->UnknownFunction
[i] [5784][cb.exe] Start Address of Thread 7ff70a871a80 in C:\WINDOWS\CarbonBlack\cb.exe->UnknownFunction
[i] [5784][cb.exe] Start Address of Thread 7ff70a871a80 in C:\WINDOWS\CarbonBlack\cb.exe->UnknownFunction
[i] [5784][cb.exe] Start Address of Thread 7ff70a871a80 in C:\WINDOWS\CarbonBlack\cb.exe->UnknownFunction
[i] [5784][cb.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5784][cb.exe] Start Address of Thread 7ffb55de9ae0 in C:\WINDOWS\WinSxS\amd64_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.19041.1466_none_91a4907ccc87e3b8\gdiplus.dll->GdiplusStartup
[i] [5784][cb.exe] Start Address of Thread 7ff70a8624e0 in C:\WINDOWS\CarbonBlack\cb.exe->UnknownFunction
[i] [5784][cb.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5784][cb.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5796][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [5796][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5796][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5796][svchost.exe] Start Address of Thread 7ffb52798de0 in C:\WINDOWS\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [5796][svchost.exe] Start Address of Thread 7ffb52798de0 in C:\WINDOWS\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [5796][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5796][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5796][svchost.exe] Start Address of Thread 7ffb561f5600 in c:\windows\system32\cryptsvc.dll->UnknownFunction
[i] [5796][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5844][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [5844][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5844][svchost.exe] Start Address of Thread 7ffb5543f4a0 in c:\windows\system32\diagtrack.dll->UtcSysprepGeneralize
[i] [5844][svchost.exe] Start Address of Thread 7ffb5543f490 in c:\windows\system32\diagtrack.dll->UtcSysprepGeneralize
[i] [5844][svchost.exe] Start Address of Thread 7ffb5544b320 in c:\windows\system32\diagtrack.dll->UtcSysprepGeneralize
[i] [5844][svchost.exe] Start Address of Thread 7ffb5541aa80 in c:\windows\system32\diagtrack.dll->UtcSysprepGeneralize
[i] [5844][svchost.exe] Start Address of Thread 7ffb554b7ce0 in c:\windows\system32\diagtrack.dll->UtcSysprepGeneralize
[i] [5844][svchost.exe] Start Address of Thread 7ffb554b8d80 in c:\windows\system32\diagtrack.dll->UtcSysprepGeneralize
[i] [5844][svchost.exe] Start Address of Thread 7ffb5541aa90 in c:\windows\system32\diagtrack.dll->UtcSysprepGeneralize
[i] [5844][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5844][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5844][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5844][svchost.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [5844][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5844][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5844][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5872][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [5872][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [5872][svchost.exe] Start Address of Thread 7ffb54fe9eb0 in c:\windows\system32\dps.dll->ServiceMain
[i] [5872][svchost.exe] Start Address of Thread 7ffb54febc70 in c:\windows\system32\dps.dll->ServiceMain
[i] [5872][svchost.exe] Start Address of Thread 7ffb6c88eac0 in C:\Windows\System32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [5872][svchost.exe] Start Address of Thread 7ffb53821480 in C:\WINDOWS\System32\wpnsruprov.dll->UnknownFunction
[i] [5872][svchost.exe] Start Address of Thread 7ffb521900d0 in C:\WINDOWS\System32\appsruprov.dll->LogMemoryPerfCountersPeriodically
[i] [5872][svchost.exe] Start Address of Thread 7ffb52049ba0 in C:\WINDOWS\System32\energyprov.dll->SruInitializeProvider
[i] [5872][svchost.exe] Start Address of Thread 7ffb53cf42e0 in C:\WINDOWS\system32\radardt.dll->WdiHandleInstance
[i] [5872][svchost.exe] Start Address of Thread 7ffb53cf23a0 in C:\WINDOWS\system32\radardt.dll->WdiHandleInstance
[i] [5872][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5872][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5872][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5872][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5872][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5872][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5872][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5872][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5916][esif_uf.exe] Start Address of Thread 7ff7e8ba6e40 in C:\WINDOWS\System32\Intel\DPTF\esif_uf.exe->UnknownFunction
[i] [5916][esif_uf.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [5916][esif_uf.exe] Start Address of Thread 7ff7e8b984a0 in C:\WINDOWS\System32\Intel\DPTF\esif_uf.exe->UnknownFunction
[i] [5916][esif_uf.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5964][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [5964][svchost.exe] Start Address of Thread 7ffb57983a60 in C:\WINDOWS\system32\httpprxm.dll->SubServiceStart
[i] [5964][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5964][svchost.exe] Start Address of Thread 7ffb57962e20 in C:\WINDOWS\system32\adhsvc.dll->SubServiceScmNotification
[i] [5964][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6064][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [6064][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [6064][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6084][openvpnserv.exe] Start Address of Thread 401520 in C:\Program Files\OpenVPN\bin\openvpnserv.exe->UnknownFunction
[i] [6084][openvpnserv.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [6084][openvpnserv.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6092][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [6092][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [6092][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6100][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [6100][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6116][RtkAudUService64.exe] Start Address of Thread 7ff7643a1ab8 in C:\WINDOWS\System32\DriverStore\FileRepository\hdxsstm.inf_amd64_7d200f2580ecd8a5\RtkAudUService64.exe->UnknownFunction
[i] [6116][RtkAudUService64.exe] Start Address of Thread 7ff764349e00 in C:\WINDOWS\System32\DriverStore\FileRepository\hdxsstm.inf_amd64_7d200f2580ecd8a5\RtkAudUService64.exe->UnknownFunction
[i] [6116][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6116][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6116][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6116][RtkAudUService64.exe] Start Address of Thread 7ff76438dbd0 in C:\WINDOWS\System32\DriverStore\FileRepository\hdxsstm.inf_amd64_7d200f2580ecd8a5\RtkAudUService64.exe->UnknownFunction
[i] [6116][RtkAudUService64.exe] Start Address of Thread 7ff764349e00 in C:\WINDOWS\System32\DriverStore\FileRepository\hdxsstm.inf_amd64_7d200f2580ecd8a5\RtkAudUService64.exe->UnknownFunction
[i] [6116][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6116][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6116][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6116][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6116][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6116][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6116][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2568][sqlwriter.exe] Start Address of Thread 7ff6acbaeaf8 in C:\Program Files\Microsoft SQL Server\90\Shared\sqlwriter.exe->DmpRemoteDumpRequest
[i] [2568][sqlwriter.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [2568][sqlwriter.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3496][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3496][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [3496][svchost.exe] Start Address of Thread 7ffb54543e60 in c:\windows\system32\wiaservc.dll->UnknownFunction
[i] [3496][svchost.exe] Start Address of Thread 7ffb5454ecc0 in c:\windows\system32\wiaservc.dll->UnknownFunction
[i] [3496][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6152][SurfaceColorService.exe] Start Address of Thread 7ff7f02b1230 in C:\WINDOWS\System32\SurfaceColorService.exe->UnknownFunction
[i] [6152][SurfaceColorService.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6152][SurfaceColorService.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6316][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [6316][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6316][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6324][C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2111.5-0\MsMpEng.exe] not analysed 5
[i] [6332][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [6332][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6332][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [6332][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6332][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6332][svchost.exe] Start Address of Thread 7ffb6fbd1010 in C:\WINDOWS\system32\mswsock.dll->UnknownFunction
[i] [6332][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6364][com.docker.service] Start Address of Thread 2413a810000 in C:\Program Files\Docker\Docker\com.docker.service->UnknownFunction
[i] [6364][com.docker.service] Start Address of Thread 7ffb50d67c40 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->GC_Initialize
[i] [6364][com.docker.service] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [6364][com.docker.service] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6364][com.docker.service] Start Address of Thread 7ffb50bd9d10 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [6364][com.docker.service] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [6364][com.docker.service] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6376][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [6376][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [6376][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6376][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6528][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [6528][svchost.exe] Start Address of Thread 7ffb531773f0 in c:\windows\system32\tapisrv.dll->ServiceMain
[i] [6528][svchost.exe] Start Address of Thread 7ffb531773f0 in c:\windows\system32\tapisrv.dll->ServiceMain
[i] [6528][svchost.exe] Start Address of Thread 7ffb531773f0 in c:\windows\system32\tapisrv.dll->ServiceMain
[i] [6528][svchost.exe] Start Address of Thread 7ffb531773f0 in c:\windows\system32\tapisrv.dll->ServiceMain
[i] [6528][svchost.exe] Start Address of Thread 7ffb51b3da30 in C:\WINDOWS\System32\unimdm.tsp->uhelp
[i] [6528][svchost.exe] Start Address of Thread 7ffb51b11520 in C:\WINDOWS\System32\uniplat.dll->Ordinal198
[i] [6528][svchost.exe] Start Address of Thread 7ffb519930e0 in C:\WINDOWS\System32\kmddsp.tsp->UnknownFunction
[i] [6528][svchost.exe] Start Address of Thread 7ffb51981ab0 in C:\WINDOWS\System32\hidphone.tsp->UnknownFunction
[i] [6528][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6880][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [6880][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [6880][svchost.exe] Start Address of Thread 7ffb52472490 in C:\WINDOWS\System32\rastapi.DLL->CheckRasmanDependency
[i] [6880][svchost.exe] Start Address of Thread 7ffb5245d570 in C:\WINDOWS\System32\rastapi.DLL->UnknownFunction
[i] [6880][svchost.exe] Start Address of Thread 7ffb521c1ad0 in C:\WINDOWS\SYSTEM32\tapi32.dll->NonAsyncEventThread
[i] [6880][svchost.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [6880][svchost.exe] Start Address of Thread 7ffb52b89db0 in C:\WINDOWS\SYSTEM32\rasmans.dll->ServiceMain
[i] [6880][svchost.exe] Start Address of Thread 7ffb518b7a70 in C:\WINDOWS\system32\rasppp.dll->PppStop
[i] [6880][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6880][svchost.exe] Start Address of Thread 7ffb52bf5fe0 in C:\WINDOWS\SYSTEM32\rasmans.dll->NlmGetBestCostNetworkConnection
[i] [6880][svchost.exe] Start Address of Thread 7ffb52be1220 in C:\WINDOWS\SYSTEM32\rasmans.dll->NlmGetBestCostNetworkConnection
[i] [6880][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6880][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6880][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6880][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8156][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [8156][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8156][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3092][C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2111.5-0\NisSrv.exe] not analysed 5
[i] [8468][wmiprvse.exe] Start Address of Thread 7ff7546f2580 in C:\WINDOWS\system32\wbem\wmiprvse.exe->UnknownFunction
[i] [8468][wmiprvse.exe] Start Address of Thread 7ffb60c43ca0 in C:\WINDOWS\SYSTEM32\NCObjAPI.DLL->WmiAddObjectProp
[i] [8468][wmiprvse.exe] Start Address of Thread 7ff7546eb120 in C:\WINDOWS\system32\wbem\wmiprvse.exe->UnknownFunction
[i] [8468][wmiprvse.exe] Start Address of Thread 7ffb3dae74d0 in C:\WINDOWS\system32\wbem\wmipiprt.dll->DllUnregisterServer
[i] [8468][wmiprvse.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8468][wmiprvse.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9064][dptf_helper.exe] Start Address of Thread 7ff6ff6762d0 in C:\WINDOWS\system32\Intel\DPTF\dptf_helper.exe->UnknownFunction
[i] [9064][dptf_helper.exe] Start Address of Thread 7ff6ff675900 in C:\WINDOWS\system32\Intel\DPTF\dptf_helper.exe->UnknownFunction
[i] [9064][dptf_helper.exe] Start Address of Thread 7ff6ff674060 in C:\WINDOWS\system32\Intel\DPTF\dptf_helper.exe->UnknownFunction
[i] [9064][dptf_helper.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9192][sihost.exe] Start Address of Thread 7ff669535eb0 in C:\WINDOWS\system32\sihost.exe->UnknownFunction
[i] [9192][sihost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [9192][sihost.exe] Start Address of Thread 7ffb4caebef0 in C:\Windows\System32\modernexecserver.dll->UnknownFunction
[i] [9192][sihost.exe] Start Address of Thread 7ff669535050 in C:\WINDOWS\system32\sihost.exe->UnknownFunction
[i] [9192][sihost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9192][sihost.exe] Start Address of Thread 7ffb4ce265e0 in C:\WINDOWS\system32\activationmanager.dll->DllCanUnloadNow
[i] [9192][sihost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [9192][sihost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9192][sihost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9192][sihost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9192][sihost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [8264][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [8264][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [8264][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8264][svchost.exe] Start Address of Thread 7ffb56959d00 in C:\WINDOWS\system32\WlanRadioManager.dll->DllGetClassObject
[i] [8264][svchost.exe] Start Address of Thread 7ffb6c88eac0 in C:\Windows\System32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [8264][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8264][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8264][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8264][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8264][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8264][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [8264][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8264][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8264][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8264][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8420][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [8420][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8420][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8420][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8420][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8420][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [8420][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8420][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8420][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8492][SurfaceColorTracker.exe] Start Address of Thread 7ff70519730c in C:\WINDOWS\System32\SurfaceColorTracker.exe->UnknownFunction
[i] [8492][SurfaceColorTracker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8592][taskhostw.exe] Start Address of Thread 7ff6e0905bf0 in C:\WINDOWS\system32\taskhostw.exe->UnknownFunction
[i] [8592][taskhostw.exe] Start Address of Thread 7ff6e09012d0 in C:\WINDOWS\system32\taskhostw.exe->UnknownFunction
[i] [8592][taskhostw.exe] Start Address of Thread 7ffb4f501210 in C:\WINDOWS\System32\PlaySndSrv.dll->UnknownFunction
[i] [8592][taskhostw.exe] Start Address of Thread 7ffb519531b0 in C:\WINDOWS\System32\WINMM.dll->timeGetTime
[i] [8592][taskhostw.exe] Start Address of Thread 7ffb52798de0 in C:\WINDOWS\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [8592][taskhostw.exe] Start Address of Thread 7ffb52798de0 in C:\WINDOWS\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [8592][taskhostw.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8592][taskhostw.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8592][taskhostw.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8592][taskhostw.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7040][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [7040][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [7040][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7040][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7040][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7040][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3608][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3608][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [3608][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3608][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [3608][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [3608][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3608][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3608][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3608][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3608][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [3608][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8868][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [8868][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [8868][svchost.exe] Start Address of Thread 7ffb46fdd7a0 in C:\WINDOWS\system32\WwanRadioManager.dll->DllGetClassObject
[i] [8868][svchost.exe] Start Address of Thread 7ffb46fb99c0 in C:\WINDOWS\system32\XboxGipRadioManager.dll->DllUnregisterServer
[i] [8868][svchost.exe] Start Address of Thread 7ffb56959d00 in C:\WINDOWS\system32\WlanRadioManager.dll->DllGetClassObject
[i] [8868][svchost.exe] Start Address of Thread 7ffb6c88eac0 in C:\Windows\System32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [8868][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8868][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9176][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [9176][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][Explorer.EXE] Start Address of Thread 7ff642010ec0 in C:\WINDOWS\Explorer.EXE->UnknownFunction
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][Explorer.EXE] Start Address of Thread 7ff641f87b90 in C:\WINDOWS\Explorer.EXE->UnknownFunction
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb6efa0b10 in C:\WINDOWS\system32\sppc.dll->SLpVLActivateProduct
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb449ef540 in C:\Windows\System32\windows.immersiveshell.serviceprovider.dll->UnknownFunction
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb5ed76800 in C:\Windows\System32\InputHost.dll->DllGetActivationFactory
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb453f39a0 in C:\Windows\System32\twinui.pcshell.dll->DllGetClassObject
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb4529eff0 in C:\Windows\System32\twinui.pcshell.dll->DllCanUnloadNow
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb485a6ad0 in C:\WINDOWS\System32\wlidprov.dll->DllCanUnloadNow
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb485a6ad0 in C:\WINDOWS\System32\wlidprov.dll->DllCanUnloadNow
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb485a6ad0 in C:\WINDOWS\System32\wlidprov.dll->DllCanUnloadNow
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb6c88eac0 in C:\Windows\System32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb47adbd60 in C:\Windows\System32\TetheringStation.dll->TetheringStationFreeMemory
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb6c88eac0 in C:\Windows\System32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb6c88eac0 in C:\Windows\System32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb406226b0 in C:\WINDOWS\SYSTEM32\fxsst.dll->DllMain
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb41861c90 in C:\WINDOWS\SYSTEM32\msiltcfg.dll->RestartMsi
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb530235b0 in UnknownModule->UnknownFunction
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb519531b0 in C:\WINDOWS\System32\WINMM.dll->timeGetTime
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb37b2aad0 in C:\WINDOWS\SYSTEM32\DUI70.dll->DrawShadowTextEx
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb69c943f0 in C:\Windows\System32\WorkFoldersShell.dll->DllGetClassObject
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [9120][Explorer.EXE] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [9384][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [9384][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9384][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9720][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [9720][svchost.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [9720][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [9720][svchost.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [9720][svchost.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [9720][svchost.exe] Start Address of Thread 7ffb725e17d0 in C:\WINDOWS\System32\ole32.dll->UnknownFunction
[i] [9720][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9720][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9720][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6384][StartMenuExperienceHost.exe] Start Address of Thread 7ff7b6e93ef0 in C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe->UnknownFunction
[i] [6384][StartMenuExperienceHost.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [6384][StartMenuExperienceHost.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [6384][StartMenuExperienceHost.exe] Start Address of Thread 7ffb5f13f150 in C:\Windows\System32\MrmCoreR.dll->ShouldMergeInproc
[i] [6384][StartMenuExperienceHost.exe] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [6384][StartMenuExperienceHost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [6384][StartMenuExperienceHost.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [6384][StartMenuExperienceHost.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [6384][StartMenuExperienceHost.exe] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [6384][StartMenuExperienceHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6384][StartMenuExperienceHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6384][StartMenuExperienceHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6384][StartMenuExperienceHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6384][StartMenuExperienceHost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [6572][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [6572][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6572][svchost.exe] Start Address of Thread 7ffb72dc4fe0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleasePool
[i] [6572][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [6572][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6572][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6572][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6572][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7228][mousocoreworker.exe] Start Address of Thread 7ff7909f1860 in C:\Windows\System32\mousocoreworker.exe->StoreIsSpace
[i] [7228][mousocoreworker.exe] Start Address of Thread 7ffb72dc4fe0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleasePool
[i] [7228][mousocoreworker.exe] Start Address of Thread 7ffb72dc4fe0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleasePool
[i] [7228][mousocoreworker.exe] Start Address of Thread 7ff7908f7340 in C:\Windows\System32\mousocoreworker.exe->UnknownFunction
[i] [7228][mousocoreworker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7228][mousocoreworker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8456][RuntimeBroker.exe] Start Address of Thread 7ff691526740 in C:\Windows\System32\RuntimeBroker.exe->UnknownFunction
[i] [8456][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10748][RuntimeBroker.exe] Start Address of Thread 7ff691526740 in C:\Windows\System32\RuntimeBroker.exe->UnknownFunction
[i] [10748][RuntimeBroker.exe] Start Address of Thread 7ffb5ed76800 in C:\WINDOWS\SYSTEM32\InputHost.dll->DllGetActivationFactory
[i] [10748][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10748][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10748][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10748][RuntimeBroker.exe] Start Address of Thread 7ffb6efa0b10 in c:\windows\system32\sppc.dll->SLpVLActivateProduct
[i] [10748][RuntimeBroker.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [10748][RuntimeBroker.exe] Start Address of Thread 7ffb6c88eac0 in C:\WINDOWS\SYSTEM32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [10748][RuntimeBroker.exe] Start Address of Thread 7ffb47adbd60 in C:\Windows\System32\TetheringStation.dll->TetheringStationFreeMemory
[i] [10748][RuntimeBroker.exe] Start Address of Thread 7ffb6c88eac0 in C:\WINDOWS\SYSTEM32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [10748][RuntimeBroker.exe] Start Address of Thread 7ffb6c88eac0 in C:\WINDOWS\SYSTEM32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [10748][RuntimeBroker.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [10748][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11048][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [11048][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [11048][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11048][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11048][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11048][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11048][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10352][ctfmon.exe] Start Address of Thread 7ff7b2be11c0 in C:\WINDOWS\system32\ctfmon.exe->UnknownFunction
[i] [10352][ctfmon.exe] Start Address of Thread 7ffb72b2cd30 in C:\WINDOWS\System32\msctf.dll->TF_Notify
[i] [10352][ctfmon.exe] Start Address of Thread 7ffb4d7b4780 in C:\WINDOWS\system32\MsCtfMonitor.DLL->DoMsCtfMonitor
[i] [10352][ctfmon.exe] Start Address of Thread 7ffb38540ee0 in C:\WINDOWS\system32\InputService.dll->InitializeService
[i] [10352][ctfmon.exe] Start Address of Thread 7ffb38540d40 in C:\WINDOWS\system32\InputService.dll->InitializeService
[i] [10352][ctfmon.exe] Start Address of Thread 7ffb39258ac0 in C:\WINDOWS\system32\MTFServer.dll->DllCanUnloadNow
[i] [10352][ctfmon.exe] Start Address of Thread 7ffb39258ac0 in C:\WINDOWS\system32\MTFServer.dll->DllCanUnloadNow
[i] [10352][ctfmon.exe] Start Address of Thread 7ffb39258ac0 in C:\WINDOWS\system32\MTFServer.dll->DllCanUnloadNow
[i] [10352][ctfmon.exe] Start Address of Thread 7ffb5ed76800 in C:\WINDOWS\SYSTEM32\InputHost.dll->DllGetActivationFactory
[i] [10352][ctfmon.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11176][TabTip.exe] Start Address of Thread 7ff7dd49ae60 in C:\Program Files\Common Files\microsoft shared\ink\TabTip.exe->UnknownFunction
[i] [11176][TabTip.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [11176][TabTip.exe] Start Address of Thread 7ff7dd499f30 in C:\Program Files\Common Files\microsoft shared\ink\TabTip.exe->UnknownFunction
[i] [11176][TabTip.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [11176][TabTip.exe] Start Address of Thread 7ffb55de9ae0 in C:\WINDOWS\WinSxS\amd64_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.19041.1466_none_91a4907ccc87e3b8\gdiplus.dll->GdiplusStartup
[i] [11176][TabTip.exe] Start Address of Thread 7ffb4af2ecb0 in C:\Program Files\Common Files\Microsoft Shared\Ink\IpsPlugin.dll->DllUnregisterServer
[i] [11176][TabTip.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [11176][TabTip.exe] Start Address of Thread 7ffb41cd34e0 in C:\Program Files\Common Files\microsoft shared\ink\tabskb.dll->DllCanUnloadNow
[i] [11176][TabTip.exe] Start Address of Thread 7ff7dd4cc890 in C:\Program Files\Common Files\microsoft shared\ink\TabTip.exe->UnknownFunction
[i] [11176][TabTip.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11176][TabTip.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9264][TextInputHost.exe] Start Address of Thread 7ff7a2681300 in C:\WINDOWS\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\InputApp\TextInputHost.exe->UnknownFunction
[i] [9264][TextInputHost.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9264][TextInputHost.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [9264][TextInputHost.exe] Start Address of Thread 7ffb5f13f150 in C:\Windows\System32\MrmCoreR.dll->ShouldMergeInproc
[i] [9264][TextInputHost.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9264][TextInputHost.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [9264][TextInputHost.exe] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [9264][TextInputHost.exe] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [9264][TextInputHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9264][TextInputHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9264][TextInputHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8092][LockApp.exe] Start Address of Thread 7ff6b7eb2410 in C:\WINDOWS\SystemApps\Microsoft.LockApp_cw5n1h2txyewy\LockApp.exe->UnknownFunction
[i] [8092][LockApp.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [8092][LockApp.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [8092][LockApp.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [8092][LockApp.exe] Start Address of Thread 7ffb5f13f150 in C:\Windows\System32\MrmCoreR.dll->ShouldMergeInproc
[i] [8092][LockApp.exe] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [8092][LockApp.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [8092][LockApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8092][LockApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8092][LockApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8092][LockApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8092][LockApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8092][LockApp.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [8092][LockApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8092][LockApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11476][RuntimeBroker.exe] Start Address of Thread 7ff691526740 in C:\Windows\System32\RuntimeBroker.exe->UnknownFunction
[i] [11476][RuntimeBroker.exe] Start Address of Thread 7ffb40b0dea0 in C:\Windows\System32\lockappbroker.dll->UnknownFunction
[i] [11476][RuntimeBroker.exe] Start Address of Thread 7ffb6c88eac0 in C:\WINDOWS\SYSTEM32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [11476][RuntimeBroker.exe] Start Address of Thread 7ffb47adbd60 in C:\Windows\System32\TetheringStation.dll->TetheringStationFreeMemory
[i] [11476][RuntimeBroker.exe] Start Address of Thread 7ffb6c88eac0 in C:\WINDOWS\SYSTEM32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [11476][RuntimeBroker.exe] Start Address of Thread 7ffb6c88eac0 in C:\WINDOWS\SYSTEM32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [11476][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11476][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11476][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11476][RuntimeBroker.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [11476][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12112][SettingSyncHost.exe] Start Address of Thread 7ff7b9beb610 in C:\WINDOWS\system32\SettingSyncHost.exe->UnknownFunction
[i] [12112][SettingSyncHost.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [12112][SettingSyncHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12112][SettingSyncHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12000][DllHost.exe] Start Address of Thread 7ff7d92414e0 in C:\WINDOWS\system32\DllHost.exe->UnknownFunction
[i] [12000][DllHost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [12000][DllHost.exe] Start Address of Thread 7ffb52798de0 in C:\WINDOWS\SYSTEM32\ESENT.dll->JetEnableMultiInstanceA
[i] [12000][DllHost.exe] Start Address of Thread 7ffb52798de0 in C:\WINDOWS\SYSTEM32\ESENT.dll->JetEnableMultiInstanceA
[i] [12000][DllHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12000][DllHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12628][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\System32\svchost.exe->UnknownFunction
[i] [12628][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12628][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13048][SecurityHealthSystray.exe] Start Address of Thread 7ff6404c5a10 in C:\Windows\System32\SecurityHealthSystray.exe->UnknownFunction
[i] [13048][SecurityHealthSystray.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13112][C:\Windows\System32\SecurityHealthService.exe] not analysed 5
[i] [13188][RtkAudUService64.exe] Start Address of Thread 7ff7643a1ab8 in C:\Windows\System32\DriverStore\FileRepository\hdxsstm.inf_amd64_7d200f2580ecd8a5\RtkAudUService64.exe->UnknownFunction
[i] [13188][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13188][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13188][RtkAudUService64.exe] Start Address of Thread 7ff76438dbd0 in C:\Windows\System32\DriverStore\FileRepository\hdxsstm.inf_amd64_7d200f2580ecd8a5\RtkAudUService64.exe->UnknownFunction
[i] [13188][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13188][RtkAudUService64.exe] Start Address of Thread 7ff764349e00 in C:\Windows\System32\DriverStore\FileRepository\hdxsstm.inf_amd64_7d200f2580ecd8a5\RtkAudUService64.exe->UnknownFunction
[i] [13188][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13188][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12392][openvpn-gui.exe] Start Address of Thread 9714f0 in C:\Program Files\OpenVPN\bin\openvpn-gui.exe->UnknownFunction
[i] [12392][openvpn-gui.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12036][wmiprvse.exe] Start Address of Thread 7ff7546f2580 in C:\WINDOWS\system32\wbem\wmiprvse.exe->UnknownFunction
[i] [12036][wmiprvse.exe] Start Address of Thread 7ffb60c43ca0 in C:\WINDOWS\SYSTEM32\NCObjAPI.DLL->WmiAddObjectProp
[i] [12036][wmiprvse.exe] Start Address of Thread 7ff7546eb120 in C:\WINDOWS\system32\wbem\wmiprvse.exe->UnknownFunction
[i] [12036][wmiprvse.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12036][wmiprvse.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12036][wmiprvse.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6160][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\System32\svchost.exe->UnknownFunction
[i] [6160][svchost.exe] Start Address of Thread 7ffb39a22990 in c:\windows\system32\pcasvc.dll->UnknownFunction
[i] [6160][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6160][svchost.exe] Start Address of Thread 7ffb39a25cb0 in c:\windows\system32\pcasvc.dll->ServiceMain
[i] [6160][svchost.exe] Start Address of Thread 7ffb39a25b20 in c:\windows\system32\pcasvc.dll->ServiceMain
[i] [6160][svchost.exe] Start Address of Thread 7ffb39a35940 in c:\windows\system32\pcasvc.dll->PcaPatchSdbTask
[i] [6160][svchost.exe] Start Address of Thread 7ffb39a21060 in c:\windows\system32\pcasvc.dll->UnknownFunction
[i] [6160][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5932][Teams.exe] Start Address of Thread 7ff699475a70 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [5932][Teams.exe] Start Address of Thread 7ff6967933a0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->GetHandleVerifier
[i] [5932][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5932][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5932][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5932][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5932][Teams.exe] Start Address of Thread 7ff699482cb0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [5932][Teams.exe] Start Address of Thread 7ff699482cb0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [5932][Teams.exe] Start Address of Thread 7ff699482cb0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [5932][Teams.exe] Start Address of Thread 7ff699482cb0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [5932][Teams.exe] Start Address of Thread 7ff699482cb0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [5932][Teams.exe] Start Address of Thread 7ff699482cb0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [5932][Teams.exe] Start Address of Thread 7ff699482cb0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [5932][Teams.exe] Start Address of Thread 7ff699482cb0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [5932][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5932][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5932][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5932][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5932][Teams.exe] Start Address of Thread 7ff699482cb0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [5932][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5932][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5932][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5932][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5932][Teams.exe] Start Address of Thread 7ffb2e39bd50 in C:\Windows\System32\MsSpellCheckingFacility.dll->DllUnregisterServer
[i] [5932][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5932][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [5932][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [5932][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [5932][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [5932][Teams.exe] Start Address of Thread 7ffb56959d00 in C:\WINDOWS\system32\WlanRadioManager.dll->DllGetClassObject
[i] [5932][Teams.exe] Start Address of Thread 7ffb6c88eac0 in C:\WINDOWS\SYSTEM32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [5932][Teams.exe] Start Address of Thread 7ffb4447fa20 in \\?\C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\resources\app.asar.unpacked\node_modules\office-int-win\build\Release\office-int-win.node->UnknownFunction
[i] [5932][Teams.exe] Start Address of Thread 7ffb44462890 in \\?\C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\resources\app.asar.unpacked\node_modules\office-int-win\build\Release\office-int-win.node->UnknownFunction
[i] [5932][Teams.exe] Start Address of Thread 7ffb444731a0 in \\?\C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\resources\app.asar.unpacked\node_modules\office-int-win\build\Release\office-int-win.node->UnknownFunction
[i] [5932][Teams.exe] Start Address of Thread 7ffb4447c850 in \\?\C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\resources\app.asar.unpacked\node_modules\office-int-win\build\Release\office-int-win.node->UnknownFunction
[i] [5932][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5932][Teams.exe] Start Address of Thread 7ffb444750f0 in \\?\C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\resources\app.asar.unpacked\node_modules\office-int-win\build\Release\office-int-win.node->UnknownFunction
[i] [5932][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [5932][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5932][Teams.exe] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [5932][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5932][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5932][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5932][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [8280][GoogleCrashHandler64.exe] Start Address of Thread 7ff7bc8210cc in C:\Program Files (x86)\Google\Update\1.3.36.112\GoogleCrashHandler64.exe->UnknownFunction
[i] [8280][GoogleCrashHandler64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8280][GoogleCrashHandler64.exe] Start Address of Thread 7ff7bc81fca8 in C:\Program Files (x86)\Google\Update\1.3.36.112\GoogleCrashHandler64.exe->UnknownFunction
[i] [8280][GoogleCrashHandler64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12192][Teams.exe] Start Address of Thread 7ff699475a70 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [12192][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [12192][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [12192][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [12192][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [12192][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [12192][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12192][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [12192][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [12192][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [12192][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [12192][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [12192][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5756][Teams.exe] Start Address of Thread 7ff699475a70 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [5756][Teams.exe] Start Address of Thread 7ff6967933a0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->GetHandleVerifier
[i] [5756][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5756][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5756][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5756][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5756][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5756][Teams.exe] Start Address of Thread 7ffb6fbd1010 in C:\WINDOWS\system32\mswsock.dll->UnknownFunction
[i] [5756][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5756][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5756][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5756][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [11084][Teams.exe] Start Address of Thread 7ff699475a70 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [11084][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [11084][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [11084][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [11084][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11084][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [11084][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [11084][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [11084][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [11084][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [11084][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [11084][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [11084][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [11084][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [11084][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10756][Teams.exe] Start Address of Thread 7ff699475a70 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [10756][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10756][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13412][Teams.exe] Start Address of Thread 7ff699475a70 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [13412][Teams.exe] Start Address of Thread 7ff6967933a0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->GetHandleVerifier
[i] [13412][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [13412][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [13412][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [13412][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13412][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [13412][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [13412][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13412][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13632][slack.exe] Start Address of Thread 7ff7e0f16540 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [13632][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13632][slack.exe] Start Address of Thread 7ff7df94bb30 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->GetHandleVerifier
[i] [13632][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13632][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13632][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13632][slack.exe] Start Address of Thread 7ff7e0f255c0 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [13632][slack.exe] Start Address of Thread 7ff7e0f255c0 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [13632][slack.exe] Start Address of Thread 7ff7e0f255c0 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [13632][slack.exe] Start Address of Thread 7ff7e0f255c0 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [13632][slack.exe] Start Address of Thread 7ff7e0f255c0 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [13632][slack.exe] Start Address of Thread 7ff7e0f255c0 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [13632][slack.exe] Start Address of Thread 7ff7e0f255c0 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [13632][slack.exe] Start Address of Thread 7ff7e0f255c0 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [13632][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13632][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13632][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13632][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13632][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13632][slack.exe] Start Address of Thread 7ff7e0f255c0 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [13632][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13632][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13632][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13632][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13632][slack.exe] Start Address of Thread 7ffb2e39bd50 in C:\Windows\System32\MsSpellCheckingFacility.dll->DllUnregisterServer
[i] [13632][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13632][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13632][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13632][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14208][slack.exe] Start Address of Thread 7ff7e0f16540 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [14208][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [14208][slack.exe] Start Address of Thread 7ff7e00c8580 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->node::FatalException
[i] [14208][slack.exe] Start Address of Thread 7ff7e00c8580 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->node::FatalException
[i] [14208][slack.exe] Start Address of Thread 7ff7e00c8580 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->node::FatalException
[i] [14208][slack.exe] Start Address of Thread 7ff7dfc85ed0 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_fs_poll_getpath
[i] [14208][slack.exe] Start Address of Thread 7ff7dfc85ed0 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_fs_poll_getpath
[i] [14208][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13536][slack.exe] Start Address of Thread 7ff7e0f16540 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [13536][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13536][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13536][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13536][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13536][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13536][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13536][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13536][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13536][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13536][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13536][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13536][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13536][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13648][slack.exe] Start Address of Thread 7ff7e0f16540 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [13648][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13648][slack.exe] Start Address of Thread 7ff7df94bb30 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->GetHandleVerifier
[i] [13648][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13648][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13648][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13648][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13648][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13648][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13648][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13648][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13800][Cortana.exe] Start Address of Thread 7ff70c138000 in C:\Program Files\WindowsApps\Microsoft.549981C3F5F10_3.2110.13603.0_x64__8wekyb3d8bbwe\Cortana.exe->UnknownFunction
[i] [13800][Cortana.exe] Start Address of Thread 7ffb2e49c130 in C:\Program Files\WindowsApps\Microsoft.NET.Native.Runtime.2.2_2.2.28604.0_x64__8wekyb3d8bbwe\mrt100_app.dll->RhpSendCustomEventToDebugger
[i] [13800][Cortana.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [13800][Cortana.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [13800][Cortana.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [13800][Cortana.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13800][Cortana.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [13800][Cortana.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [13800][Cortana.exe] Start Address of Thread 7ffb5f13f150 in C:\Windows\System32\MrmCoreR.dll->ShouldMergeInproc
[i] [13800][Cortana.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [13800][Cortana.exe] Start Address of Thread 7ffb572d3440 in C:\Windows\System32\Windows.Media.Devices.dll->DllGetClassObject
[i] [13800][Cortana.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13800][Cortana.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13800][Cortana.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13800][Cortana.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13800][Cortana.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [13800][Cortana.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13928][slack.exe] Start Address of Thread 7ff7e0f16540 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [13928][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13928][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13928][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13928][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13928][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13928][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13928][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13928][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13928][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13928][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13928][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13928][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13928][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13928][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13928][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13928][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ff6b692c1b0 in C:\Program Files\Microsoft Office\Office16\OUTLOOK.EXE->UnknownFunction
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e3188 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal899
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb356dd740 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso40uiwin32client.dll->Ordinal957
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb356ede34 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso40uiwin32client.dll->Ordinal452
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 711fe5f8 in C:\WINDOWS\SYSTEM32\PGPsdk.dll->PGPGetIndexedSymmetricCipherInfo
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb445e9dc0 in C:\Program Files\PGP Corporation\PGP Desktop\PGPMSMDB.DLL->HrTrustedPSTOverrideHandlerCallback
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb445ed490 in C:\Program Files\PGP Corporation\PGP Desktop\PGPMSMDB.DLL->IsTransportLoaded
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb03909dc0 in C:\Program Files\PGP Corporation\PGP Desktop\PGPMSPST.DLL->HrTrustedPSTOverrideHandlerCallback
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb0390d490 in C:\Program Files\PGP Corporation\PGP Desktop\PGPMSPST.DLL->IsTransportLoaded
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb042709e4 in C:\Program Files\Microsoft Office\Office16\MSPST32.DLL->MSProviderInit
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb042709e4 in C:\Program Files\Microsoft Office\Office16\MSPST32.DLL->MSProviderInit
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ff6b6a6ed44 in C:\Program Files\Microsoft Office\Office16\OUTLOOK.EXE->OutlookSyncEventOccurredEx
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb055a3308 in C:\Program Files\Microsoft Office\Office16\ADDINS\BCSAddin.dll->DllGetClassObject
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb50d67c40 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->GC_Initialize
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb10761c94 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso99Lwin32client.dll->Ordinal2177
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb06174924 in C:\Program Files\Microsoft Office\Office16\wwlib.dll->PTLS7::FsValidateReuse
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb519531b0 in C:\WINDOWS\SYSTEM32\WINMM.dll->timeGetTime
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb06174924 in C:\Program Files\Microsoft Office\Office16\wwlib.dll->PTLS7::FsValidateReuse
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb41861c90 in C:\WINDOWS\SYSTEM32\msiltcfg.dll->RestartMsi
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][OUTLOOK.EXE] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [7952][POWERPNT.EXE] Start Address of Thread 7ff7780514c4 in C:\Program Files\Microsoft Office\Office16\POWERPNT.EXE->UnknownFunction
[i] [7952][POWERPNT.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [7952][POWERPNT.EXE] Start Address of Thread 7ffb473e3188 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal899
[i] [7952][POWERPNT.EXE] Start Address of Thread 7ffb356dd740 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso40uiwin32client.dll->Ordinal957
[i] [7952][POWERPNT.EXE] Start Address of Thread 7ffb356ede34 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso40uiwin32client.dll->Ordinal452
[i] [7952][POWERPNT.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [7952][POWERPNT.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [7952][POWERPNT.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [7952][POWERPNT.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7952][POWERPNT.EXE] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [7952][POWERPNT.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [7952][POWERPNT.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7952][POWERPNT.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7952][POWERPNT.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4316][PGPcbt64.exe] Start Address of Thread 7ff723fd13ac in C:\Program Files (x86)\PGP Corporation\PGP Desktop\PGPcbt64.exe->UnknownFunction
[i] [4316][PGPcbt64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9916][RuntimeBroker.exe] Start Address of Thread 7ff691526740 in C:\Windows\System32\RuntimeBroker.exe->UnknownFunction
[i] [9916][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9916][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9916][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14604][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [14604][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [14604][svchost.exe] Start Address of Thread 7ffb4042bfd0 in c:\windows\system32\agentactivationruntimewindows.dll->GetAgentActivationRuntimePalComponentFactory
[i] [14604][svchost.exe] Start Address of Thread 7ffb4042bfd0 in c:\windows\system32\agentactivationruntimewindows.dll->GetAgentActivationRuntimePalComponentFactory
[i] [14604][svchost.exe] Start Address of Thread 7ffb4044c840 in c:\windows\system32\agentactivationruntimewindows.dll->GetAgentActivationRuntimePalComponentFactory
[i] [14604][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14604][svchost.exe] Start Address of Thread 7ffb40466f40 in c:\windows\system32\agentactivationruntimewindows.dll->GetAgentActivationRuntimePalComponentFactory
[i] [14604][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14604][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14604][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14604][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14604][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14604][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14604][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14592][Teams.exe] Start Address of Thread 7ff699475a70 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [14592][Teams.exe] Start Address of Thread 7ff6967933a0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->GetHandleVerifier
[i] [14592][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [14592][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [14592][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [14592][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14592][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [14592][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [14592][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [14592][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [14592][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [14592][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [14592][Teams.exe] Start Address of Thread 7ff699482cb0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [14592][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ffb40e44dc0 in \\?\C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\resources\app.asar.unpacked\node_modules\slimcore\bin\RtmPal.dll->UnknownFunction
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ff699482cb0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [14592][Teams.exe] Start Address of Thread 7ff699482cb0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [14592][Teams.exe] Start Address of Thread 7ff699482cb0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [14592][Teams.exe] Start Address of Thread 7ff699482cb0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ffb69945030 in C:\WINDOWS\System32\perfos.dll->OpenOSObject
[i] [14592][Teams.exe] Start Address of Thread 7ffb699313a0 in C:\WINDOWS\System32\perfdisk.dll->UnknownFunction
[i] [14592][Teams.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [14592][Teams.exe] Start Address of Thread 7ffb097ef9e0 in C:\WINDOWS\SYSTEM32\d3d9.dll->Direct3DShaderValidatorCreate9
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [14592][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14592][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [14592][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [14592][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11152][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [11152][svchost.exe] Start Address of Thread 7ffb6c88eac0 in C:\WINDOWS\SYSTEM32\Wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [11152][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11152][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11732][C:\Windows\System32\SgrmBroker.exe] not analysed 5
[i] [8988][C:\Windows\System32\svchost.exe] not analysed 5
[i] [9364][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [9364][svchost.exe] Start Address of Thread 7ffb52798de0 in c:\windows\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [9364][svchost.exe] Start Address of Thread 7ffb52798de0 in c:\windows\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [9364][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14844][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [14844][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [14844][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6432][ApplicationFrameHost.exe] Start Address of Thread 7ff7e3be2a30 in C:\WINDOWS\system32\ApplicationFrameHost.exe->UnknownFunction
[i] [6432][ApplicationFrameHost.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\SHCORE.dll->Ordinal172
[i] [6432][ApplicationFrameHost.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\SHCORE.dll->Ordinal172
[i] [6432][ApplicationFrameHost.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\SHCORE.dll->Ordinal172
[i] [6432][ApplicationFrameHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6432][ApplicationFrameHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16244][Calculator.exe] Start Address of Thread 7ff7849b78dc in C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_10.2103.8.0_x64__8wekyb3d8bbwe\Calculator.exe->VSDesignerDllMain
[i] [16244][Calculator.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16244][Calculator.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [16244][Calculator.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16244][Calculator.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\SHCORE.dll->Ordinal172
[i] [16244][Calculator.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [16244][Calculator.exe] Start Address of Thread 7ffb5f13f150 in C:\WINDOWS\SYSTEM32\mrmcorer.dll->ShouldMergeInproc
[i] [16244][Calculator.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\SHCORE.dll->SHStrDupW
[i] [16244][Calculator.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16244][Calculator.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [16244][Calculator.exe] Start Address of Thread 7ffb68714070 in C:\Program Files\WindowsApps\Microsoft.VCLibs.140.00_14.0.30704.0_x64__8wekyb3d8bbwe\CONCRT140_APP.dll->Concurrency::set_task_execution_resources
[i] [16244][Calculator.exe] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [16244][Calculator.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16244][Calculator.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16244][Calculator.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16244][Calculator.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16244][Calculator.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16244][Calculator.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [16244][Calculator.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16244][Calculator.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16244][Calculator.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12500][RuntimeBroker.exe] Start Address of Thread 7ff691526740 in C:\Windows\System32\RuntimeBroker.exe->UnknownFunction
[i] [12500][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12600][SystemSettings.exe] Start Address of Thread 7ff71ffa40c0 in C:\Windows\ImmersiveControlPanel\SystemSettings.exe->UnknownFunction
[i] [12600][SystemSettings.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12600][SystemSettings.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [12600][SystemSettings.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\SHCORE.dll->Ordinal172
[i] [12600][SystemSettings.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [12600][SystemSettings.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\SHCORE.dll->SHStrDupW
[i] [12600][SystemSettings.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12600][SystemSettings.exe] Start Address of Thread 7ffb6efa0b10 in C:\WINDOWS\SYSTEM32\sppc.dll->SLpVLActivateProduct
[i] [12600][SystemSettings.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\SHCORE.dll->Ordinal172
[i] [12600][SystemSettings.exe] Start Address of Thread 7ffb5ed76800 in C:\Windows\System32\InputHost.dll->DllGetActivationFactory
[i] [12600][SystemSettings.exe] Start Address of Thread 7ffb6c88eac0 in C:\WINDOWS\SYSTEM32\Wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [12600][SystemSettings.exe] Start Address of Thread 7ffb47adbd60 in C:\WINDOWS\SYSTEM32\TetheringStation.dll->TetheringStationFreeMemory
[i] [12600][SystemSettings.exe] Start Address of Thread 7ffb6c88eac0 in C:\WINDOWS\SYSTEM32\Wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [12600][SystemSettings.exe] Start Address of Thread 7ffb6c88eac0 in C:\WINDOWS\SYSTEM32\Wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [12600][SystemSettings.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12600][SystemSettings.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [12600][SystemSettings.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12600][SystemSettings.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12600][SystemSettings.exe] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [12600][SystemSettings.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\SHCORE.dll->SHStrDupW
[i] [12600][SystemSettings.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [12600][SystemSettings.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16356][UserOOBEBroker.exe] Start Address of Thread 7ff68b477390 in C:\Windows\System32\oobe\UserOOBEBroker.exe->UnknownFunction
[i] [16356][UserOOBEBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16356][UserOOBEBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16356][UserOOBEBroker.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [13924][RuntimeBroker.exe] Start Address of Thread 7ff691526740 in C:\Windows\System32\RuntimeBroker.exe->UnknownFunction
[i] [13924][RuntimeBroker.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [13924][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13924][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][SearchIndexer.exe] Start Address of Thread 7ff604caa630 in C:\WINDOWS\system32\SearchIndexer.exe->UnknownFunction
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb52798de0 in c:\windows\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb52798de0 in c:\windows\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb52798de0 in c:\windows\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb47f5f740 in C:\WINDOWS\system32\tquery.dll->DllCanUnloadNow
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb4af253c0 in C:\Program Files\Common Files\Microsoft Shared\Ink\IpsPlugin.dll->DllGetClassObject
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb4827ac70 in C:\WINDOWS\system32\MSSRCH.DLL->CSearchServiceObj::CSearchServiceObj
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb4827a120 in C:\WINDOWS\system32\MSSRCH.DLL->CSearchServiceObj::CSearchServiceObj
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb48271cf0 in C:\WINDOWS\system32\MSSRCH.DLL->CSearchServiceObj::Initialize
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb48260380 in C:\WINDOWS\system32\MSSRCH.DLL->CSearchServiceObj::~CSearchServiceObj
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb47f5f740 in C:\WINDOWS\system32\tquery.dll->DllCanUnloadNow
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb47f5f740 in C:\WINDOWS\system32\tquery.dll->DllCanUnloadNow
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb47f5f740 in C:\WINDOWS\system32\tquery.dll->DllCanUnloadNow
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [956][SearchIndexer.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\SHCORE.dll->SHStrDupW
[i] [244][msedgewebview2.exe] Start Address of Thread 7ff7cc7c1690 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedgewebview2.exe->INetworkConnectionFactory::operator=
[i] [244][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][msedgewebview2.exe] Start Address of Thread 7ff7cc752d10 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedgewebview2.exe->INetworkConnectionFactory::operator=
[i] [244][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [244][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][msedgewebview2.exe] Start Address of Thread 7ffb4a752270 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\oneds.dll->Microsoft::Applications::Events::EventProperty::EventProperty
[i] [244][msedgewebview2.exe] Start Address of Thread 7ffb4a752270 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\oneds.dll->Microsoft::Applications::Events::EventProperty::EventProperty
[i] [244][msedgewebview2.exe] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [244][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [244][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [244][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [6624][msedgewebview2.exe] Start Address of Thread 7ff7cc7c1690 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedgewebview2.exe->INetworkConnectionFactory::operator=
[i] [6624][msedgewebview2.exe] Start Address of Thread 7ff7cc7fdba0 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedgewebview2.exe->INetworkConnectionFactory::operator=
[i] [6624][msedgewebview2.exe] Start Address of Thread 7ff7cc91a780 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedgewebview2.exe->IsSandboxedProcess
[i] [6624][msedgewebview2.exe] Start Address of Thread 7ff7cc91a780 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedgewebview2.exe->IsSandboxedProcess
[i] [6624][msedgewebview2.exe] Start Address of Thread 7ff7cc91a780 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedgewebview2.exe->IsSandboxedProcess
[i] [6624][msedgewebview2.exe] Start Address of Thread 7ff7cc757a30 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedgewebview2.exe->INetworkConnectionFactory::operator=
[i] [6624][msedgewebview2.exe] Start Address of Thread 7ff7cc757a30 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedgewebview2.exe->INetworkConnectionFactory::operator=
[i] [6624][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11936][msedgewebview2.exe] Start Address of Thread 7ff7cc7c1690 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedgewebview2.exe->INetworkConnectionFactory::operator=
[i] [11936][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [11936][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [11936][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [11936][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [11936][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [11936][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [11936][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11936][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [11936][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [11936][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [11936][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [11936][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [11936][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [11936][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11936][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11936][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8304][msedgewebview2.exe] Start Address of Thread 7ff7cc7c1690 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedgewebview2.exe->INetworkConnectionFactory::operator=
[i] [8304][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8304][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8304][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8304][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8304][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8304][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8304][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8304][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8304][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7172][msedgewebview2.exe] Start Address of Thread 7ff7cc7c1690 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedgewebview2.exe->INetworkConnectionFactory::operator=
[i] [7172][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [7172][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [7172][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [7172][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [7172][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [7172][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [7172][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8836][msedgewebview2.exe] Start Address of Thread 7ff7cc7c1690 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedgewebview2.exe->INetworkConnectionFactory::operator=
[i] [8836][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8836][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8836][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8836][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8836][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8836][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8836][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8836][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8836][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8836][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8836][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8836][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8836][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8836][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [15904][msedgewebview2.exe] Start Address of Thread 7ff7cc7c1690 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedgewebview2.exe->INetworkConnectionFactory::operator=
[i] [15904][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15904][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15904][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15904][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15904][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15904][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [15904][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15904][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15904][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15904][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15904][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15904][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15904][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15904][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [15904][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2716][Video.UI.exe] Start Address of Thread 7ff7b97235f0 in C:\Program Files\WindowsApps\Microsoft.ZuneVideo_10.21111.10511.0_x64__8wekyb3d8bbwe\Video.UI.exe->UnknownFunction
[i] [2716][Video.UI.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [2716][Video.UI.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [2716][Video.UI.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [2716][Video.UI.exe] Start Address of Thread 7ffb68714070 in C:\Program Files\WindowsApps\Microsoft.VCLibs.140.00_14.0.30704.0_x64__8wekyb3d8bbwe\CONCRT140_APP.dll->Concurrency::set_task_execution_resources
[i] [2716][Video.UI.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [2716][Video.UI.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [2716][Video.UI.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [2716][Video.UI.exe] Start Address of Thread 7ffb52798de0 in C:\WINDOWS\SYSTEM32\ESENT.dll->JetEnableMultiInstanceA
[i] [2716][Video.UI.exe] Start Address of Thread 7ffb52798de0 in C:\WINDOWS\SYSTEM32\ESENT.dll->JetEnableMultiInstanceA
[i] [2716][Video.UI.exe] Start Address of Thread 7ffb5f13f150 in C:\Windows\System32\MrmCoreR.dll->ShouldMergeInproc
[i] [2716][Video.UI.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2716][Video.UI.exe] Start Address of Thread 7ffb706abeb0 in C:\WINDOWS\System32\CRYPT32.dll->CertFreeCTLContext
[i] [2716][Video.UI.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [2716][Video.UI.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2716][Video.UI.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [2716][Video.UI.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2716][Video.UI.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4988][RuntimeBroker.exe] Start Address of Thread 7ff691526740 in C:\Windows\System32\RuntimeBroker.exe->UnknownFunction
[i] [4988][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14484][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 2486e40fe96 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\ServiceHub\controller\Microsoft.ServiceHub.Controller.exe->UnknownFunction
[i] [14484][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb50d67c40 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->GC_Initialize
[i] [14484][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [14484][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb50bd9d10 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [14484][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb52a08e40 in C:\WINDOWS\SYSTEM32\rasman.dll->RasSignalMonitorThreadExit
[i] [14484][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb50d21ac0 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->GetMetaDataPublicInterfaceFromInternal
[i] [14484][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14484][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14484][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [14484][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [14484][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14484][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [9508][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [9508][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [9508][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9508][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5668][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [5668][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [5668][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5188][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [5188][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [5188][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [15780][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [15780][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [15780][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9472][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [9472][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [9472][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4012][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [4012][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [4012][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8200][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [8200][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [8200][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7716][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [7716][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [7716][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12684][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [12684][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [12684][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5564][git-bash.exe] Start Address of Thread c11520 in C:\Program Files\Git\git-bash.exe->UnknownFunction
[i] [5564][git-bash.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1672][mintty.exe] Start Address of Thread 100401000 in C:\Program Files\Git\usr\bin\mintty.exe->UnknownFunction
[i] [1672][mintty.exe] Start Address of Thread 180046eb0 in C:\Program Files\Git\usr\bin\msys-2.0.dll->setprogname
[i] [1672][mintty.exe] Start Address of Thread 180046eb0 in C:\Program Files\Git\usr\bin\msys-2.0.dll->setprogname
[i] [1672][mintty.exe] Start Address of Thread 180046eb0 in C:\Program Files\Git\usr\bin\msys-2.0.dll->setprogname
[i] [1672][mintty.exe] Start Address of Thread 180046eb0 in C:\Program Files\Git\usr\bin\msys-2.0.dll->setprogname
[i] [1672][mintty.exe] Start Address of Thread 180046eb0 in C:\Program Files\Git\usr\bin\msys-2.0.dll->setprogname
[i] [1672][mintty.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5868][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [5868][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [5868][conhost.exe] Start Address of Thread 7ff62eef4a90 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [5868][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10380][bash.exe] Start Address of Thread 100401000 in C:\Program Files\Git\usr\bin\mintty.exe->UnknownFunction
[i] [10380][bash.exe] Start Address of Thread 180046eb0 in C:\Program Files\Git\usr\bin\msys-2.0.dll->setprogname
[i] [10380][bash.exe] Start Address of Thread 180046eb0 in C:\Program Files\Git\usr\bin\msys-2.0.dll->setprogname
[i] [10380][bash.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8792][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [8792][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [8792][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2804][ServiceHub.TestWindowStoreHost.exe] Start Address of Thread 1e5a6e53072 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\ServiceHub\Hosts\ServiceHub.Host.CLR.AnyCPU\ServiceHub.TestWindowStoreHost.exe->UnknownFunction
[i] [2804][ServiceHub.TestWindowStoreHost.exe] Start Address of Thread 7ffb50d67c40 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->GC_Initialize
[i] [2804][ServiceHub.TestWindowStoreHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [2804][ServiceHub.TestWindowStoreHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [2804][ServiceHub.TestWindowStoreHost.exe] Start Address of Thread 7ffb50bd9d10 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [2804][ServiceHub.TestWindowStoreHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [2804][ServiceHub.TestWindowStoreHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [2804][ServiceHub.TestWindowStoreHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13612][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [13612][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [13612][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17152][cmd.exe] Start Address of Thread 7ff79a6e8f50 in C:\WINDOWS\system32\cmd.exe->UnknownFunction
[i] [17152][cmd.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17152][cmd.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17300][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [17300][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [17300][conhost.exe] Start Address of Thread 7ff62eef4a90 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [17300][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17300][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 1631d120000 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\ServiceHub\Hosts\ServiceHub.Host.CLR.x64\ServiceHub.DataWarehouseHost.exe->UnknownFunction
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50d67c40 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->GC_Initialize
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bd9d10 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb52a08e40 in C:\WINDOWS\SYSTEM32\rasman.dll->RasSignalMonitorThreadExit
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb55de9ae0 in C:\WINDOWS\WinSxS\amd64_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.19041.1466_none_91a4907ccc87e3b8\gdiplus.dll->GdiplusStartup
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [17096][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17316][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [17316][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [17316][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [15252][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\System32\svchost.exe->UnknownFunction
[i] [15252][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [15252][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [15252][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17068][taskhostw.exe] Start Address of Thread 7ff6e0905bf0 in C:\WINDOWS\system32\taskhostw.exe->UnknownFunction
[i] [17068][taskhostw.exe] Start Address of Thread 7ff6e09012d0 in C:\WINDOWS\system32\taskhostw.exe->UnknownFunction
[i] [17068][taskhostw.exe] Start Address of Thread 7ffb578f20f0 in c:\windows\system32\wdi.dll->WdipLaunchLocalHost
[i] [17068][taskhostw.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17068][taskhostw.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13008][Microsoft.Photos.exe] Start Address of Thread 7ff66793b000 in C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2021.21090.10008.0_x64__8wekyb3d8bbwe\Microsoft.Photos.exe->UnknownFunction
[i] [13008][Microsoft.Photos.exe] Start Address of Thread 7ffb2e49c130 in C:\Program Files\WindowsApps\Microsoft.NET.Native.Runtime.2.2_2.2.28604.0_x64__8wekyb3d8bbwe\mrt100_app.dll->RhpSendCustomEventToDebugger
[i] [13008][Microsoft.Photos.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [13008][Microsoft.Photos.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [13008][Microsoft.Photos.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [13008][Microsoft.Photos.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [13008][Microsoft.Photos.exe] Start Address of Thread 7ffb5f13f150 in C:\Windows\System32\MrmCoreR.dll->ShouldMergeInproc
[i] [13008][Microsoft.Photos.exe] Start Address of Thread 7ffb68714070 in C:\Program Files\WindowsApps\Microsoft.VCLibs.140.00_14.0.30704.0_x64__8wekyb3d8bbwe\CONCRT140_APP.dll->Concurrency::set_task_execution_resources
[i] [13008][Microsoft.Photos.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [13008][Microsoft.Photos.exe] Start Address of Thread 7ffb72dc4fe0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleasePool
[i] [13008][Microsoft.Photos.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [13008][Microsoft.Photos.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [13008][Microsoft.Photos.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13008][Microsoft.Photos.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [13008][Microsoft.Photos.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12084][RuntimeBroker.exe] Start Address of Thread 7ff691526740 in C:\Windows\System32\RuntimeBroker.exe->UnknownFunction
[i] [12084][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18648][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\System32\svchost.exe->UnknownFunction
[i] [18648][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [18648][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [18648][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18648][svchost.exe] Start Address of Thread 7ffb52798de0 in c:\windows\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [18648][svchost.exe] Start Address of Thread 7ffb52798de0 in c:\windows\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [18648][svchost.exe] Start Address of Thread 7ffb52798de0 in c:\windows\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [18648][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18648][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18648][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18648][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18648][svchost.exe] Start Address of Thread 7ffb683b1760 in C:\WINDOWS\system32\SSDPAPI.dll->RegisterServiceEx
[i] [18648][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18648][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18648][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11372][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\System32\svchost.exe->UnknownFunction
[i] [11372][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [11372][svchost.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [11372][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11372][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22440][YourPhone.exe] Start Address of Thread 7ff612739000 in C:\Program Files\WindowsApps\Microsoft.YourPhone_1.21113.36.0_x64__8wekyb3d8bbwe\YourPhone.exe->UnknownFunction
[i] [22440][YourPhone.exe] Start Address of Thread 7ffb2e49c130 in C:\Program Files\WindowsApps\Microsoft.NET.Native.Runtime.2.2_2.2.28604.0_x64__8wekyb3d8bbwe\mrt100_app.dll->RhpSendCustomEventToDebugger
[i] [22440][YourPhone.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [22440][YourPhone.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [22440][YourPhone.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [22440][YourPhone.exe] Start Address of Thread 7ffb5f13f150 in C:\Windows\System32\MrmCoreR.dll->ShouldMergeInproc
[i] [22440][YourPhone.exe] Start Address of Thread 7ffb68714070 in C:\Program Files\WindowsApps\Microsoft.VCLibs.140.00_14.0.30704.0_x64__8wekyb3d8bbwe\CONCRT140_APP.dll->Concurrency::set_task_execution_resources
[i] [22440][YourPhone.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [22440][YourPhone.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [22440][YourPhone.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22440][YourPhone.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [22440][YourPhone.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [21888][RuntimeBroker.exe] Start Address of Thread 7ff691526740 in C:\Windows\System32\RuntimeBroker.exe->UnknownFunction
[i] [21888][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22436][pwahelper.exe] Start Address of Thread 7ff76a641f50 in C:\Program Files (x86)\Microsoft\Edge\Application\pwahelper.exe->Ordinal0
[i] [22436][pwahelper.exe] Start Address of Thread 7ffb2e9eee40 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\pwahelper.dll->edge_pwahelper::PwaHelperImpl::PinTileToStart
[i] [22436][pwahelper.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22436][pwahelper.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22024][msedge.exe] Start Address of Thread 7ff6b20a1690 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [22024][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][msedge.exe] Start Address of Thread 7ff6b2032d10 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [22024][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22024][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][msedge.exe] Start Address of Thread 7ffb02a277b0 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\oneauth.dll->MATSEndWamAction
[i] [22024][msedge.exe] Start Address of Thread 7ffb4a752270 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\oneds.dll->Microsoft::Applications::Events::EventProperty::EventProperty
[i] [22024][msedge.exe] Start Address of Thread 7ffb4a752270 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\oneds.dll->Microsoft::Applications::Events::EventProperty::EventProperty
[i] [22024][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22024][msedge.exe] Start Address of Thread 7ffb2e39bd50 in C:\Windows\System32\MsSpellCheckingFacility.dll->DllUnregisterServer
[i] [22024][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22024][msedge.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [22024][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22024][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3076][msedge.exe] Start Address of Thread 7ff6b20a1690 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [3076][msedge.exe] Start Address of Thread 7ff6b20ddba0 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [3076][msedge.exe] Start Address of Thread 7ff6b21fa780 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->IsSandboxedProcess
[i] [3076][msedge.exe] Start Address of Thread 7ff6b21fa780 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->IsSandboxedProcess
[i] [3076][msedge.exe] Start Address of Thread 7ff6b21fa780 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->IsSandboxedProcess
[i] [3076][msedge.exe] Start Address of Thread 7ff6b2037a30 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [3076][msedge.exe] Start Address of Thread 7ff6b2037a30 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [3076][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3076][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13708][msedge.exe] Start Address of Thread 7ff6b20a1690 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [13708][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13708][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13708][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13708][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13708][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13708][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13708][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13708][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13708][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13708][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13708][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13708][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13708][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13708][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13708][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [15152][msedge.exe] Start Address of Thread 7ff6b20a1690 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [15152][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15152][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15152][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15152][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [15152][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15152][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15152][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15152][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [15152][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15152][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [15152][msedge.exe] Start Address of Thread 7ffb6fbd1010 in C:\WINDOWS\system32\mswsock.dll->UnknownFunction
[i] [15152][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [21376][msedge.exe] Start Address of Thread 7ff6b20a1690 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [21376][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [21376][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [21376][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [21376][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [21376][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [21376][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [21376][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [21376][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18888][msedge.exe] Start Address of Thread 7ff6b20a1690 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [18888][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18888][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18888][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7608][msedge.exe] Start Address of Thread 7ff6b20a1690 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [7608][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [7608][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [7608][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [7608][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [7608][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [7608][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [7608][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18636][msedge.exe] Start Address of Thread 7ff6b20a1690 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [18636][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18636][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18636][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18636][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18636][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18636][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18636][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18636][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18636][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [19832][slack.exe] Start Address of Thread 7ff7e0f16540 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [19832][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [19832][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [19832][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [19832][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [19832][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [19832][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [19832][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [19832][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [16736][RtkUWP.exe] Start Address of Thread 7ff646f7269c in C:\Program Files\WindowsApps\RealtekSemiconductorCorp.RealtekAudioControl_1.1.137.0_x64__dt26b99r8h8gj\RtkUWP.exe->VSDesignerDllMain
[i] [16736][RtkUWP.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [16736][RtkUWP.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [16736][RtkUWP.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [16736][RtkUWP.exe] Start Address of Thread 7ffb5f13f150 in C:\Windows\System32\MrmCoreR.dll->ShouldMergeInproc
[i] [16736][RtkUWP.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16736][RtkUWP.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [16736][RtkUWP.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [16736][RtkUWP.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16736][RtkUWP.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16672][RuntimeBroker.exe] Start Address of Thread 7ff691526740 in C:\Windows\System32\RuntimeBroker.exe->UnknownFunction
[i] [16672][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18068][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\System32\svchost.exe->UnknownFunction
[i] [18068][svchost.exe] Start Address of Thread 7ffb52798de0 in c:\windows\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [18068][svchost.exe] Start Address of Thread 7ffb52798de0 in c:\windows\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [18068][svchost.exe] Start Address of Thread 7ffb52798de0 in c:\windows\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [18068][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2892][Teams.exe] Start Address of Thread 7ff699475a70 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [2892][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [2892][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [2892][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [2892][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2892][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [2892][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [2892][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [2892][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [2892][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [2892][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [2892][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [2892][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2892][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10836][HxD.exe] Start Address of Thread 9199c0 in C:\Program Files\HxD\HxD.exe->UnknownFunction
[i] [10836][HxD.exe] Start Address of Thread 40e8a0 in C:\Program Files\HxD\HxD.exe->UnknownFunction
[i] [10836][HxD.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12756][C:\Windows\System32\svchost.exe] not analysed 5
[i] [10448][SnippingTool.exe] Start Address of Thread 7ff6af2136d0 in C:\WINDOWS\system32\SnippingTool.exe->UnknownFunction
[i] [10448][SnippingTool.exe] Start Address of Thread 7ffb55de9ae0 in C:\WINDOWS\WinSxS\amd64_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.19041.1466_none_91a4907ccc87e3b8\gdiplus.dll->GdiplusStartup
[i] [10448][SnippingTool.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [10448][SnippingTool.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [10448][SnippingTool.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [10448][SnippingTool.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [10448][SnippingTool.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [10448][SnippingTool.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [10448][SnippingTool.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8212][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\System32\svchost.exe->UnknownFunction
[i] [8212][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8212][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8212][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8212][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17884][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\System32\svchost.exe->UnknownFunction
[i] [17884][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [17884][svchost.exe] Start Address of Thread 7ffb6ac91450 in c:\windows\system32\lmhsvc.dll->ServiceMain
[i] [17884][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16872][WUDFHost.exe] Start Address of Thread 7ff745b60d40 in C:\Windows\System32\WUDFHost.exe->UnknownFunction
[i] [16872][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16872][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16872][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16872][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16872][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18744][WUDFHost.exe] Start Address of Thread 7ff745b60d40 in C:\Windows\System32\WUDFHost.exe->UnknownFunction
[i] [18744][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18744][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18744][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18744][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18744][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18744][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13744][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [13744][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22124][slack.exe] Start Address of Thread 7ff7e0f16540 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [22124][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [22124][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [22124][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [22124][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [22124][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22124][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [22124][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [22124][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [22124][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [22124][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [22124][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [22124][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [22124][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22124][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [22124][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [20988][ShellExperienceHost.exe] Start Address of Thread 7ff6d6c9ec00 in C:\WINDOWS\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe->UnknownFunction
[i] [20988][ShellExperienceHost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [20988][ShellExperienceHost.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [20988][ShellExperienceHost.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [20988][ShellExperienceHost.exe] Start Address of Thread 7ffb5f13f150 in C:\Windows\System32\MrmCoreR.dll->ShouldMergeInproc
[i] [20988][ShellExperienceHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20988][ShellExperienceHost.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [20988][ShellExperienceHost.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [20988][ShellExperienceHost.exe] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [20988][ShellExperienceHost.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [20988][ShellExperienceHost.exe] Start Address of Thread 7ffb6957f500 in C:\Windows\System32\AudioSes.dll->DllGetActivationFactory
[i] [20988][ShellExperienceHost.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [20988][ShellExperienceHost.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [20988][ShellExperienceHost.exe] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [20988][ShellExperienceHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20988][ShellExperienceHost.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [20988][ShellExperienceHost.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [20988][ShellExperienceHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20988][ShellExperienceHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][SearchApp.exe] Start Address of Thread 7ff7f40f4980 in C:\WINDOWS\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe->UnknownFunction
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb5f13f150 in C:\Windows\System32\MrmCoreR.dll->ShouldMergeInproc
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb2579dd40 in C:\WINDOWS\SYSTEM32\edgehtml.dll->InitializeLocalHtmlEngine
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb2577e9b0 in C:\WINDOWS\SYSTEM32\edgehtml.dll->Ordinal128
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb2587b2b0 in C:\WINDOWS\SYSTEM32\edgehtml.dll->InitializeLocalHtmlEngine
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb2587b2b0 in C:\WINDOWS\SYSTEM32\edgehtml.dll->InitializeLocalHtmlEngine
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb2587b2b0 in C:\WINDOWS\SYSTEM32\edgehtml.dll->InitializeLocalHtmlEngine
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb2588bfb0 in C:\WINDOWS\SYSTEM32\edgehtml.dll->InitializeLocalHtmlEngine
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb706abeb0 in C:\WINDOWS\System32\CRYPT32.dll->CertFreeCTLContext
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb256190b0 in C:\WINDOWS\SYSTEM32\edgehtml.dll->Ordinal128
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb25576d40 in C:\WINDOWS\SYSTEM32\edgehtml.dll->Streams_CreateByteChunk
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22552][OneDrive.exe] Start Address of Thread 7ff6c7e81a30 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\OneDrive\OneDrive.exe->UnknownFunction
[i] [22552][OneDrive.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [22552][OneDrive.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [22552][OneDrive.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [22552][OneDrive.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [22552][OneDrive.exe] Start Address of Thread 7ffb326b58a0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\OneDrive\21.245.1128.0002\SyncEngine.DLL->CreateDirectoryListing
[i] [22552][OneDrive.exe] Start Address of Thread 7ffb326b58a0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\OneDrive\21.245.1128.0002\SyncEngine.DLL->CreateDirectoryListing
[i] [22552][OneDrive.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [22552][OneDrive.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [22552][OneDrive.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [22552][OneDrive.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [22552][OneDrive.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [22552][OneDrive.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [22552][OneDrive.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [22552][OneDrive.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22552][OneDrive.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22552][OneDrive.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [4636][RuntimeBroker.exe] Start Address of Thread 7ff691526740 in C:\Windows\System32\RuntimeBroker.exe->UnknownFunction
[i] [4636][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [21576][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [21576][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][chrome.exe] Start Address of Thread 7ff77414d070 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [21576][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [21576][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [21576][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [21576][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [21576][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][chrome.exe] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [21576][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [8520][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [8520][chrome.exe] Start Address of Thread 7ff7740bea70 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->Ordinal0
[i] [8520][chrome.exe] Start Address of Thread 7ff774159320 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [8520][chrome.exe] Start Address of Thread 7ff774159320 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [8520][chrome.exe] Start Address of Thread 7ff774159320 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [8520][chrome.exe] Start Address of Thread 7ff7740dbf10 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->Ordinal0
[i] [8520][chrome.exe] Start Address of Thread 7ff7740dbf10 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->Ordinal0
[i] [8520][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22584][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [22584][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22584][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22584][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22584][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22584][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22584][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22584][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22584][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22584][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22584][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22584][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22584][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22584][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22584][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1560][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [1560][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [1560][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [1560][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [1560][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1560][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [1560][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [1560][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [1560][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1560][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1560][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [1560][chrome.exe] Start Address of Thread 7ffb6fbd1010 in C:\WINDOWS\system32\mswsock.dll->UnknownFunction
[i] [1560][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [2544][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [2544][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [2544][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [2544][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [2544][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [2544][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [2544][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2544][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21968][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [21968][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21968][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21968][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21968][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21968][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [21968][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21968][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21968][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21968][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21968][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21968][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21968][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21968][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21968][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9688][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [9688][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [9688][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [9688][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [9688][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [9688][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9688][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [9688][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [9688][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [9688][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [9688][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [9688][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [9688][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [9688][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [9688][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10772][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [10772][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [10772][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [10772][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [10772][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [10772][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10772][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [10772][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [10772][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [10772][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [10772][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [10772][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [10772][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [10772][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [10772][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22004][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [22004][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22004][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22004][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22004][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22004][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22004][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22004][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22004][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22004][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22004][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22004][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22004][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22004][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22004][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7324][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [7324][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7324][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7324][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7324][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7324][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7324][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7324][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7324][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7324][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7324][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7324][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7324][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7324][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7324][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7324][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17868][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [17868][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [17868][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [17868][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [17868][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [17868][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [17868][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17868][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17868][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [17868][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22644][msedge.exe] Start Address of Thread 7ff6b20a1690 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [22644][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22644][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22644][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22644][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22644][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22644][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22644][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22644][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22644][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22644][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22644][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22644][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22644][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22644][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13916][msedge.exe] Start Address of Thread 7ff6b20a1690 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [13916][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13916][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13916][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13916][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13916][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13916][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13916][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13916][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13916][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13916][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13916][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13916][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13916][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13916][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13916][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6840][msedge.exe] Start Address of Thread 7ff6b20a1690 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [6840][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [6840][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [6840][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [6840][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [6840][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6840][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [6840][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [6840][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [6840][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [6840][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [6840][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [6840][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [6840][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [6840][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18164][msedge.exe] Start Address of Thread 7ff6b20a1690 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [18164][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18164][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18164][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18164][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18164][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18164][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18164][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18164][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18164][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18164][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18164][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18164][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18164][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18164][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2456][msedge.exe] Start Address of Thread 7ff6b20a1690 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [2456][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [2456][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [2456][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [2456][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [2456][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2456][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [2456][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [2456][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16200][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [16200][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16200][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16200][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16200][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16200][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16200][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16200][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16200][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16200][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16200][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16200][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16200][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16200][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16200][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20484][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [20484][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [20484][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [20484][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [20484][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [20484][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20484][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [20484][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [20484][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [20484][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [20484][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [20484][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [20484][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [20484][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [20484][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16100][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [16100][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16100][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16100][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16100][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16100][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16100][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16100][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16100][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16100][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16100][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16100][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16100][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16100][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16100][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16100][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7704][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [7704][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7704][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7704][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7704][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7704][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7704][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7704][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7704][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7704][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7704][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7704][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7704][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7704][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7704][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10636][notepad.exe] Start Address of Thread 7ff644675410 in C:\WINDOWS\system32\notepad.exe->UnknownFunction
[i] [10636][notepad.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23360][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [23360][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23360][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23360][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23360][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23360][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23360][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23360][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23360][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23360][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23360][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23360][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23360][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23360][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23360][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23360][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23360][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13688][ScriptedSandbox64.exe] Start Address of Thread 7ff613f3559c in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [13688][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e030 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [13688][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e2d0 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [13688][ScriptedSandbox64.exe] Start Address of Thread 7ff613f27a14 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [13688][ScriptedSandbox64.exe] Start Address of Thread 7ff613f27b78 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [13688][ScriptedSandbox64.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [13688][ScriptedSandbox64.exe] Start Address of Thread 7ffaffd3dae0 in C:\Windows\System32\mshtml.dll->DllGetClassObject
[i] [13688][ScriptedSandbox64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13688][ScriptedSandbox64.exe] Start Address of Thread 7ffaffd3dae0 in C:\Windows\System32\mshtml.dll->DllGetClassObject
[i] [13688][ScriptedSandbox64.exe] Start Address of Thread 7ffaffce3ab0 in C:\Windows\System32\mshtml.dll->InitializeLocalHtmlEngine
[i] [13688][ScriptedSandbox64.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [13688][ScriptedSandbox64.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [13688][ScriptedSandbox64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [19084][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [19084][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19084][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19084][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19084][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19084][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [19084][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19084][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19084][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19084][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19084][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19084][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19084][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19084][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19084][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [19348][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [19348][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19348][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19348][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19348][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19348][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [19348][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19348][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19348][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19348][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19348][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19348][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19348][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19348][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19348][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11376][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [11376][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11376][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11376][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11376][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11376][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11376][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11376][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11376][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11376][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11376][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11376][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11376][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11376][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11376][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23536][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [23536][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23536][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23536][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23536][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23536][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23536][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23536][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23536][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23536][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23536][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23536][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23536][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23536][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23536][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23536][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23536][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [16724][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16724][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5760][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [5760][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [5760][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [5760][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [5760][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [5760][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [5760][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5760][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [5760][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [5760][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [5760][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [5760][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [5760][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [5760][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [5760][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18104][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 207ace7fe96 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\ServiceHub\controller\Microsoft.ServiceHub.Controller.exe->UnknownFunction
[i] [18104][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb50d67c40 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->GC_Initialize
[i] [18104][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [18104][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18104][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18104][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb50bd9d10 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [18104][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb52a08e40 in C:\WINDOWS\SYSTEM32\rasman.dll->RasSignalMonitorThreadExit
[i] [18104][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18104][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb50d21ac0 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->GetMetaDataPublicInterfaceFromInternal
[i] [18104][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [21152][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [21152][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [21152][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17744][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [17744][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [17744][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [19200][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [19200][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [19200][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17804][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [17804][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [17804][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17804][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20516][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [20516][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [20516][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20516][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [21820][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [21820][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [21820][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14424][C:\Windows\System32\svchost.exe] not analysed 5
[i] [16264][SearchProtocolHost.exe] Start Address of Thread 7ff6f7c28220 in C:\WINDOWS\system32\SearchProtocolHost.exe->UnknownFunction
[i] [16264][SearchProtocolHost.exe] Start Address of Thread 7ff6f7c22890 in C:\WINDOWS\system32\SearchProtocolHost.exe->UnknownFunction
[i] [16264][SearchProtocolHost.exe] Start Address of Thread 7ff6f7c173b0 in C:\WINDOWS\system32\SearchProtocolHost.exe->UnknownFunction
[i] [16264][SearchProtocolHost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [16264][SearchProtocolHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16264][SearchProtocolHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16264][SearchProtocolHost.exe] Start Address of Thread 7ffb3c241c00 in C:\PROGRA~1\MICROS~1\Office16\MAPIPH.DLL->DllUnregisterServer
[i] [16264][SearchProtocolHost.exe] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [16264][SearchProtocolHost.exe] Start Address of Thread 7ffb473e3188 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal899
[i] [16264][SearchProtocolHost.exe] Start Address of Thread 7ffb356dd740 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso40uiwin32client.dll->Ordinal957
[i] [16264][SearchProtocolHost.exe] Start Address of Thread 7ffb356ede34 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso40uiwin32client.dll->Ordinal452
[i] [16264][SearchProtocolHost.exe] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [16264][SearchProtocolHost.exe] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [16264][SearchProtocolHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16264][SearchProtocolHost.exe] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [16264][SearchProtocolHost.exe] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [16264][SearchProtocolHost.exe] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [16264][SearchProtocolHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16936][C:\Windows\System32\svchost.exe] not analysed 5
[i] [22720][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 26e0daf0000 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\ServiceHub\Hosts\ServiceHub.Host.CLR.x64\ServiceHub.DataWarehouseHost.exe->UnknownFunction
[i] [22720][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50d67c40 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->GC_Initialize
[i] [22720][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [22720][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22720][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22720][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [22720][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bd9d10 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [22720][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22720][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22720][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22720][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22720][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22720][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22720][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22720][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22720][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb52a08e40 in C:\WINDOWS\SYSTEM32\rasman.dll->RasSignalMonitorThreadExit
[i] [22720][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [22720][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb55de9ae0 in C:\WINDOWS\WinSxS\amd64_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.19041.1466_none_91a4907ccc87e3b8\gdiplus.dll->GdiplusStartup
[i] [22720][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [22720][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [22720][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [22720][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [22720][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [22720][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [22720][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [22720][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [22720][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [22720][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [7448][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [7448][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [7448][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10336][StandardCollector.Service.exe] Start Address of Thread 7ff73ed11ef0 in C:\Program Files (x86)\Microsoft Visual Studio\Shared\Common\DiagnosticsHub.Collection.Service\StandardCollector.Service.exe->UnknownFunction
[i] [10336][StandardCollector.Service.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [10336][StandardCollector.Service.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [10336][StandardCollector.Service.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10336][StandardCollector.Service.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10336][StandardCollector.Service.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10336][StandardCollector.Service.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10336][StandardCollector.Service.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10336][StandardCollector.Service.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10336][StandardCollector.Service.exe] Start Address of Thread 7ffb35297b30 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Team Tools\DiagnosticsHub\Collector\DiagnosticsHub.StandardCollector.Runtime.dll->UnknownFunction
[i] [10336][StandardCollector.Service.exe] Start Address of Thread 7ffb35297b30 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Team Tools\DiagnosticsHub\Collector\DiagnosticsHub.StandardCollector.Runtime.dll->UnknownFunction
[i] [10336][StandardCollector.Service.exe] Start Address of Thread 7ffb35297b30 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Team Tools\DiagnosticsHub\Collector\DiagnosticsHub.StandardCollector.Runtime.dll->UnknownFunction
[i] [10336][StandardCollector.Service.exe] Start Address of Thread 7ffb72dc4fe0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleasePool
[i] [10336][StandardCollector.Service.exe] Start Address of Thread 7ffb72dc4fe0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleasePool
[i] [10336][StandardCollector.Service.exe] Start Address of Thread 7ffb72dc4fe0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleasePool
[i] [10336][StandardCollector.Service.exe] Start Address of Thread 7ffb35297b30 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Team Tools\DiagnosticsHub\Collector\DiagnosticsHub.StandardCollector.Runtime.dll->UnknownFunction
[i] [10336][StandardCollector.Service.exe] Start Address of Thread 7ffb35297b30 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Team Tools\DiagnosticsHub\Collector\DiagnosticsHub.StandardCollector.Runtime.dll->UnknownFunction
[i] [10336][StandardCollector.Service.exe] Start Address of Thread 7ffb72dc4fe0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleasePool
[i] [10336][StandardCollector.Service.exe] Start Address of Thread 7ffb35297b30 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Team Tools\DiagnosticsHub\Collector\DiagnosticsHub.StandardCollector.Runtime.dll->UnknownFunction
[i] [10336][StandardCollector.Service.exe] Start Address of Thread 7ffb35297b30 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Team Tools\DiagnosticsHub\Collector\DiagnosticsHub.StandardCollector.Runtime.dll->UnknownFunction
[i] [10336][StandardCollector.Service.exe] Start Address of Thread 7ffb72dc4fe0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleasePool
[i] [10336][StandardCollector.Service.exe] Start Address of Thread 7ffb35297b30 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Team Tools\DiagnosticsHub\Collector\DiagnosticsHub.StandardCollector.Runtime.dll->UnknownFunction
[i] [10336][StandardCollector.Service.exe] Start Address of Thread 7ffb72dc4fe0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleasePool
[i] [10336][StandardCollector.Service.exe] Start Address of Thread 7ffb72dc4fe0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleasePool
[i] [14456][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [14456][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [14456][conhost.exe] Start Address of Thread 7ff62eef4a90 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [14456][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14456][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1512][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [1512][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [1512][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8176][msvsmon.exe] Start Address of Thread 7ff7a49a4818 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\Remote Debugger\x64\msvsmon.exe->OnAbnormalAbort
[i] [8176][msvsmon.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8176][msvsmon.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8176][msvsmon.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8176][msvsmon.exe] Start Address of Thread 7ff7a4991eb8 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\Remote Debugger\x64\msvsmon.exe->OnAbnormalAbort
[i] [8176][msvsmon.exe] Start Address of Thread 7ffb1b5ff1a0 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\Remote Debugger\x64\vsdebugeng.dll->ProcDkmWorkListSetDescription
[i] [8176][msvsmon.exe] Start Address of Thread 7ffb1b5e27cc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\Remote Debugger\x64\vsdebugeng.dll->DkmDllSetRootProcessId
[i] [8176][msvsmon.exe] Start Address of Thread 7ffb1b568e0c in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\Remote Debugger\x64\vsdebugeng.dll->ProcDkmGetExtendedPart
[i] [8176][msvsmon.exe] Start Address of Thread 7ffb272596e8 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\Remote Debugger\x64\vsdebugeng.impl.dll->ReleaseForeground
[i] [8176][msvsmon.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [8176][msvsmon.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8176][msvsmon.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8176][msvsmon.exe] Start Address of Thread 7ffb50d67c40 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->GC_Initialize
[i] [8176][msvsmon.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [14808][MEMGUARD.exe] Start Address of Thread 7ff734f41023 in C:\Data\NCC\!Code\Slop\MEMGUARD\x64\Debug\MEMGUARD.exe->ILT+30(mainCRTStartup)
[i] [14808][MEMGUARD.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14808][MEMGUARD.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14808][MEMGUARD.exe] Start Address of Thread 2210ff00000 in UnknownModule->UnknownFunction
[i] [14808][MEMGUARD.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16476][SearchFilterHost.exe] Start Address of Thread 7ff6e55a82f0 in C:\WINDOWS\system32\SearchFilterHost.exe->UnknownFunction
[i] [16476][SearchFilterHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16476][SearchFilterHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16476][SearchFilterHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16476][SearchFilterHost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [16476][SearchFilterHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16476][SearchFilterHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20880][msvsmon.exe] Start Address of Thread 7ff7a49a4818 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\Remote Debugger\x64\msvsmon.exe->OnAbnormalAbort
[i] [20880][msvsmon.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20880][msvsmon.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20880][msvsmon.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20880][msvsmon.exe] Start Address of Thread 7ff7a4991eb8 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\Remote Debugger\x64\msvsmon.exe->OnAbnormalAbort
[i] [20880][msvsmon.exe] Start Address of Thread 7ffb1b5ff1a0 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\Remote Debugger\x64\vsdebugeng.dll->ProcDkmWorkListSetDescription
[i] [20880][msvsmon.exe] Start Address of Thread 7ffb1b5e27cc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\Remote Debugger\x64\vsdebugeng.dll->DkmDllSetRootProcessId
[i] [20880][msvsmon.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20880][msvsmon.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20880][msvsmon.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [20880][msvsmon.exe] Start Address of Thread 7ffb1b568e0c in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\Remote Debugger\x64\vsdebugeng.dll->ProcDkmGetExtendedPart
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f3559c in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e030 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e2d0 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f27a14 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f27b78 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ffaffd3dae0 in C:\Windows\System32\mshtml.dll->DllGetClassObject
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ffaffd3dae0 in C:\Windows\System32\mshtml.dll->DllGetClassObject
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ffaffce3ab0 in C:\Windows\System32\mshtml.dll->InitializeLocalHtmlEngine
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ffaffd3dae0 in C:\Windows\System32\mshtml.dll->DllGetClassObject
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [14152][AUDIODG.EXE] Start Address of Thread 7ff6ed58cc30 in C:\WINDOWS\system32\AUDIODG.EXE->UnknownFunction
[i] [14152][AUDIODG.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14152][AUDIODG.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14152][AUDIODG.EXE] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [14152][AUDIODG.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14152][AUDIODG.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14152][AUDIODG.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14152][AUDIODG.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17972][d-thread-start.exe] Start Address of Thread 7ff62eb11b54 in C:\Data\NCC\!Code\Git.Public\DetectWindowsCopyOnWriteForAPI\d-cow\x64\Release\d-thread-start.exe->wmainCRTStartup
[i] [17972][d-thread-start.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17972][d-thread-start.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17972][d-thread-start.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] Total of 343 processes - didn't open 18 - total of 2769 threads - 0 start in unknown modules
```

