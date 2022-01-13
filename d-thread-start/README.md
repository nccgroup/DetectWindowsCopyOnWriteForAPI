Thread Starting Function Enumerator for Windows
======================
Enumerates the address and which module the starting address of each thread points to. This will help detect when threat actors allocate memory for their payload and use that address as the start address to `CreateThread` or `CreateRemoteThread` etc. 

Example of it finding the result of CreateRemoteThread from memory:
```
[i] [22516][9764][MEMGUARD.exe] Start Address of Thread 7ff734f41023 in C:\Data\NCC\!Code\Slop\MEMGUARD\x64\Debug\MEMGUARD.exe->ILT+30(mainCRTStartup)
[i] [22516][18584][MEMGUARD.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22516][4240][MEMGUARD.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22516][9668][MEMGUARD.exe] Start Address of Thread 1e8c7330000 in UnknownModule->UnknownFunction    <---- result of CreateRemoteThread
[i] [22516][7772][MEMGUARD.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
...

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
[i] [1084][1100][lsass.exe] Start Address of Thread 7ff6a47020d0 in C:\WINDOWS\system32\lsass.exe->LsaImpersonateKsecCaller
[i] [1084][1112][lsass.exe] Start Address of Thread 7ffb700e0cf0 in C:\WINDOWS\system32\lsasrv.dll->LsaIFree_LSAPR_TRANSLATED_NAMES
[i] [1084][1116][lsass.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1084][1124][lsass.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [1084][1148][lsass.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1084][7512][lsass.exe] Start Address of Thread 7ffb705250d0 in C:\WINDOWS\System32\ucrtbase.dll->o__beginthread
[i] [1084][10484][lsass.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1084][17896][lsass.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1084][22980][lsass.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1084][11312][lsass.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1084][16740][lsass.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][1204][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [1200][1476][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][1848][svchost.exe] Start Address of Thread 7ffb6afa8ac0 in c:\windows\system32\DAB.dll->DabInitialize
[i] [1200][680][svchost.exe] Start Address of Thread 7ffb6dcdefd0 in C:\WINDOWS\SYSTEM32\psmserviceexthost.dll->PsmCrmSessionUserNotification
[i] [1200][8828][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][11124][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][14536][svchost.exe] Start Address of Thread 7ffb41861c90 in C:\WINDOWS\SYSTEM32\msiltcfg.dll->RestartMsi
[i] [1200][18664][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][7732][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][4344][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][18448][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][1980][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][15800][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][14528][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][23136][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][11784][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][21296][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][23304][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][17568][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [1200][19032][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][3088][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][9072][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][11536][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1200][19444][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1228][1232][fontdrvhost.exe] Start Address of Thread 7ff78e3326a0 in C:\WINDOWS\system32\fontdrvhost.exe->UnknownFunction
[i] [1228][1244][fontdrvhost.exe] Start Address of Thread 7ff78e32de80 in C:\WINDOWS\system32\fontdrvhost.exe->UnknownFunction
[i] [1228][1248][fontdrvhost.exe] Start Address of Thread 7ff78e32de80 in C:\WINDOWS\system32\fontdrvhost.exe->UnknownFunction
[i] [1228][1252][fontdrvhost.exe] Start Address of Thread 7ff78e32de80 in C:\WINDOWS\system32\fontdrvhost.exe->UnknownFunction
[i] [1228][1256][fontdrvhost.exe] Start Address of Thread 7ff78e32de80 in C:\WINDOWS\system32\fontdrvhost.exe->UnknownFunction
[i] [1228][17788][fontdrvhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1308][1312][WUDFHost.exe] Start Address of Thread 7ff745b60d40 in C:\Windows\System32\WUDFHost.exe->UnknownFunction
[i] [1308][1692][WUDFHost.exe] Start Address of Thread 7ffb6d6bb6e0 in c:\windows\system32\drivers\umdf\surfacepenpairing.dll->UnknownFunction
[i] [1308][4652][WUDFHost.exe] Start Address of Thread 7ffb5fa90100 in c:\windows\system32\drivers\umdf\sensorshid.dll->UnknownFunction
[i] [1308][11580][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1308][19888][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1308][9400][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1308][9564][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1308][13324][WUDFHost.exe] Start Address of Thread 7ffb28efaae0 in c:\windows\system32\drivers\umdf\surfacedockfwupdate.dll->UnknownFunction
[i] [1308][14140][WUDFHost.exe] Start Address of Thread 7ffb28f03210 in c:\windows\system32\drivers\umdf\surfacedockfwupdate.dll->UnknownFunction
[i] [1308][2556][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1316][1320][winlogon.exe] Start Address of Thread 7ff71b898e60 in C:\WINDOWS\system32\winlogon.exe->UnknownFunction
[i] [1316][1636][winlogon.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1316][1060][winlogon.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1316][17360][winlogon.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1316][15484][winlogon.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1316][15976][winlogon.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1388][1392][fontdrvhost.exe] Start Address of Thread 7ff78e3326a0 in C:\WINDOWS\system32\fontdrvhost.exe->UnknownFunction
[i] [1388][1400][fontdrvhost.exe] Start Address of Thread 7ff78e32de80 in C:\WINDOWS\system32\fontdrvhost.exe->UnknownFunction
[i] [1388][1404][fontdrvhost.exe] Start Address of Thread 7ff78e32de80 in C:\WINDOWS\system32\fontdrvhost.exe->UnknownFunction
[i] [1388][1408][fontdrvhost.exe] Start Address of Thread 7ff78e32de80 in C:\WINDOWS\system32\fontdrvhost.exe->UnknownFunction
[i] [1388][1412][fontdrvhost.exe] Start Address of Thread 7ff78e32de80 in C:\WINDOWS\system32\fontdrvhost.exe->UnknownFunction
[i] [1388][22764][fontdrvhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1448][1452][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [1448][1520][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [1448][1528][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1448][13060][svchost.exe] Start Address of Thread 7ffb41861c90 in C:\WINDOWS\SYSTEM32\msiltcfg.dll->RestartMsi
[i] [1448][18656][svchost.exe] Start Address of Thread 7ffb6e026570 in c:\windows\system32\rpcss.dll->UnknownFunction
[i] [1448][20680][svchost.exe] Start Address of Thread 7ffb6e026570 in c:\windows\system32\rpcss.dll->UnknownFunction
[i] [1448][21264][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1448][21788][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1448][21072][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1448][11800][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1448][15880][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1448][18020][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1448][22692][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1448][22632][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1448][22600][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1448][3932][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1448][2704][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1448][19244][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1448][18148][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1484][1488][WUDFHost.exe] Start Address of Thread 7ff745b60d40 in C:\Windows\System32\WUDFHost.exe->UnknownFunction
[i] [1484][1496][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1484][1500][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1484][1504][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1484][1508][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1484][1592][WUDFHost.exe] Start Address of Thread 7ffb6df4f630 in c:\windows\system32\drivers\umdf\esif_umdf2.dll->UnknownFunction
[i] [1484][1612][WUDFHost.exe] Start Address of Thread 7ffb6def1aa0 in c:\windows\system32\drivers\umdf\esif_umdf2.dll->UnknownFunction
[i] [1484][1620][WUDFHost.exe] Start Address of Thread 7ffb6def1aa0 in c:\windows\system32\drivers\umdf\esif_umdf2.dll->UnknownFunction
[i] [1484][1772][WUDFHost.exe] Start Address of Thread 7ffb6c6a7a30 in C:\WINDOWS\system32\Intel\DPTF\dptf.dll->EsifServices::sendCommand
[i] [1484][1780][WUDFHost.exe] Start Address of Thread 7ffb6df4f630 in c:\windows\system32\drivers\umdf\esif_umdf2.dll->UnknownFunction
[i] [1484][16604][WUDFHost.exe] Start Address of Thread 7ffb6c6a7a30 in C:\WINDOWS\system32\Intel\DPTF\dptf.dll->EsifServices::sendCommand
[i] [1484][22328][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1544][1548][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [1544][1580][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1544][1556][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1544][8832][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1544][18872][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1544][13528][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [1544][22400][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1544][1852][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1544][20836][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1664][1668][dwm.exe] Start Address of Thread 7ff6908e3160 in C:\WINDOWS\system32\dwm.exe->UnknownFunction
[i] [1664][4368][dwm.exe] Start Address of Thread 7ffb6d5cbb60 in C:\WINDOWS\SYSTEM32\dwmredir.dll->DwmRedirectionManagerInitialize
[i] [1664][4416][dwm.exe] Start Address of Thread 7ffb6c99f410 in C:\WINDOWS\system32\dwmcore.dll->MilTransport_Release
[i] [1664][4440][dwm.exe] Start Address of Thread 7ffb6ca48db0 in C:\WINDOWS\system32\dwmcore.dll->MilTransport_AddRef
[i] [1664][4444][dwm.exe] Start Address of Thread 7ffb6ca48d70 in C:\WINDOWS\system32\dwmcore.dll->MilCompositionEngine_Initialize
[i] [1664][4448][dwm.exe] Start Address of Thread 7ffb6ca48d00 in C:\WINDOWS\system32\dwmcore.dll->MilCompositionEngine_Initialize
[i] [1664][4464][dwm.exe] Start Address of Thread 7ffb6ca48b50 in C:\WINDOWS\system32\dwmcore.dll->MilCompositionEngine_Initialize
[i] [1664][4468][dwm.exe] Start Address of Thread 7ffb6d50b2c0 in C:\WINDOWS\SYSTEM32\udwm.dll->UnknownFunction
[i] [1664][4472][dwm.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1664][4504][dwm.exe] Start Address of Thread 7ffb6038f930 in C:\Windows\System32\Windows.Gaming.Input.dll->DllGetClassObject
[i] [1664][4532][dwm.exe] Start Address of Thread 7ffb60818860 in C:\WINDOWS\SYSTEM32\ism.dll->CreateSystemInputHost
[i] [1664][4624][dwm.exe] Start Address of Thread 7ffb5f765e90 in C:\Windows\System32\DispBroker.dll->DispBrokerTraceLogCallback
[i] [1664][4940][dwm.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1664][17596][dwm.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1708][1712][WUDFHost.exe] Start Address of Thread 7ff745b60d40 in C:\Windows\System32\WUDFHost.exe->UnknownFunction
[i] [1708][1724][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1708][1728][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1708][1748][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1708][1752][WUDFHost.exe] Start Address of Thread 7ffb6c909414 in c:\windows\system32\drivers\umdf\sarproxy.dll->UnknownFunction
[i] [1708][1756][WUDFHost.exe] Start Address of Thread 7ffb6c90c190 in c:\windows\system32\drivers\umdf\sarproxy.dll->UnknownFunction
[i] [1708][1760][WUDFHost.exe] Start Address of Thread 7ffb6c906a34 in c:\windows\system32\drivers\umdf\sarproxy.dll->UnknownFunction
[i] [1708][1764][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1708][7208][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1708][22068][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1808][1812][WUDFHost.exe] Start Address of Thread 7ff745b60d40 in C:\Windows\System32\WUDFHost.exe->UnknownFunction
[i] [1808][1824][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1808][1828][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1808][1832][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1808][1836][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1808][1884][WUDFHost.exe] Start Address of Thread 7ffb6af50de0 in c:\windows\system32\drivers\umdf\iddcx.dll->UnknownFunction
[i] [1808][22016][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1956][1960][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [1956][2156][svchost.exe] Start Address of Thread 7ffb6a910d40 in c:\windows\system32\termsrv.dll->SvchostPushServiceGlobals
[i] [1956][2392][svchost.exe] Start Address of Thread 7ffb6a95df70 in c:\windows\system32\termsrv.dll->SvchostPushServiceGlobals
[i] [1956][2416][svchost.exe] Start Address of Thread 7ffb6a945610 in c:\windows\system32\termsrv.dll->SvchostPushServiceGlobals
[i] [1956][2552][svchost.exe] Start Address of Thread 7ffb6933a7a0 in C:\WINDOWS\system32\rdpcorets.dll->DllGetClassObject
[i] [1956][3032][svchost.exe] Start Address of Thread 7ffb69224030 in C:\WINDOWS\system32\RDPBASE.dll->CRdpFIPSEncryption_CreateInstance
[i] [1956][3056][svchost.exe] Start Address of Thread 7ffb69224030 in C:\WINDOWS\system32\RDPBASE.dll->CRdpFIPSEncryption_CreateInstance
[i] [1956][2176][svchost.exe] Start Address of Thread 7ffb69224030 in C:\WINDOWS\system32\RDPBASE.dll->CRdpFIPSEncryption_CreateInstance
[i] [1956][2076][svchost.exe] Start Address of Thread 7ffb69224030 in C:\WINDOWS\system32\RDPBASE.dll->CRdpFIPSEncryption_CreateInstance
[i] [1956][2576][svchost.exe] Start Address of Thread 7ffb69224030 in C:\WINDOWS\system32\RDPBASE.dll->CRdpFIPSEncryption_CreateInstance
[i] [1956][2728][svchost.exe] Start Address of Thread 7ffb69224030 in C:\WINDOWS\system32\RDPBASE.dll->CRdpFIPSEncryption_CreateInstance
[i] [1956][2952][svchost.exe] Start Address of Thread 7ffb69224030 in C:\WINDOWS\system32\RDPBASE.dll->CRdpFIPSEncryption_CreateInstance
[i] [1956][3084][svchost.exe] Start Address of Thread 7ffb69224030 in C:\WINDOWS\system32\RDPBASE.dll->CRdpFIPSEncryption_CreateInstance
[i] [1956][3112][svchost.exe] Start Address of Thread 7ffb69224030 in C:\WINDOWS\system32\RDPBASE.dll->CRdpFIPSEncryption_CreateInstance
[i] [1956][3132][svchost.exe] Start Address of Thread 7ffb69224030 in C:\WINDOWS\system32\RDPBASE.dll->CRdpFIPSEncryption_CreateInstance
[i] [1956][12772][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1956][18416][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [1956][11912][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1956][9912][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1956][21564][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1956][20740][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1984][1988][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [1984][2224][svchost.exe] Start Address of Thread 7ffb6a5a53d0 in c:\windows\system32\wevtsvc.dll->ServiceMain
[i] [1984][2908][svchost.exe] Start Address of Thread 7ffb6a5aae10 in c:\windows\system32\wevtsvc.dll->ServiceMain
[i] [1984][2920][svchost.exe] Start Address of Thread 7ffb6a5aae10 in c:\windows\system32\wevtsvc.dll->ServiceMain
[i] [1984][2932][svchost.exe] Start Address of Thread 7ffb6a5aae10 in c:\windows\system32\wevtsvc.dll->ServiceMain
[i] [1984][10784][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1984][6700][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1984][14596][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1984][3904][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1992][1996][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [1992][2260][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1992][3872][svchost.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [1992][13120][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2004][2008][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2004][20892][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1784][1540][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [1784][18208][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1784][6824][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1784][10292][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1784][19672][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1784][5544][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1788][2052][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [1788][2328][svchost.exe] Start Address of Thread 7ffb6a3b2510 in c:\windows\system32\btagservice.dll->ServiceMain
[i] [1788][23172][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2056][2060][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2056][2228][svchost.exe] Start Address of Thread 7ffb6a4ef3a0 in c:\windows\system32\bthavctpsvc.dll->DllGetClassObject
[i] [2056][5304][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2056][19232][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2084][2088][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2084][2188][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [2084][2380][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2084][2384][svchost.exe] Start Address of Thread 7ffb6a05d310 in C:\WINDOWS\SYSTEM32\Microsoft.Bluetooth.Service.dll->UnknownFunction
[i] [2084][2616][svchost.exe] Start Address of Thread 7ffb6a065330 in C:\WINDOWS\SYSTEM32\Microsoft.Bluetooth.Service.dll->UnknownFunction
[i] [2084][2924][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2084][3048][svchost.exe] Start Address of Thread 7ffb6a4a7880 in c:\windows\system32\bthserv.dll->ServiceMain
[i] [2084][23152][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2084][8712][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2084][16396][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [2092][2096][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2092][1696][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2092][3708][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2092][18864][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2192][2196][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2192][5576][svchost.exe] Start Address of Thread 7ffb56959d00 in C:\WINDOWS\system32\WlanRadioManager.dll->DllGetClassObject
[i] [2192][5584][svchost.exe] Start Address of Thread 7ffb6c88eac0 in C:\Windows\System32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [2192][5528][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2192][18052][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2252][2256][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2252][2772][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2252][3432][svchost.exe] Start Address of Thread 7ffb66891890 in C:\WINDOWS\SYSTEM32\cmintegrator.dll->UnknownFunction
[i] [2252][3436][svchost.exe] Start Address of Thread 7ffb69b82020 in c:\windows\system32\wcmsvc.dll->CdeGetProfileList
[i] [2252][5580][svchost.exe] Start Address of Thread 7ffb6c88eac0 in C:\Windows\System32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [2252][5592][svchost.exe] Start Address of Thread 7ffb6c8ca130 in C:\Windows\System32\wlanapi.dll->WlanVerifyProfileIpConfiguration
[i] [2252][9144][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2252][15124][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2252][1640][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2252][19164][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2252][22156][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2252][18488][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2264][2268][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2264][2400][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [2264][2524][svchost.exe] Start Address of Thread 7ffb6970d6c0 in C:\WINDOWS\system32\dhcpcore6.dll->Dhcpv6Main
[i] [2264][12472][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2264][15204][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2264][15420][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2264][8368][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2264][2220][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2264][15972][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2516][2520][IntelCpHDCPSvc.exe] Start Address of Thread 7ff6cf73ec10 in C:\WINDOWS\System32\DriverStore\FileRepository\64kb8682.inf_amd64_170ccd25b9699b84\IntelCpHDCPSvc.exe->UnknownFunction
[i] [2516][2656][IntelCpHDCPSvc.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [2516][2736][IntelCpHDCPSvc.exe] Start Address of Thread 7ff6cf726f80 in C:\WINDOWS\System32\DriverStore\FileRepository\64kb8682.inf_amd64_170ccd25b9699b84\IntelCpHDCPSvc.exe->UnknownFunction
[i] [2516][19416][IntelCpHDCPSvc.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][2532][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2528][2788][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][2792][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][2796][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][2800][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][2852][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][2856][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][2860][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][2868][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][2872][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][2876][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][3036][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][3040][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][3044][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][3060][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][5212][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][5220][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][18320][svchost.exe] Start Address of Thread 7ffb5f3068e0 in C:\WINDOWS\SYSTEM32\SensorsNativeApi.V2.dll->SensorGetFifoMaxSizeV2
[i] [2528][5480][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][14352][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][9276][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][16868][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][12984][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][4548][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2528][2988][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2632][2636][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2632][2748][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [2632][2808][svchost.exe] Start Address of Thread 7ffb68681b80 in c:\windows\system32\hidserv.dll->ServiceMain
[i] [2632][2880][svchost.exe] Start Address of Thread 7ffb686822c0 in c:\windows\system32\hidserv.dll->ServiceMain
[i] [2632][3012][svchost.exe] Start Address of Thread 7ffb68682600 in c:\windows\system32\hidserv.dll->ServiceMain
[i] [2632][10340][svchost.exe] Start Address of Thread 7ffb68682600 in c:\windows\system32\hidserv.dll->ServiceMain
[i] [2632][16720][svchost.exe] Start Address of Thread 7ffb68682600 in c:\windows\system32\hidserv.dll->ServiceMain
[i] [2632][2776][svchost.exe] Start Address of Thread 7ffb68682600 in c:\windows\system32\hidserv.dll->ServiceMain
[i] [2632][20712][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2664][2668][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2664][2992][svchost.exe] Start Address of Thread 7ffb6847ff50 in c:\windows\system32\nlasvc.dll->UnknownFunction
[i] [2664][3572][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [2664][4996][svchost.exe] Start Address of Thread 7ffb683b1760 in C:\WINDOWS\System32\ssdpapi.dll->RegisterServiceEx
[i] [2664][15684][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2664][16800][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2672][2676][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2672][4976][svchost.exe] Start Address of Thread 7ffb684ffef0 in c:\windows\system32\umrdp.dll->SvchostPushServiceGlobals
[i] [2672][14028][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2832][2836][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2832][2132][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [2832][2888][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2832][3080][svchost.exe] Start Address of Thread 7ffb67ad0870 in C:\WINDOWS\system32\taskcomp.dll->IsRegistering
[i] [2832][6060][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2832][9100][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2832][7864][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2832][14224][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2832][6456][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2968][2972][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2968][3140][svchost.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [2968][9428][svchost.exe] Start Address of Thread 7ffb677f6680 in c:\windows\system32\tabsvc.dll->UnknownFunction
[i] [2968][7336][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3068][2068][IntelCpHeciSvc.exe] Start Address of Thread 7ff7445c83b0 in C:\WINDOWS\System32\DriverStore\FileRepository\64kb8682.inf_amd64_170ccd25b9699b84\IntelCpHeciSvc.exe->UnknownFunction
[i] [3068][2884][IntelCpHeciSvc.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [3068][3136][IntelCpHeciSvc.exe] Start Address of Thread 7ff7445b7dd0 in C:\WINDOWS\System32\DriverStore\FileRepository\64kb8682.inf_amd64_170ccd25b9699b84\IntelCpHeciSvc.exe->UnknownFunction
[i] [3068][18724][IntelCpHeciSvc.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2996][2936][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2996][11404][svchost.exe] Start Address of Thread 7ffb5387d020 in C:\WINDOWS\system32\dafBth.dll->DllCanUnloadNow
[i] [2996][11408][svchost.exe] Start Address of Thread 7ffb5387d020 in C:\WINDOWS\system32\dafBth.dll->DllCanUnloadNow
[i] [2996][12488][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2996][22668][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3168][3172][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3168][3588][svchost.exe] Start Address of Thread 7ffb669dc220 in c:\windows\system32\netprofmsvc.dll->ServiceMain
[i] [3168][3592][svchost.exe] Start Address of Thread 7ffb669db2d0 in c:\windows\system32\netprofmsvc.dll->ServiceMain
[i] [3168][3596][svchost.exe] Start Address of Thread 7ffb669d5380 in c:\windows\system32\netprofmsvc.dll->UnknownFunction
[i] [3168][5572][svchost.exe] Start Address of Thread 7ffb6c88eac0 in C:\WINDOWS\system32\WlanApi.dll->WlanQueryVirtualInterfaceType
[i] [3168][2116][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3168][22252][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3168][10684][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [3168][1444][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3168][20912][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3168][17584][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3168][6696][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3204][3208][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3204][3328][svchost.exe] Start Address of Thread 7ffb669736f0 in c:\windows\system32\certprop.dll->UnknownFunction
[i] [3204][9044][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3204][9048][svchost.exe] Start Address of Thread 7ffb669736f0 in c:\windows\system32\certprop.dll->UnknownFunction
[i] [3204][22736][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3228][3232][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3228][7836][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3228][16616][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3288][3292][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3288][7616][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3288][21904][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3344][3348][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3344][3476][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [3344][4300][svchost.exe] Start Address of Thread 7ffb6f179160 in c:\windows\system32\AUTHZ.dll->AuthzInitializeResourceManagerEx
[i] [3344][4308][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3344][5396][svchost.exe] Start Address of Thread 7ffb56f92e40 in C:\WINDOWS\system32\wbem\ncprov.dll->UnknownFunction
[i] [3344][5400][svchost.exe] Start Address of Thread 7ffb60c43ca0 in C:\WINDOWS\SYSTEM32\NCObjAPI.DLL->WmiAddObjectProp
[i] [3344][5404][svchost.exe] Start Address of Thread 7ffb60c43ca0 in C:\WINDOWS\SYSTEM32\NCObjAPI.DLL->WmiAddObjectProp
[i] [3344][16176][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3344][16676][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3344][19580][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3344][22680][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3344][5896][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3344][14400][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [3344][15776][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3360][3364][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3360][2916][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3360][9980][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3360][9920][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3360][20796][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3360][21300][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [3360][13128][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3360][15536][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3360][2036][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3404][3408][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3404][3556][svchost.exe] Start Address of Thread 7ffb666311f0 in c:\windows\system32\dnsrslvr.dll->ServiceMain
[i] [3404][3644][svchost.exe] Start Address of Thread 7ffb66633530 in c:\windows\system32\dnsrslvr.dll->ServiceMain
[i] [3404][3648][svchost.exe] Start Address of Thread 7ffb666333a0 in c:\windows\system32\dnsrslvr.dll->ServiceMain
[i] [3404][3660][svchost.exe] Start Address of Thread 7ffb66633e40 in c:\windows\system32\dnsrslvr.dll->ServiceMain
[i] [3404][17740][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3404][8952][svchost.exe] Start Address of Thread 7ffb6662eec0 in c:\windows\system32\dnsrslvr.dll->Reg_DoRegisterAdapter
[i] [3404][13124][svchost.exe] Start Address of Thread 7ffb6662e010 in c:\windows\system32\dnsrslvr.dll->Reg_DoRegisterAdapter
[i] [3404][23244][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3404][4876][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3404][19308][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3404][6424][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3404][18512][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3404][19440][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3412][3416][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3412][3516][svchost.exe] Start Address of Thread 7ffb666b5350 in c:\windows\system32\wkssvc.dll->SvchostPushServiceGlobals
[i] [3412][3624][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3412][4360][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3412][12420][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3628][3632][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3628][3756][svchost.exe] Start Address of Thread 7ffb62eb4d00 in c:\windows\system32\sessenv.dll->UnknownFunction
[i] [3628][3760][svchost.exe] Start Address of Thread 7ffb62ebace0 in c:\windows\system32\sessenv.dll->ServiceMain
[i] [3628][3768][svchost.exe] Start Address of Thread 7ffb62d37d40 in C:\WINDOWS\System32\RdvVmTransport.dll->RdvTransport_TerminateInstance
[i] [3628][3772][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3628][3868][svchost.exe] Start Address of Thread 7ffb62eba7a0 in c:\windows\system32\sessenv.dll->ServiceMain
[i] [3628][22040][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3636][3640][spaceman.exe] Start Address of Thread 7ff6b5a9d950 in C:\WINDOWS\system32\spaceman.exe->UnknownFunction
[i] [3636][7900][spaceman.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3636][5424][spaceman.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3680][3684][vmms.exe] Start Address of Thread 7ff6db030010 in C:\WINDOWS\system32\vmms.exe->UnknownFunction
[i] [3680][4040][vmms.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [3680][4984][vmms.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [3680][4680][vmms.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [3680][4672][vmms.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [3680][4696][vmms.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3680][3700][vmms.exe] Start Address of Thread 7ffb69224030 in C:\WINDOWS\system32\RDPBASE.dll->CRdpFIPSEncryption_CreateInstance
[i] [3680][3704][vmms.exe] Start Address of Thread 7ffb69224030 in C:\WINDOWS\system32\RDPBASE.dll->CRdpFIPSEncryption_CreateInstance
[i] [3680][4728][vmms.exe] Start Address of Thread 7ffb69224030 in C:\WINDOWS\system32\RDPBASE.dll->CRdpFIPSEncryption_CreateInstance
[i] [3680][5084][vmms.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [3680][15636][vmms.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3680][17648][vmms.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3712][3716][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3712][3752][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [3712][19092][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3824][3828][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3824][3916][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [3824][3976][svchost.exe] Start Address of Thread 7ffb62b18830 in c:\windows\system32\usermgr.dll->UnknownFunction
[i] [3824][9500][svchost.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [3824][13136][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3824][3548][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3824][11560][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3824][16496][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3824][11856][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3824][15672][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3824][13000][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3832][3836][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3832][3960][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [3832][3980][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [3832][4016][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [3832][7964][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3832][19664][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3992][3996][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3992][20052][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4048][4052][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [4048][3936][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4048][4196][svchost.exe] Start Address of Thread 7ffb621ce880 in c:\windows\system32\es.dll->ServiceMain
[i] [4048][8228][svchost.exe] Start Address of Thread 7ffb621cd300 in c:\windows\system32\es.dll->ServiceMain
[i] [4048][11212][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4048][6504][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4048][13184][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4056][4060][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [4056][3272][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [4056][18044][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4056][3696][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4056][18380][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4056][15796][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [4072][4076][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [4072][3864][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [4072][14440][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3804][UNKNOWN] not analysed 31
[i] [2492][3912][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2492][21648][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2492][14160][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3924][3920][WUDFHost.exe] Start Address of Thread 7ff745b60d40 in C:\Windows\System32\WUDFHost.exe->UnknownFunction
[i] [3924][4100][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3924][4104][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3924][4108][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3924][4112][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3924][21328][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3924][10724][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4132][4136][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [4132][4244][svchost.exe] Start Address of Thread 7ffb6f179160 in c:\windows\system32\AUTHZ.dll->AuthzInitializeResourceManagerEx
[i] [4132][4352][svchost.exe] Start Address of Thread 7ffb6f179160 in c:\windows\system32\AUTHZ.dll->AuthzInitializeResourceManagerEx
[i] [4132][5676][svchost.exe] Start Address of Thread 7ffb6f179160 in c:\windows\system32\AUTHZ.dll->AuthzInitializeResourceManagerEx
[i] [4132][5720][svchost.exe] Start Address of Thread 7ffb56422f10 in c:\windows\system32\mpssvc.dll->ServiceMain
[i] [4132][5824][svchost.exe] Start Address of Thread 7ffb618937d0 in c:\windows\system32\bfe.dll->BfeGetDirectDispatchTable
[i] [4132][5852][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4132][6172][svchost.exe] Start Address of Thread 7ffb56428ab0 in c:\windows\system32\mpssvc.dll->ServiceMain
[i] [4132][6564][svchost.exe] Start Address of Thread 7ffb5641f8e0 in c:\windows\system32\mpssvc.dll->UnknownFunction
[i] [4132][6568][svchost.exe] Start Address of Thread 7ffb56427f40 in c:\windows\system32\mpssvc.dll->ServiceMain
[i] [4132][16380][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4132][8032][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4132][6484][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4132][2476][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4164][4168][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [4164][4236][svchost.exe] Start Address of Thread 7ffb61b25520 in c:\windows\system32\audioendpointbuilder.dll->UnknownFunction
[i] [4164][9248][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4164][13504][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4184][4188][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [4184][4260][svchost.exe] Start Address of Thread 7ffb61730080 in c:\windows\system32\fntcache.dll->UnknownFunction
[i] [4184][4264][svchost.exe] Start Address of Thread 7ffb61761e80 in c:\windows\system32\fntcache.dll->ServiceMain
[i] [4184][9648][svchost.exe] Start Address of Thread 7ffb61730080 in c:\windows\system32\fntcache.dll->UnknownFunction
[i] [4184][9292][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4184][656][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4372][4376][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [4372][4436][svchost.exe] Start Address of Thread 7ffb6d4165d0 in c:\windows\system32\coremessaging.dll->SvchostPushServiceGlobals
[i] [4372][8640][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4372][15132][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4488][4492][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [4488][4180][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4508][4512][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [4508][16008][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4564][4568][dashost.exe] Start Address of Thread 7ff70e81ea20 in C:\WINDOWS\system32\dashost.exe->UnknownFunction
[i] [4564][5024][dashost.exe] Start Address of Thread 7ffb683b1760 in C:\WINDOWS\system32\SSDPAPI.dll->RegisterServiceEx
[i] [4564][5272][dashost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4564][7796][dashost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4564][17548][dashost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4564][8620][dashost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4660][4664][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [4660][4788][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4660][4964][svchost.exe] Start Address of Thread 7ffb5f231910 in c:\windows\system32\ssdpsrv.dll->SvchostPushServiceGlobals
[i] [4660][4968][svchost.exe] Start Address of Thread 7ffb5f2363e0 in c:\windows\system32\ssdpsrv.dll->SvchostPushServiceGlobals
[i] [4660][5048][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4660][4692][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4660][1532][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4660][7896][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4660][17984][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4740][4744][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [4740][4860][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [4740][4880][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4740][4888][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4740][4896][svchost.exe] Start Address of Thread 7ffb5ec7cfd0 in c:\windows\system32\sensrsvc.dll->UnknownFunction
[i] [4740][5000][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4740][5112][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4740][5064][svchost.exe] Start Address of Thread 7ffb5d8a1f60 in C:\WINDOWS\System32\RotMgr.dll->UnknownFunction
[i] [4740][10680][svchost.exe] Start Address of Thread 7ffb5f3068e0 in C:\WINDOWS\System32\SensorsNativeApi.V2.dll->SensorGetFifoMaxSizeV2
[i] [4740][22656][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4772][4776][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [4772][4924][svchost.exe] Start Address of Thread 7ffb5ecadf60 in c:\windows\system32\sensorservice.dll->ServiceMain
[i] [4772][4928][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4772][4932][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4772][4948][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4772][5004][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4772][8440][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5056][5060][vmcompute.exe] Start Address of Thread 7ff636c65800 in C:\WINDOWS\system32\vmcompute.exe->ORSetKeySecurity
[i] [5056][5072][vmcompute.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [5056][16408][vmcompute.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2648][4232][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [2648][5152][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2648][5160][svchost.exe] Start Address of Thread 7ffb576e7d10 in c:\windows\system32\audiosrv.dll->ServiceMain
[i] [2648][5164][svchost.exe] Start Address of Thread 7ffb576e9710 in c:\windows\system32\audiosrv.dll->ServiceMain
[i] [2648][5172][svchost.exe] Start Address of Thread 7ffb57625b70 in c:\windows\system32\AUDIOSRVPOLICYMANAGER.dll->ActivatePolicyManager
[i] [2648][11156][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2648][13804][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2648][21432][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2648][21472][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2648][21216][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2648][6704][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [2648][21684][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5252][5256][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [5252][7756][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5252][7908][svchost.exe] Start Address of Thread 7ffb6c88eac0 in c:\windows\system32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [5252][4092][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5252][8664][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5316][5320][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [5316][5484][svchost.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [5316][5508][svchost.exe] Start Address of Thread 7ffb56972710 in C:\WINDOWS\SYSTEM32\wlgpclnt.dll->GenerateWLANPolicy
[i] [5316][5532][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5316][5596][svchost.exe] Start Address of Thread 7ffb6c88eac0 in c:\windows\system32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [5316][5640][svchost.exe] Start Address of Thread 7ffb568a17e0 in C:\WINDOWS\SYSTEM32\wifinetworkmanager.dll->DllGetClassObject
[i] [5316][6448][svchost.exe] Start Address of Thread 7ffb6f179160 in c:\windows\system32\AUTHZ.dll->AuthzInitializeResourceManagerEx
[i] [5316][1732][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5316][20308][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5316][3620][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5316][9028][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5316][3536][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5316][22288][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5316][13428][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5316][19588][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5468][5472][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [5468][5492][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [5468][5520][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5468][5812][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [5468][18548][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5512][5516][spoolsv.exe] Start Address of Thread 7ff7df9e30c0 in C:\WINDOWS\System32\spoolsv.exe->PrvSplProcessSessionEvent
[i] [5512][5552][spoolsv.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [5512][5612][spoolsv.exe] Start Address of Thread 7ff7df9fec30 in C:\WINDOWS\System32\spoolsv.exe->PrvRouterInstallPrinterDriverPackageFromConnection
[i] [5512][10124][spoolsv.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5512][10176][spoolsv.exe] Start Address of Thread 7ffb3d63015c in C:\WINDOWS\System32\HPMPM081.DLL->InitializePrintMonitorUI
[i] [5512][10180][spoolsv.exe] Start Address of Thread 7ffb3d62a7b0 in C:\WINDOWS\System32\HPMPM081.DLL->InitializePrintMonitorUI
[i] [5512][7332][spoolsv.exe] Start Address of Thread 7ffb3d733500 in C:\WINDOWS\System32\PrintIsolationProxy.dll->Ordinal401
[i] [5512][7928][spoolsv.exe] Start Address of Thread 7ffb3d7eb920 in C:\WINDOWS\System32\localspl.dll->InitializePrintMonitor2
[i] [5512][14416][spoolsv.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5512][16656][spoolsv.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5512][11140][spoolsv.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5512][16580][spoolsv.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5616][5620][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [5616][5656][svchost.exe] Start Address of Thread 7ffb566677a0 in c:\windows\system32\wbiosrvc.dll->OutOfProcessExceptionEventDebuggerLaunchCallback
[i] [5616][5664][svchost.exe] Start Address of Thread 7ffb566677a0 in c:\windows\system32\wbiosrvc.dll->OutOfProcessExceptionEventDebuggerLaunchCallback
[i] [5616][6300][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [5616][6308][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5616][6344][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [5616][7224][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5616][7280][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5616][7396][svchost.exe] Start Address of Thread 7ffb559bdaa0 in C:\WINDOWS\system32\FaceProcessor.dll->FileInputManager_SendInfraredFrameData
[i] [5616][7400][svchost.exe] Start Address of Thread 7ffb559bd9b0 in C:\WINDOWS\system32\FaceProcessor.dll->FileInputManager_SendInfraredFrameData
[i] [5616][12348][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5616][20844][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5776][5780][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [5776][5900][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [5776][6044][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5776][6136][svchost.exe] Start Address of Thread 7ffb625862a0 in C:\WINDOWS\system32\SSCORE.DLL->SsCoreUnlockVolumes
[i] [5776][18988][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5776][2284][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5784][5788][cb.exe] Start Address of Thread 7ff70a9fee30 in C:\WINDOWS\CarbonBlack\cb.exe->UnknownFunction
[i] [5784][6168][cb.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [5784][6400][cb.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5784][6924][cb.exe] Start Address of Thread 7ff70a871a80 in C:\WINDOWS\CarbonBlack\cb.exe->UnknownFunction
[i] [5784][6928][cb.exe] Start Address of Thread 7ff70a871a80 in C:\WINDOWS\CarbonBlack\cb.exe->UnknownFunction
[i] [5784][6932][cb.exe] Start Address of Thread 7ff70a871a80 in C:\WINDOWS\CarbonBlack\cb.exe->UnknownFunction
[i] [5784][6936][cb.exe] Start Address of Thread 7ff70a871a80 in C:\WINDOWS\CarbonBlack\cb.exe->UnknownFunction
[i] [5784][6496][cb.exe] Start Address of Thread 7ff70a871a80 in C:\WINDOWS\CarbonBlack\cb.exe->UnknownFunction
[i] [5784][6524][cb.exe] Start Address of Thread 7ff70a871a80 in C:\WINDOWS\CarbonBlack\cb.exe->UnknownFunction
[i] [5784][6588][cb.exe] Start Address of Thread 7ff70a871a80 in C:\WINDOWS\CarbonBlack\cb.exe->UnknownFunction
[i] [5784][6736][cb.exe] Start Address of Thread 7ff70a871a80 in C:\WINDOWS\CarbonBlack\cb.exe->UnknownFunction
[i] [5784][6024][cb.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5784][1932][cb.exe] Start Address of Thread 7ffb55de9ae0 in C:\WINDOWS\WinSxS\amd64_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.19041.1466_none_91a4907ccc87e3b8\gdiplus.dll->GdiplusStartup
[i] [5784][6028][cb.exe] Start Address of Thread 7ff70a8624e0 in C:\WINDOWS\CarbonBlack\cb.exe->UnknownFunction
[i] [5784][12824][cb.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5784][3900][cb.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5784][21196][cb.exe] Start Address of Thread 7ffb706abeb0 in C:\WINDOWS\System32\CRYPT32.dll->CertFreeCTLContext
[i] [5796][5800][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [5796][6076][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5796][7904][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5796][1464][svchost.exe] Start Address of Thread 7ffb52798de0 in C:\WINDOWS\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [5796][1184][svchost.exe] Start Address of Thread 7ffb52798de0 in C:\WINDOWS\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [5796][6616][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5796][23312][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5796][16584][svchost.exe] Start Address of Thread 7ffb561f5600 in c:\windows\system32\cryptsvc.dll->UnknownFunction
[i] [5796][10992][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5844][5848][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [5844][7364][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5844][7428][svchost.exe] Start Address of Thread 7ffb5543f4a0 in c:\windows\system32\diagtrack.dll->UtcSysprepGeneralize
[i] [5844][7432][svchost.exe] Start Address of Thread 7ffb5543f490 in c:\windows\system32\diagtrack.dll->UtcSysprepGeneralize
[i] [5844][7444][svchost.exe] Start Address of Thread 7ffb5544b320 in c:\windows\system32\diagtrack.dll->UtcSysprepGeneralize
[i] [5844][7452][svchost.exe] Start Address of Thread 7ffb5541aa80 in c:\windows\system32\diagtrack.dll->UtcSysprepGeneralize
[i] [5844][7456][svchost.exe] Start Address of Thread 7ffb554b7ce0 in c:\windows\system32\diagtrack.dll->UtcSysprepGeneralize
[i] [5844][7484][svchost.exe] Start Address of Thread 7ffb554b8d80 in c:\windows\system32\diagtrack.dll->UtcSysprepGeneralize
[i] [5844][7488][svchost.exe] Start Address of Thread 7ffb5541aa90 in c:\windows\system32\diagtrack.dll->UtcSysprepGeneralize
[i] [5844][22596][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5844][7292][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5844][16576][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5844][19684][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5844][16492][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5844][20492][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [5872][5876][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [5872][6108][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [5872][6272][svchost.exe] Start Address of Thread 7ffb54fe9eb0 in c:\windows\system32\dps.dll->ServiceMain
[i] [5872][6304][svchost.exe] Start Address of Thread 7ffb54febc70 in c:\windows\system32\dps.dll->ServiceMain
[i] [5872][7216][svchost.exe] Start Address of Thread 7ffb6c88eac0 in c:\windows\system32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [5872][7248][svchost.exe] Start Address of Thread 7ffb53821480 in C:\WINDOWS\System32\wpnsruprov.dll->UnknownFunction
[i] [5872][7252][svchost.exe] Start Address of Thread 7ffb521900d0 in C:\WINDOWS\System32\appsruprov.dll->LogMemoryPerfCountersPeriodically
[i] [5872][7688][svchost.exe] Start Address of Thread 7ffb52049ba0 in C:\WINDOWS\System32\energyprov.dll->SruInitializeProvider
[i] [5872][8756][svchost.exe] Start Address of Thread 7ffb53cf42e0 in C:\WINDOWS\system32\radardt.dll->WdiHandleInstance
[i] [5872][2624][svchost.exe] Start Address of Thread 7ffb53cf23a0 in C:\WINDOWS\system32\radardt.dll->WdiHandleInstance
[i] [5872][18176][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5872][16148][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5872][18576][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5872][6372][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5872][7132][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5872][12760][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5872][17520][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5872][22268][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5872][12264][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5872][20776][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5872][10376][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5872][20220][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5872][16972][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5916][5920][esif_uf.exe] Start Address of Thread 7ff7e8ba6e40 in C:\WINDOWS\System32\Intel\DPTF\esif_uf.exe->UnknownFunction
[i] [5916][6036][esif_uf.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [5916][6256][esif_uf.exe] Start Address of Thread 7ff7e8b984a0 in C:\WINDOWS\System32\Intel\DPTF\esif_uf.exe->UnknownFunction
[i] [5916][2468][esif_uf.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5964][5968][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [5964][6488][svchost.exe] Start Address of Thread 7ffb57983a60 in C:\WINDOWS\system32\httpprxm.dll->SubServiceStart
[i] [5964][6500][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5964][6852][svchost.exe] Start Address of Thread 7ffb57962e20 in C:\WINDOWS\system32\adhsvc.dll->SubServiceScmNotification
[i] [5964][22372][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5964][11596][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6064][6068][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [6064][6244][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [6064][13532][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6084][6088][openvpnserv.exe] Start Address of Thread 401520 in C:\Program Files\OpenVPN\bin\openvpnserv.exe->UnknownFunction
[i] [6084][6408][openvpnserv.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [6084][3764][openvpnserv.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6084][11796][openvpnserv.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6092][6096][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [6092][6464][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [6092][9460][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6092][21256][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6100][6104][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [6100][2956][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6116][6120][RtkAudUService64.exe] Start Address of Thread 7ff7643a1ab8 in C:\WINDOWS\System32\DriverStore\FileRepository\hdxsstm.inf_amd64_7d200f2580ecd8a5\RtkAudUService64.exe->UnknownFunction
[i] [6116][6348][RtkAudUService64.exe] Start Address of Thread 7ff764349e00 in C:\WINDOWS\System32\DriverStore\FileRepository\hdxsstm.inf_amd64_7d200f2580ecd8a5\RtkAudUService64.exe->UnknownFunction
[i] [6116][6352][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6116][6600][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6116][6620][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6116][6660][RtkAudUService64.exe] Start Address of Thread 7ff76438dbd0 in C:\WINDOWS\System32\DriverStore\FileRepository\hdxsstm.inf_amd64_7d200f2580ecd8a5\RtkAudUService64.exe->UnknownFunction
[i] [6116][6720][RtkAudUService64.exe] Start Address of Thread 7ff764349e00 in C:\WINDOWS\System32\DriverStore\FileRepository\hdxsstm.inf_amd64_7d200f2580ecd8a5\RtkAudUService64.exe->UnknownFunction
[i] [6116][6820][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6116][6860][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6116][6876][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6116][13836][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6116][4684][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6116][13200][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6116][5336][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2568][5660][sqlwriter.exe] Start Address of Thread 7ff6acbaeaf8 in C:\Program Files\Microsoft SQL Server\90\Shared\sqlwriter.exe->DmpRemoteDumpRequest
[i] [2568][6312][sqlwriter.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [2568][17060][sqlwriter.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3496][5940][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3496][6192][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [3496][6428][svchost.exe] Start Address of Thread 7ffb54543e60 in c:\windows\system32\wiaservc.dll->UnknownFunction
[i] [3496][6440][svchost.exe] Start Address of Thread 7ffb5454ecc0 in c:\windows\system32\wiaservc.dll->UnknownFunction
[i] [3496][4620][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6152][6156][SurfaceColorService.exe] Start Address of Thread 7ff7f02b1230 in C:\WINDOWS\System32\SurfaceColorService.exe->UnknownFunction
[i] [6152][12528][SurfaceColorService.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6152][9356][SurfaceColorService.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6316][6320][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [6316][7016][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6316][7020][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6324][C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2111.5-0\MsMpEng.exe] not analysed 5
[i] [6332][6336][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [6332][6668][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6332][9464][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [6332][17172][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6332][19788][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6332][22640][svchost.exe] Start Address of Thread 7ffb6fbd1010 in C:\WINDOWS\system32\mswsock.dll->UnknownFunction
[i] [6332][23176][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6364][6368][com.docker.service] Start Address of Thread 2413a810000 in C:\Program Files\Docker\Docker\com.docker.service->UnknownFunction
[i] [6364][7152][com.docker.service] Start Address of Thread 7ffb50d67c40 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->GC_Initialize
[i] [6364][7156][com.docker.service] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [6364][7548][com.docker.service] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6364][8016][com.docker.service] Start Address of Thread 7ffb50bd9d10 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [6364][8072][com.docker.service] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [6364][17044][com.docker.service] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6376][6380][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [6376][6724][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [6376][7308][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6376][21628][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6528][6532][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [6528][6792][svchost.exe] Start Address of Thread 7ffb531773f0 in c:\windows\system32\tapisrv.dll->ServiceMain
[i] [6528][6796][svchost.exe] Start Address of Thread 7ffb531773f0 in c:\windows\system32\tapisrv.dll->ServiceMain
[i] [6528][6800][svchost.exe] Start Address of Thread 7ffb531773f0 in c:\windows\system32\tapisrv.dll->ServiceMain
[i] [6528][6804][svchost.exe] Start Address of Thread 7ffb531773f0 in c:\windows\system32\tapisrv.dll->ServiceMain
[i] [6528][7268][svchost.exe] Start Address of Thread 7ffb51b3da30 in C:\WINDOWS\System32\unimdm.tsp->uhelp
[i] [6528][7272][svchost.exe] Start Address of Thread 7ffb51b11520 in C:\WINDOWS\System32\uniplat.dll->Ordinal198
[i] [6528][7276][svchost.exe] Start Address of Thread 7ffb519930e0 in C:\WINDOWS\System32\kmddsp.tsp->UnknownFunction
[i] [6528][7296][svchost.exe] Start Address of Thread 7ffb51981ab0 in C:\WINDOWS\System32\hidphone.tsp->UnknownFunction
[i] [6528][12856][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6880][6884][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [6880][6920][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [6880][7232][svchost.exe] Start Address of Thread 7ffb52472490 in C:\WINDOWS\System32\rastapi.DLL->CheckRasmanDependency
[i] [6880][7236][svchost.exe] Start Address of Thread 7ffb5245d570 in C:\WINDOWS\System32\rastapi.DLL->UnknownFunction
[i] [6880][7300][svchost.exe] Start Address of Thread 7ffb521c1ad0 in C:\WINDOWS\SYSTEM32\tapi32.dll->NonAsyncEventThread
[i] [6880][7316][svchost.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [6880][7328][svchost.exe] Start Address of Thread 7ffb52b89db0 in C:\WINDOWS\SYSTEM32\rasmans.dll->ServiceMain
[i] [6880][7376][svchost.exe] Start Address of Thread 7ffb518b7a70 in C:\WINDOWS\system32\rasppp.dll->PppStop
[i] [6880][7384][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6880][7424][svchost.exe] Start Address of Thread 7ffb52bf5fe0 in C:\WINDOWS\SYSTEM32\rasmans.dll->NlmGetBestCostNetworkConnection
[i] [6880][7436][svchost.exe] Start Address of Thread 7ffb52be1220 in C:\WINDOWS\SYSTEM32\rasmans.dll->NlmGetBestCostNetworkConnection
[i] [6880][7480][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6880][20928][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6880][3284][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6880][19860][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6880][17744][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8156][8160][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [8156][16364][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8156][10924][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3092][C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2111.5-0\NisSrv.exe] not analysed 5
[i] [8468][8472][wmiprvse.exe] Start Address of Thread 7ff7546f2580 in C:\WINDOWS\system32\wbem\wmiprvse.exe->UnknownFunction
[i] [8468][8512][wmiprvse.exe] Start Address of Thread 7ffb60c43ca0 in C:\WINDOWS\SYSTEM32\NCObjAPI.DLL->WmiAddObjectProp
[i] [8468][8548][wmiprvse.exe] Start Address of Thread 7ff7546eb120 in C:\WINDOWS\system32\wbem\wmiprvse.exe->UnknownFunction
[i] [8468][14200][wmiprvse.exe] Start Address of Thread 7ffb3dae74d0 in C:\WINDOWS\system32\wbem\wmipiprt.dll->DllUnregisterServer
[i] [8468][5588][wmiprvse.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8468][11200][wmiprvse.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8468][15712][wmiprvse.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [9064][9068][dptf_helper.exe] Start Address of Thread 7ff6ff6762d0 in C:\WINDOWS\system32\Intel\DPTF\dptf_helper.exe->UnknownFunction
[i] [9064][9092][dptf_helper.exe] Start Address of Thread 7ff6ff675900 in C:\WINDOWS\system32\Intel\DPTF\dptf_helper.exe->UnknownFunction
[i] [9064][9096][dptf_helper.exe] Start Address of Thread 7ff6ff674060 in C:\WINDOWS\system32\Intel\DPTF\dptf_helper.exe->UnknownFunction
[i] [9064][5028][dptf_helper.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9192][9196][sihost.exe] Start Address of Thread 7ff669535eb0 in C:\WINDOWS\system32\sihost.exe->UnknownFunction
[i] [9192][8344][sihost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [9192][2304][sihost.exe] Start Address of Thread 7ffb4caebef0 in C:\Windows\System32\modernexecserver.dll->UnknownFunction
[i] [9192][2128][sihost.exe] Start Address of Thread 7ff669535050 in C:\WINDOWS\system32\sihost.exe->UnknownFunction
[i] [9192][8720][sihost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9192][7184][sihost.exe] Start Address of Thread 7ffb4ce265e0 in C:\WINDOWS\system32\activationmanager.dll->DllCanUnloadNow
[i] [9192][13556][sihost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [9192][19964][sihost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9192][10940][sihost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9192][23180][sihost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9192][20612][sihost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [9192][3504][sihost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9192][5652][sihost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9192][17248][sihost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9192][4912][sihost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9192][11632][sihost.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [8264][5308][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [8264][8428][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [8264][7816][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8264][10916][svchost.exe] Start Address of Thread 7ffb56959d00 in C:\WINDOWS\system32\WlanRadioManager.dll->DllGetClassObject
[i] [8264][10920][svchost.exe] Start Address of Thread 7ffb6c88eac0 in c:\windows\system32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [8264][12736][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8264][18680][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8264][8596][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8264][13680][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8264][21708][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8264][22768][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8264][19356][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8264][3420][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [8420][8396][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [8420][2496][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8420][9684][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8420][6196][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8420][8144][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8420][10536][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [8420][19828][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8420][13976][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8420][14824][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8420][11436][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8492][8484][SurfaceColorTracker.exe] Start Address of Thread 7ff70519730c in C:\WINDOWS\System32\SurfaceColorTracker.exe->UnknownFunction
[i] [8492][8764][SurfaceColorTracker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8592][5956][taskhostw.exe] Start Address of Thread 7ff6e0905bf0 in C:\WINDOWS\system32\taskhostw.exe->UnknownFunction
[i] [8592][8760][taskhostw.exe] Start Address of Thread 7ff6e09012d0 in C:\WINDOWS\system32\taskhostw.exe->UnknownFunction
[i] [8592][8588][taskhostw.exe] Start Address of Thread 7ffb4f501210 in C:\WINDOWS\System32\PlaySndSrv.dll->UnknownFunction
[i] [8592][5924][taskhostw.exe] Start Address of Thread 7ffb519531b0 in C:\WINDOWS\System32\WINMM.dll->timeGetTime
[i] [8592][10120][taskhostw.exe] Start Address of Thread 7ffb52798de0 in C:\WINDOWS\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [8592][10132][taskhostw.exe] Start Address of Thread 7ffb52798de0 in C:\WINDOWS\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [8592][292][taskhostw.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8592][10700][taskhostw.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8592][18120][taskhostw.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8592][3488][taskhostw.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8592][5236][taskhostw.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8592][3512][taskhostw.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7040][7344][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [7040][7696][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [7040][5952][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7040][19924][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7040][17452][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7040][8936][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7040][8696][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [7040][4616][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7040][10696][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7040][15460][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7040][11824][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7040][17964][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7040][7516][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7040][16968][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7040][14364][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7040][636][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7040][17852][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7040][6536][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7040][23168][svchost.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [3608][4476][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [3608][8736][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [3608][8748][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3608][9280][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [3608][9844][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [3608][2588][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3608][9584][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3608][18032][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3608][7388][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3608][21940][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3608][20172][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [3608][12432][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8868][8308][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [8868][9084][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [8868][9296][svchost.exe] Start Address of Thread 7ffb46fdd7a0 in C:\WINDOWS\system32\WwanRadioManager.dll->DllGetClassObject
[i] [8868][9324][svchost.exe] Start Address of Thread 7ffb46fb99c0 in C:\WINDOWS\system32\XboxGipRadioManager.dll->DllUnregisterServer
[i] [8868][9328][svchost.exe] Start Address of Thread 7ffb56959d00 in C:\WINDOWS\system32\WlanRadioManager.dll->DllGetClassObject
[i] [8868][9332][svchost.exe] Start Address of Thread 7ffb6c88eac0 in c:\windows\system32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [8868][14204][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8868][7852][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9176][4176][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [9176][22472][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][8972][Explorer.EXE] Start Address of Thread 7ff642010ec0 in C:\WINDOWS\Explorer.EXE->UnknownFunction
[i] [9120][9496][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][9656][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][9660][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][9740][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][9744][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][9748][Explorer.EXE] Start Address of Thread 7ff641f87b90 in C:\WINDOWS\Explorer.EXE->UnknownFunction
[i] [9120][9756][Explorer.EXE] Start Address of Thread 7ffb6efa0b10 in C:\Windows\System32\sppc.dll->SLpVLActivateProduct
[i] [9120][9768][Explorer.EXE] Start Address of Thread 7ffb449ef540 in C:\Windows\System32\windows.immersiveshell.serviceprovider.dll->UnknownFunction
[i] [9120][9840][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][9876][Explorer.EXE] Start Address of Thread 7ffb5ed76800 in C:\Windows\System32\InputHost.dll->DllGetActivationFactory
[i] [9120][9880][Explorer.EXE] Start Address of Thread 7ffb453f39a0 in C:\Windows\System32\twinui.pcshell.dll->DllGetClassObject
[i] [9120][9892][Explorer.EXE] Start Address of Thread 7ffb4529eff0 in C:\Windows\System32\twinui.pcshell.dll->DllCanUnloadNow
[i] [9120][9944][Explorer.EXE] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [9120][9952][Explorer.EXE] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [9120][9968][Explorer.EXE] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [9120][9972][Explorer.EXE] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [9120][9984][Explorer.EXE] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [9120][9988][Explorer.EXE] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [9120][10036][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][10040][Explorer.EXE] Start Address of Thread 7ffb485a6ad0 in C:\WINDOWS\System32\wlidprov.dll->DllCanUnloadNow
[i] [9120][10048][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][10052][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][10056][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][10076][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][10164][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][10416][Explorer.EXE] Start Address of Thread 7ffb485a6ad0 in C:\WINDOWS\System32\wlidprov.dll->DllCanUnloadNow
[i] [9120][11024][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][11044][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][4148][Explorer.EXE] Start Address of Thread 7ffb485a6ad0 in C:\WINDOWS\System32\wlidprov.dll->DllCanUnloadNow
[i] [9120][11120][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][11128][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][11184][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][11216][Explorer.EXE] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [9120][10368][Explorer.EXE] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [9120][10608][Explorer.EXE] Start Address of Thread 7ffb6c88eac0 in c:\windows\system32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [9120][10584][Explorer.EXE] Start Address of Thread 7ffb47adbd60 in C:\Windows\System32\TetheringStation.dll->TetheringStationFreeMemory
[i] [9120][9492][Explorer.EXE] Start Address of Thread 7ffb6c88eac0 in c:\windows\system32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [9120][9868][Explorer.EXE] Start Address of Thread 7ffb6c88eac0 in c:\windows\system32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [9120][9924][Explorer.EXE] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [9120][6940][Explorer.EXE] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [9120][11340][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][11940][Explorer.EXE] Start Address of Thread 7ffb406226b0 in C:\WINDOWS\SYSTEM32\fxsst.dll->DllMain
[i] [9120][10976][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][10980][Explorer.EXE] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [9120][10500][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][10968][Explorer.EXE] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [9120][10984][Explorer.EXE] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [9120][10996][Explorer.EXE] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [9120][13628][Explorer.EXE] Start Address of Thread 7ffb41861c90 in C:\WINDOWS\SYSTEM32\msiltcfg.dll->RestartMsi
[i] [9120][8204][Explorer.EXE] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [9120][12652][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][16632][Explorer.EXE] Start Address of Thread 7ffb530235b0 in UnknownModule->UnknownFunction
[i] [9120][12040][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][7660][Explorer.EXE] Start Address of Thread 7ffb519531b0 in C:\WINDOWS\System32\WINMM.dll->timeGetTime
[i] [9120][14292][Explorer.EXE] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [9120][19148][Explorer.EXE] Start Address of Thread 7ffb37b2aad0 in C:\WINDOWS\SYSTEM32\DUI70.dll->DrawShadowTextEx
[i] [9120][18108][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][18468][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][20080][Explorer.EXE] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [9120][5696][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][5556][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][1356][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][14252][Explorer.EXE] Start Address of Thread 7ffb69c943f0 in C:\Windows\System32\WorkFoldersShell.dll->DllGetClassObject
[i] [9120][21692][Explorer.EXE] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [9120][21704][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][13696][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][10372][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][5992][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][11180][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][18784][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][12648][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][12128][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][20396][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][19544][Explorer.EXE] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [9120][3472][Explorer.EXE] Start Address of Thread 7ffb69ca35b0 in C:\Windows\System32\WorkFoldersShell.dll->DllUnregisterServer
[i] [9120][2024][Explorer.EXE] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9120][21768][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][3688][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][10660][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][22696][Explorer.EXE] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [9120][22952][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][22784][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][988][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][22480][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][19516][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][18104][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][18304][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][17972][Explorer.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9120][18420][Explorer.EXE] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [9120][12744][Explorer.EXE] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [9120][23432][Explorer.EXE] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [9120][12336][Explorer.EXE] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [9384][9388][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [9384][9548][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9384][22356][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9720][9724][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [9720][9848][svchost.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [9720][9860][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [9720][13920][svchost.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [9720][13156][svchost.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [9720][4208][svchost.exe] Start Address of Thread 7ffb725e17d0 in C:\WINDOWS\System32\ole32.dll->UnknownFunction
[i] [9720][23156][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9720][18868][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9720][15036][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [9720][10188][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [6384][9056][StartMenuExperienceHost.exe] Start Address of Thread 7ff7b6e93ef0 in C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe->UnknownFunction
[i] [6384][8660][StartMenuExperienceHost.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [6384][10200][StartMenuExperienceHost.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [6384][2828][StartMenuExperienceHost.exe] Start Address of Thread 7ffb5f13f150 in C:\WINDOWS\SYSTEM32\mrmcorer.dll->ShouldMergeInproc
[i] [6384][10544][StartMenuExperienceHost.exe] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [6384][15292][StartMenuExperienceHost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [6384][18900][StartMenuExperienceHost.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [6384][18624][StartMenuExperienceHost.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [6384][18232][StartMenuExperienceHost.exe] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [6384][11280][StartMenuExperienceHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6384][14900][StartMenuExperienceHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6384][17844][StartMenuExperienceHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6384][12312][StartMenuExperienceHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6384][13772][StartMenuExperienceHost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [6572][9732][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [6572][9940][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6572][8464][svchost.exe] Start Address of Thread 7ffb72dc4fe0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleasePool
[i] [6572][10156][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [6572][10080][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6572][10084][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6572][15480][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6572][16780][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7228][9344][mousocoreworker.exe] Start Address of Thread 7ff7909f1860 in C:\Windows\System32\mousocoreworker.exe->StoreIsSpace
[i] [7228][9424][mousocoreworker.exe] Start Address of Thread 7ffb72dc4fe0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleasePool
[i] [7228][10208][mousocoreworker.exe] Start Address of Thread 7ffb72dc4fe0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleasePool
[i] [7228][7560][mousocoreworker.exe] Start Address of Thread 7ff7908f7340 in C:\Windows\System32\mousocoreworker.exe->UnknownFunction
[i] [7228][13400][mousocoreworker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7228][15328][mousocoreworker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8456][8704][RuntimeBroker.exe] Start Address of Thread 7ff691526740 in C:\Windows\System32\RuntimeBroker.exe->UnknownFunction
[i] [8456][22716][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10748][10752][RuntimeBroker.exe] Start Address of Thread 7ff691526740 in C:\Windows\System32\RuntimeBroker.exe->UnknownFunction
[i] [10748][12140][RuntimeBroker.exe] Start Address of Thread 7ffb5ed76800 in C:\Windows\System32\InputHost.dll->DllGetActivationFactory
[i] [10748][12144][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10748][20248][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10748][3000][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10748][19592][RuntimeBroker.exe] Start Address of Thread 7ffb6efa0b10 in C:\Windows\System32\sppc.dll->SLpVLActivateProduct
[i] [10748][22360][RuntimeBroker.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [10748][7052][RuntimeBroker.exe] Start Address of Thread 7ffb6c88eac0 in c:\windows\system32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [10748][17580][RuntimeBroker.exe] Start Address of Thread 7ffb47adbd60 in C:\Windows\System32\TetheringStation.dll->TetheringStationFreeMemory
[i] [10748][3016][RuntimeBroker.exe] Start Address of Thread 7ffb6c88eac0 in c:\windows\system32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [10748][3520][RuntimeBroker.exe] Start Address of Thread 7ffb6c88eac0 in c:\windows\system32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [10748][20660][RuntimeBroker.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [10748][20456][RuntimeBroker.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [10748][16744][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10748][16480][RuntimeBroker.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [10748][8504][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10748][21088][RuntimeBroker.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [10748][13328][RuntimeBroker.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [10748][4392][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11048][11028][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [11048][11108][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [11048][7348][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11048][22352][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11048][20832][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11048][21036][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11048][4556][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [11048][17592][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10352][10332][ctfmon.exe] Start Address of Thread 7ff7b2be11c0 in C:\WINDOWS\system32\ctfmon.exe->UnknownFunction
[i] [10352][11160][ctfmon.exe] Start Address of Thread 7ffb72b2cd30 in C:\WINDOWS\System32\MSCTF.dll->TF_Notify
[i] [10352][10600][ctfmon.exe] Start Address of Thread 7ffb4d7b4780 in C:\WINDOWS\system32\MsCtfMonitor.dll->DoMsCtfMonitor
[i] [10352][10140][ctfmon.exe] Start Address of Thread 7ffb38540ee0 in C:\WINDOWS\system32\InputService.dll->InitializeService
[i] [10352][10144][ctfmon.exe] Start Address of Thread 7ffb38540d40 in C:\WINDOWS\system32\InputService.dll->InitializeService
[i] [10352][10160][ctfmon.exe] Start Address of Thread 7ffb39258ac0 in C:\WINDOWS\system32\MTFServer.dll->DllCanUnloadNow
[i] [10352][10116][ctfmon.exe] Start Address of Thread 7ffb39258ac0 in C:\WINDOWS\system32\MTFServer.dll->DllCanUnloadNow
[i] [10352][10108][ctfmon.exe] Start Address of Thread 7ffb39258ac0 in C:\WINDOWS\system32\MTFServer.dll->DllCanUnloadNow
[i] [10352][9996][ctfmon.exe] Start Address of Thread 7ffb5ed76800 in C:\Windows\System32\InputHost.dll->DllGetActivationFactory
[i] [10352][9552][ctfmon.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10352][19748][ctfmon.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10352][11504][ctfmon.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [11176][7916][TabTip.exe] Start Address of Thread 7ff7dd49ae60 in C:\Program Files\Common Files\microsoft shared\ink\TabTip.exe->UnknownFunction
[i] [11176][9380][TabTip.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [11176][10128][TabTip.exe] Start Address of Thread 7ff7dd499f30 in C:\Program Files\Common Files\microsoft shared\ink\TabTip.exe->UnknownFunction
[i] [11176][11112][TabTip.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [11176][11168][TabTip.exe] Start Address of Thread 7ffb55de9ae0 in C:\WINDOWS\WinSxS\amd64_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.19041.1466_none_91a4907ccc87e3b8\gdiplus.dll->GdiplusStartup
[i] [11176][9620][TabTip.exe] Start Address of Thread 7ffb4af2ecb0 in C:\Program Files\Common Files\Microsoft Shared\Ink\IpsPlugin.dll->DllUnregisterServer
[i] [11176][10020][TabTip.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [11176][9992][TabTip.exe] Start Address of Thread 7ffb41cd34e0 in C:\Program Files\Common Files\microsoft shared\ink\tabskb.dll->DllCanUnloadNow
[i] [11176][19180][TabTip.exe] Start Address of Thread 7ff7dd4cc890 in C:\Program Files\Common Files\microsoft shared\ink\TabTip.exe->UnknownFunction
[i] [11176][16808][TabTip.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11176][19248][TabTip.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11176][22376][TabTip.exe] Start Address of Thread 7ff7dd4cc890 in C:\Program Files\Common Files\microsoft shared\ink\TabTip.exe->UnknownFunction
[i] [9264][10900][TextInputHost.exe] Start Address of Thread 7ff7a2681300 in C:\WINDOWS\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\InputApp\TextInputHost.exe->UnknownFunction
[i] [9264][11244][TextInputHost.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9264][11204][TextInputHost.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [9264][9960][TextInputHost.exe] Start Address of Thread 7ffb5f13f150 in C:\WINDOWS\SYSTEM32\mrmcorer.dll->ShouldMergeInproc
[i] [9264][8452][TextInputHost.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [9264][10224][TextInputHost.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [9264][11324][TextInputHost.exe] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [9264][11384][TextInputHost.exe] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [9264][21116][TextInputHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9264][18300][TextInputHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9264][13784][TextInputHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8092][7568][LockApp.exe] Start Address of Thread 7ff6b7eb2410 in C:\WINDOWS\SystemApps\Microsoft.LockApp_cw5n1h2txyewy\LockApp.exe->UnknownFunction
[i] [8092][9592][LockApp.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [8092][11272][LockApp.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [8092][11304][LockApp.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [8092][11352][LockApp.exe] Start Address of Thread 7ffb5f13f150 in C:\Windows\System32\MrmCoreR.dll->ShouldMergeInproc
[i] [8092][11836][LockApp.exe] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [8092][14328][LockApp.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [8092][19852][LockApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8092][11020][LockApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8092][8460][LockApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8092][13844][LockApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8092][13216][LockApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8092][12836][LockApp.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [8092][19956][LockApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8092][14912][LockApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11476][11480][RuntimeBroker.exe] Start Address of Thread 7ff691526740 in C:\Windows\System32\RuntimeBroker.exe->UnknownFunction
[i] [11476][11612][RuntimeBroker.exe] Start Address of Thread 7ffb40b0dea0 in C:\Windows\System32\lockappbroker.dll->UnknownFunction
[i] [11476][11656][RuntimeBroker.exe] Start Address of Thread 7ffb6c88eac0 in C:\WINDOWS\SYSTEM32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [11476][11660][RuntimeBroker.exe] Start Address of Thread 7ffb47adbd60 in C:\Windows\System32\TetheringStation.dll->TetheringStationFreeMemory
[i] [11476][11688][RuntimeBroker.exe] Start Address of Thread 7ffb6c88eac0 in C:\WINDOWS\SYSTEM32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [11476][11700][RuntimeBroker.exe] Start Address of Thread 7ffb6c88eac0 in C:\WINDOWS\SYSTEM32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [11476][17476][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11476][21360][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11476][20852][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12112][12116][SettingSyncHost.exe] Start Address of Thread 7ff7b9beb610 in C:\WINDOWS\system32\SettingSyncHost.exe->UnknownFunction
[i] [12112][12220][SettingSyncHost.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [12112][2964][SettingSyncHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12112][14376][SettingSyncHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12112][12164][SettingSyncHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12112][15888][SettingSyncHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12112][16916][SettingSyncHost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [12112][10392][SettingSyncHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12112][7828][SettingSyncHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12000][12148][DllHost.exe] Start Address of Thread 7ff7d92414e0 in C:\WINDOWS\system32\DllHost.exe->UnknownFunction
[i] [12000][11692][DllHost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [12000][12340][DllHost.exe] Start Address of Thread 7ffb52798de0 in C:\WINDOWS\SYSTEM32\ESENT.dll->JetEnableMultiInstanceA
[i] [12000][12344][DllHost.exe] Start Address of Thread 7ffb52798de0 in C:\WINDOWS\SYSTEM32\ESENT.dll->JetEnableMultiInstanceA
[i] [12000][22020][DllHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12000][13444][DllHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12000][20132][DllHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12000][14648][DllHost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [12000][16292][DllHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12000][10856][DllHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12000][22940][DllHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12628][12632][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\System32\svchost.exe->UnknownFunction
[i] [12628][23384][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12628][10664][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13048][13052][SecurityHealthSystray.exe] Start Address of Thread 7ff6404c5a10 in C:\Windows\System32\SecurityHealthSystray.exe->UnknownFunction
[i] [13048][19056][SecurityHealthSystray.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13112][C:\Windows\System32\SecurityHealthService.exe] not analysed 5
[i] [13188][13192][RtkAudUService64.exe] Start Address of Thread 7ff7643a1ab8 in C:\Windows\System32\DriverStore\FileRepository\hdxsstm.inf_amd64_7d200f2580ecd8a5\RtkAudUService64.exe->UnknownFunction
[i] [13188][13224][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13188][13248][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13188][13252][RtkAudUService64.exe] Start Address of Thread 7ff76438dbd0 in C:\Windows\System32\DriverStore\FileRepository\hdxsstm.inf_amd64_7d200f2580ecd8a5\RtkAudUService64.exe->UnknownFunction
[i] [13188][13260][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13188][10412][RtkAudUService64.exe] Start Address of Thread 7ff764349e00 in C:\Windows\System32\DriverStore\FileRepository\hdxsstm.inf_amd64_7d200f2580ecd8a5\RtkAudUService64.exe->UnknownFunction
[i] [13188][6636][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13188][8216][RtkAudUService64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12392][12388][openvpn-gui.exe] Start Address of Thread 9714f0 in C:\Program Files\OpenVPN\bin\openvpn-gui.exe->UnknownFunction
[i] [12392][14048][openvpn-gui.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12392][20508][openvpn-gui.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12036][10736][wmiprvse.exe] Start Address of Thread 7ff7546f2580 in C:\WINDOWS\system32\wbem\wmiprvse.exe->UnknownFunction
[i] [12036][11896][wmiprvse.exe] Start Address of Thread 7ffb60c43ca0 in C:\WINDOWS\SYSTEM32\NCObjAPI.DLL->WmiAddObjectProp
[i] [12036][4812][wmiprvse.exe] Start Address of Thread 7ff7546eb120 in C:\WINDOWS\system32\wbem\wmiprvse.exe->UnknownFunction
[i] [12036][12992][wmiprvse.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12036][16824][wmiprvse.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6160][12664][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\System32\svchost.exe->UnknownFunction
[i] [6160][11380][svchost.exe] Start Address of Thread 7ffb39a22990 in c:\windows\system32\pcasvc.dll->UnknownFunction
[i] [6160][6416][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6160][6480][svchost.exe] Start Address of Thread 7ffb39a25cb0 in c:\windows\system32\pcasvc.dll->ServiceMain
[i] [6160][7556][svchost.exe] Start Address of Thread 7ffb39a25b20 in c:\windows\system32\pcasvc.dll->ServiceMain
[i] [6160][6420][svchost.exe] Start Address of Thread 7ffb39a35940 in c:\windows\system32\pcasvc.dll->PcaPatchSdbTask
[i] [6160][14168][svchost.exe] Start Address of Thread 7ffb39a21060 in c:\windows\system32\pcasvc.dll->UnknownFunction
[i] [6160][2696][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6160][16460][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5932][5880][Teams.exe] Start Address of Thread 7ff699475a70 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [5932][6868][Teams.exe] Start Address of Thread 7ff6967933a0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->GetHandleVerifier
[i] [5932][10396][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5932][12480][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5932][12656][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5932][12716][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5932][13228][Teams.exe] Start Address of Thread 7ff699482cb0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [5932][1352][Teams.exe] Start Address of Thread 7ff699482cb0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [5932][12920][Teams.exe] Start Address of Thread 7ff699482cb0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [5932][6904][Teams.exe] Start Address of Thread 7ff699482cb0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [5932][12404][Teams.exe] Start Address of Thread 7ff699482cb0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [5932][3236][Teams.exe] Start Address of Thread 7ff699482cb0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [5932][3252][Teams.exe] Start Address of Thread 7ff699482cb0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [5932][12520][Teams.exe] Start Address of Thread 7ff699482cb0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [5932][6436][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5932][3952][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5932][11540][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5932][11548][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5932][11532][Teams.exe] Start Address of Thread 7ff699482cb0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [5932][11344][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5932][3276][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5932][11260][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5932][13232][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5932][5700][Teams.exe] Start Address of Thread 7ffb2e39bd50 in C:\Windows\System32\MsSpellCheckingFacility.dll->DllUnregisterServer
[i] [5932][14080][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5932][14672][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [5932][14676][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [5932][8980][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [5932][8956][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [5932][14956][Teams.exe] Start Address of Thread 7ffb56959d00 in C:\WINDOWS\system32\WlanRadioManager.dll->DllGetClassObject
[i] [5932][14716][Teams.exe] Start Address of Thread 7ffb6c88eac0 in C:\WINDOWS\SYSTEM32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [5932][15524][Teams.exe] Start Address of Thread 7ffb4447fa20 in \\?\C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\resources\app.asar.unpacked\node_modules\office-int-win\build\Release\office-int-win.node->UnknownFunction
[i] [5932][15528][Teams.exe] Start Address of Thread 7ffb44462890 in \\?\C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\resources\app.asar.unpacked\node_modules\office-int-win\build\Release\office-int-win.node->UnknownFunction
[i] [5932][15532][Teams.exe] Start Address of Thread 7ffb444731a0 in \\?\C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\resources\app.asar.unpacked\node_modules\office-int-win\build\Release\office-int-win.node->UnknownFunction
[i] [5932][15556][Teams.exe] Start Address of Thread 7ffb4447c850 in \\?\C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\resources\app.asar.unpacked\node_modules\office-int-win\build\Release\office-int-win.node->UnknownFunction
[i] [5932][15680][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5932][16332][Teams.exe] Start Address of Thread 7ffb444750f0 in \\?\C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\resources\app.asar.unpacked\node_modules\office-int-win\build\Release\office-int-win.node->UnknownFunction
[i] [5932][15320][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [5932][16560][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5932][17556][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5932][16424][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5932][19560][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5932][12952][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [8280][12236][GoogleCrashHandler64.exe] Start Address of Thread 7ff7bc8210cc in C:\Program Files (x86)\Google\Update\1.3.36.112\GoogleCrashHandler64.exe->UnknownFunction
[i] [8280][14044][GoogleCrashHandler64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8280][14256][GoogleCrashHandler64.exe] Start Address of Thread 7ff7bc81fca8 in C:\Program Files (x86)\Google\Update\1.3.36.112\GoogleCrashHandler64.exe->UnknownFunction
[i] [8280][14280][GoogleCrashHandler64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12192][10932][Teams.exe] Start Address of Thread 7ff699475a70 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [12192][13132][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [12192][11056][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [12192][10512][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [12192][7100][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [12192][12620][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [12192][3444][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12192][11948][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [12192][13356][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [12192][13364][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [12192][13372][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [12192][13376][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [12192][9964][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12192][16432][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5756][12184][Teams.exe] Start Address of Thread 7ff699475a70 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [5756][3948][Teams.exe] Start Address of Thread 7ff6967933a0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->GetHandleVerifier
[i] [5756][6848][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5756][6812][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5756][6896][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5756][10232][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5756][8376][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5756][19240][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [5756][5428][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5756][8348][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5756][6612][Teams.exe] Start Address of Thread 7ffb6fbd1010 in C:\WINDOWS\system32\mswsock.dll->UnknownFunction
[i] [11084][4408][Teams.exe] Start Address of Thread 7ff699475a70 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [11084][11952][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [11084][12448][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [11084][4116][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [11084][7604][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11084][10312][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [11084][7984][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [11084][11032][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [11084][10556][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [11084][13300][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [11084][9256][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [11084][13380][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [11084][7572][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [11084][21636][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [11084][18456][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10756][10832][Teams.exe] Start Address of Thread 7ff699475a70 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [10756][10972][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][12208][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][2160][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][1416][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10756][11916][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][6284][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][10300][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][11076][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][10444][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][12240][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][13440][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][13892][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][14124][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][15496][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][9512][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][13452][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10756][21652][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [10756][6232][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [13412][13416][Teams.exe] Start Address of Thread 7ff699475a70 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [13412][13588][Teams.exe] Start Address of Thread 7ff6967933a0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->GetHandleVerifier
[i] [13412][13592][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [13412][13600][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [13412][13604][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [13412][13608][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13412][18812][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [13412][17184][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [13412][19708][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13412][6808][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13632][13636][slack.exe] Start Address of Thread 7ff7e0f16540 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [13632][13968][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13632][13980][slack.exe] Start Address of Thread 7ff7df94bb30 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->GetHandleVerifier
[i] [13632][13984][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13632][14000][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13632][14004][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13632][14008][slack.exe] Start Address of Thread 7ff7e0f255c0 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [13632][14012][slack.exe] Start Address of Thread 7ff7e0f255c0 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [13632][14016][slack.exe] Start Address of Thread 7ff7e0f255c0 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [13632][14020][slack.exe] Start Address of Thread 7ff7e0f255c0 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [13632][14088][slack.exe] Start Address of Thread 7ff7e0f255c0 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [13632][14092][slack.exe] Start Address of Thread 7ff7e0f255c0 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [13632][14096][slack.exe] Start Address of Thread 7ff7e0f255c0 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [13632][14100][slack.exe] Start Address of Thread 7ff7e0f255c0 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [13632][10516][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13632][7504][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13632][13520][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13632][13516][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13632][13512][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13632][13480][slack.exe] Start Address of Thread 7ff7e0f255c0 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [13632][13560][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13632][12300][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13632][9368][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13632][14064][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13632][14076][slack.exe] Start Address of Thread 7ffb2e39bd50 in C:\Windows\System32\MsSpellCheckingFacility.dll->DllUnregisterServer
[i] [13632][1656][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13632][15772][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13632][16836][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13632][13728][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13632][4572][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [14208][14212][slack.exe] Start Address of Thread 7ff7e0f16540 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [14208][14296][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [14208][14300][slack.exe] Start Address of Thread 7ff7e00c8580 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->node::FatalException
[i] [14208][14304][slack.exe] Start Address of Thread 7ff7e00c8580 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->node::FatalException
[i] [14208][14308][slack.exe] Start Address of Thread 7ff7e00c8580 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->node::FatalException
[i] [14208][14312][slack.exe] Start Address of Thread 7ff7dfc85ed0 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_fs_poll_getpath
[i] [14208][14316][slack.exe] Start Address of Thread 7ff7dfc85ed0 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_fs_poll_getpath
[i] [14208][5988][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13536][13548][slack.exe] Start Address of Thread 7ff7e0f16540 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [13536][13816][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13536][13872][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13536][13908][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13536][13420][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13536][13624][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13536][13644][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13536][10844][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13536][12636][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13536][18256][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13536][20944][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13536][11316][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13536][10388][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13648][13652][slack.exe] Start Address of Thread 7ff7e0f16540 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [13648][13764][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13648][13768][slack.exe] Start Address of Thread 7ff7df94bb30 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->GetHandleVerifier
[i] [13648][9544][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13648][11396][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13648][13796][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13648][11584][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13648][15440][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13648][18352][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13648][6124][slack.exe] Start Address of Thread 7ffb6fbd1010 in C:\WINDOWS\system32\mswsock.dll->UnknownFunction
[i] [13648][20472][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13648][10228][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13648][4784][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13648][19388][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13800][13824][Cortana.exe] Start Address of Thread 7ff70c138000 in C:\Program Files\WindowsApps\Microsoft.549981C3F5F10_3.2110.13603.0_x64__8wekyb3d8bbwe\Cortana.exe->UnknownFunction
[i] [13800][4084][Cortana.exe] Start Address of Thread 7ffb2e49c130 in C:\Program Files\WindowsApps\Microsoft.NET.Native.Runtime.2.2_2.2.28604.0_x64__8wekyb3d8bbwe\mrt100_app.dll->RhpSendCustomEventToDebugger
[i] [13800][11036][Cortana.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [13800][8908][Cortana.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [13800][11976][Cortana.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [13800][10440][Cortana.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13800][8172][Cortana.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [13800][9664][Cortana.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [13800][13108][Cortana.exe] Start Address of Thread 7ffb5f13f150 in C:\Windows\System32\MrmCoreR.dll->ShouldMergeInproc
[i] [13800][2324][Cortana.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [13800][14500][Cortana.exe] Start Address of Thread 7ffb572d3440 in C:\Windows\System32\Windows.Media.Devices.dll->DllGetClassObject
[i] [13800][14560][Cortana.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13800][14600][Cortana.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13800][14804][Cortana.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13800][10508][Cortana.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13800][15648][Cortana.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [13800][15688][Cortana.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13928][13932][slack.exe] Start Address of Thread 7ff7e0f16540 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [13928][8252][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13928][8276][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13928][8432][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13928][6288][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13928][2144][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13928][10476][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13928][13348][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13928][8444][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13928][10864][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13928][9672][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13928][10204][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13928][21860][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13928][17336][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13928][13308][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13928][18484][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [13928][6836][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][14156][OUTLOOK.EXE] Start Address of Thread 7ff6b692c1b0 in C:\Program Files\Microsoft Office\Office16\OUTLOOK.EXE->UnknownFunction
[i] [11652][15172][OUTLOOK.EXE] Start Address of Thread 7ffb473e3188 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal899
[i] [11652][15188][OUTLOOK.EXE] Start Address of Thread 7ffb356dd740 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso40uiwin32client.dll->Ordinal957
[i] [11652][14068][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][11052][OUTLOOK.EXE] Start Address of Thread 7ffb356ede34 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso40uiwin32client.dll->Ordinal452
[i] [11652][8564][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][15412][OUTLOOK.EXE] Start Address of Thread 711fe5f8 in C:\WINDOWS\SYSTEM32\PGPsdk.dll->PGPGetIndexedSymmetricCipherInfo
[i] [11652][15928][OUTLOOK.EXE] Start Address of Thread 7ffb445e9dc0 in C:\Program Files\PGP Corporation\PGP Desktop\PGPMSMDB.DLL->HrTrustedPSTOverrideHandlerCallback
[i] [11652][15932][OUTLOOK.EXE] Start Address of Thread 7ffb445ed490 in C:\Program Files\PGP Corporation\PGP Desktop\PGPMSMDB.DLL->IsTransportLoaded
[i] [11652][15944][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][16184][OUTLOOK.EXE] Start Address of Thread 7ffb03909dc0 in C:\Program Files\PGP Corporation\PGP Desktop\PGPMSPST.DLL->HrTrustedPSTOverrideHandlerCallback
[i] [11652][16188][OUTLOOK.EXE] Start Address of Thread 7ffb0390d490 in C:\Program Files\PGP Corporation\PGP Desktop\PGPMSPST.DLL->IsTransportLoaded
[i] [11652][16192][OUTLOOK.EXE] Start Address of Thread 7ffb042709e4 in C:\Program Files\Microsoft Office\Office16\MSPST32.DLL->MSProviderInit
[i] [11652][16220][OUTLOOK.EXE] Start Address of Thread 7ffb042709e4 in C:\Program Files\Microsoft Office\Office16\MSPST32.DLL->MSProviderInit
[i] [11652][16224][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][8476][OUTLOOK.EXE] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [11652][15184][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][11300][OUTLOOK.EXE] Start Address of Thread 7ff6b6a6ed44 in C:\Program Files\Microsoft Office\Office16\OUTLOOK.EXE->OutlookSyncEventOccurredEx
[i] [11652][14276][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][16288][OUTLOOK.EXE] Start Address of Thread 7ffb055a3308 in C:\Program Files\Microsoft Office\Office16\ADDINS\BCSAddin.dll->DllGetClassObject
[i] [11652][1840][OUTLOOK.EXE] Start Address of Thread 7ffb50d67c40 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->GC_Initialize
[i] [11652][15704][OUTLOOK.EXE] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [11652][13460][OUTLOOK.EXE] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [11652][9752][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][14412][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][11060][OUTLOOK.EXE] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [11652][13456][OUTLOOK.EXE] Start Address of Thread 7ffb10761c94 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso99Lwin32client.dll->Ordinal2177
[i] [11652][13992][OUTLOOK.EXE] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [11652][10348][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][7360][OUTLOOK.EXE] Start Address of Thread 7ffb06174924 in C:\Program Files\Microsoft Office\Office16\wwlib.dll->PTLS7::FsValidateReuse
[i] [11652][13896][OUTLOOK.EXE] Start Address of Thread 7ffb519531b0 in C:\WINDOWS\SYSTEM32\WINMM.dll->timeGetTime
[i] [11652][15980][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][17772][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][1340][OUTLOOK.EXE] Start Address of Thread 7ffb06174924 in C:\Program Files\Microsoft Office\Office16\wwlib.dll->PTLS7::FsValidateReuse
[i] [11652][6268][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][15708][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][21140][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][21288][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][21344][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][12924][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][18884][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][21780][OUTLOOK.EXE] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [11652][19556][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][18264][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][7540][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][7892][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][22624][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][22760][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][22772][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][22776][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][22780][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][22788][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][22796][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][22800][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][22804][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][22808][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][22836][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][22844][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][22868][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][22912][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][22948][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][22976][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][22988][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][22992][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][22996][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][23016][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][23020][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][23024][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][23032][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][23068][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][23072][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][23076][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][23080][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][23084][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][23088][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][23120][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][23332][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][23380][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][18396][OUTLOOK.EXE] Start Address of Thread 7ffb41861c90 in C:\WINDOWS\SYSTEM32\msiltcfg.dll->RestartMsi
[i] [11652][19264][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][12996][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][17512][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][20624][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][12156][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][18896][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][14220][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][11676][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][1740][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][22500][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][8408][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][20000][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][17604][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][3460][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][18688][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][17956][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][19608][OUTLOOK.EXE] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [11652][13020][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][21816][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][4428][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][17924][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][10588][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][17440][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][812][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][2072][OUTLOOK.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11652][17784][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][20176][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][9600][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][19768][OUTLOOK.EXE] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [11652][19948][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [11652][10488][OUTLOOK.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [7952][4272][POWERPNT.EXE] Start Address of Thread 7ff7780514c4 in C:\Program Files\Microsoft Office\Office16\POWERPNT.EXE->UnknownFunction
[i] [7952][11412][POWERPNT.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [7952][10528][POWERPNT.EXE] Start Address of Thread 7ffb473e3188 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal899
[i] [7952][9152][POWERPNT.EXE] Start Address of Thread 7ffb356dd740 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso40uiwin32client.dll->Ordinal957
[i] [7952][14136][POWERPNT.EXE] Start Address of Thread 7ffb356ede34 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso40uiwin32client.dll->Ordinal452
[i] [7952][15336][POWERPNT.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [7952][11328][POWERPNT.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [7952][10960][POWERPNT.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [7952][11192][POWERPNT.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7952][14940][POWERPNT.EXE] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [7952][14488][POWERPNT.EXE] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [7952][17064][POWERPNT.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7952][17204][POWERPNT.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7952][7860][POWERPNT.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4316][2292][PGPcbt64.exe] Start Address of Thread 7ff723fd13ac in C:\Program Files (x86)\PGP Corporation\PGP Desktop\PGPcbt64.exe->UnknownFunction
[i] [4316][13720][PGPcbt64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9916][12496][RuntimeBroker.exe] Start Address of Thread 7ff691526740 in C:\Windows\System32\RuntimeBroker.exe->UnknownFunction
[i] [9916][8076][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9916][8196][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9916][8372][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14604][14608][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [14604][14636][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [14604][14856][svchost.exe] Start Address of Thread 7ffb4042bfd0 in c:\windows\system32\agentactivationruntimewindows.dll->GetAgentActivationRuntimePalComponentFactory
[i] [14604][14860][svchost.exe] Start Address of Thread 7ffb4042bfd0 in c:\windows\system32\agentactivationruntimewindows.dll->GetAgentActivationRuntimePalComponentFactory
[i] [14604][15044][svchost.exe] Start Address of Thread 7ffb4044c840 in c:\windows\system32\agentactivationruntimewindows.dll->GetAgentActivationRuntimePalComponentFactory
[i] [14604][15048][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14604][15052][svchost.exe] Start Address of Thread 7ffb40466f40 in c:\windows\system32\agentactivationruntimewindows.dll->GetAgentActivationRuntimePalComponentFactory
[i] [14604][15084][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14604][15088][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14604][15092][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14604][15752][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14604][15756][svchost.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14604][21436][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14604][19604][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14592][14552][Teams.exe] Start Address of Thread 7ff699475a70 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [14592][8984][Teams.exe] Start Address of Thread 7ff6967933a0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->GetHandleVerifier
[i] [14592][10456][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [14592][9076][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [14592][9728][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [14592][14576][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14592][13756][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [14592][14740][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [14592][14756][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [14592][14760][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [14592][14764][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [14592][14768][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [14592][14780][Teams.exe] Start Address of Thread 7ff699482cb0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [14592][15164][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [14592][11756][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][14544][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][11148][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][14476][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][14972][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][14936][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14592][14980][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][15140][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][15344][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][15324][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][11068][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][15592][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][15596][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][15736][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][15740][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][15744][Teams.exe] Start Address of Thread 7ffb40e44dc0 in \\?\C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\resources\app.asar.unpacked\node_modules\slimcore\bin\RtmPal.dll->UnknownFunction
[i] [14592][15748][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][15812][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][15816][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][15820][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][15824][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][15828][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][15832][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][15836][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][16272][Teams.exe] Start Address of Thread 7ff699482cb0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [14592][16276][Teams.exe] Start Address of Thread 7ff699482cb0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [14592][16280][Teams.exe] Start Address of Thread 7ff699482cb0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [14592][16284][Teams.exe] Start Address of Thread 7ff699482cb0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [14592][20280][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][18440][Teams.exe] Start Address of Thread 7ffb69945030 in C:\WINDOWS\System32\perfos.dll->OpenOSObject
[i] [14592][3984][Teams.exe] Start Address of Thread 7ffb699313a0 in C:\WINDOWS\System32\perfdisk.dll->UnknownFunction
[i] [14592][10868][Teams.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [14592][8048][Teams.exe] Start Address of Thread 7ffb097ef9e0 in C:\WINDOWS\SYSTEM32\d3d9.dll->Direct3DShaderValidatorCreate9
[i] [14592][8272][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][20284][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][18640][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][21996][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][16652][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][15028][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14592][13212][Teams.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [14592][10644][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14592][21620][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14592][23444][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [11152][15304][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [11152][9200][svchost.exe] Start Address of Thread 7ffb6c88eac0 in C:\WINDOWS\SYSTEM32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [11152][20428][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11152][2596][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11152][15884][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11152][19004][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11732][C:\Windows\System32\SgrmBroker.exe] not analysed 5
[i] [8988][C:\Windows\System32\svchost.exe] not analysed 5
[i] [9364][8500][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [9364][10408][svchost.exe] Start Address of Thread 7ffb52798de0 in c:\windows\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [9364][4484][svchost.exe] Start Address of Thread 7ffb52798de0 in c:\windows\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [9364][11392][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9364][9376][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9364][21200][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [9364][21980][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9364][20876][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14844][11072][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\system32\svchost.exe->UnknownFunction
[i] [14844][16252][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [14844][15448][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6432][3876][ApplicationFrameHost.exe] Start Address of Thread 7ff7e3be2a30 in C:\WINDOWS\system32\ApplicationFrameHost.exe->UnknownFunction
[i] [6432][12504][ApplicationFrameHost.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [6432][12976][ApplicationFrameHost.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [6432][21312][ApplicationFrameHost.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [6432][14820][ApplicationFrameHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16244][2124][Calculator.exe] Start Address of Thread 7ff7849b78dc in C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_10.2103.8.0_x64__8wekyb3d8bbwe\Calculator.exe->VSDesignerDllMain
[i] [16244][10000][Calculator.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16244][12672][Calculator.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [16244][15416][Calculator.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16244][10768][Calculator.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [16244][15004][Calculator.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [16244][13904][Calculator.exe] Start Address of Thread 7ffb5f13f150 in C:\Windows\System32\MrmCoreR.dll->ShouldMergeInproc
[i] [16244][12704][Calculator.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [16244][6444][Calculator.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16244][15160][Calculator.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [16244][3448][Calculator.exe] Start Address of Thread 7ffb68714070 in C:\Program Files\WindowsApps\Microsoft.VCLibs.140.00_14.0.30704.0_x64__8wekyb3d8bbwe\CONCRT140_APP.dll->Concurrency::set_task_execution_resources
[i] [16244][9852][Calculator.exe] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [16244][13936][Calculator.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16244][8240][Calculator.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16244][7392][Calculator.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16244][2140][Calculator.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16244][4144][Calculator.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16244][5332][Calculator.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [16244][15444][Calculator.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16244][5836][Calculator.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16244][8680][Calculator.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12500][1820][RuntimeBroker.exe] Start Address of Thread 7ff691526740 in C:\Windows\System32\RuntimeBroker.exe->UnknownFunction
[i] [12500][13044][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12600][13040][SystemSettings.exe] Start Address of Thread 7ff71ffa40c0 in C:\Windows\ImmersiveControlPanel\SystemSettings.exe->UnknownFunction
[i] [12600][14884][SystemSettings.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12600][10260][SystemSettings.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [12600][11996][SystemSettings.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [12600][12940][SystemSettings.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [12600][12048][SystemSettings.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [12600][3848][SystemSettings.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12600][15012][SystemSettings.exe] Start Address of Thread 7ffb6efa0b10 in C:\WINDOWS\SYSTEM32\sppc.dll->SLpVLActivateProduct
[i] [12600][3616][SystemSettings.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [12600][14800][SystemSettings.exe] Start Address of Thread 7ffb5ed76800 in C:\WINDOWS\SYSTEM32\InputHost.dll->DllGetActivationFactory
[i] [12600][10212][SystemSettings.exe] Start Address of Thread 7ffb6c88eac0 in C:\WINDOWS\SYSTEM32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [12600][7256][SystemSettings.exe] Start Address of Thread 7ffb47adbd60 in C:\WINDOWS\SYSTEM32\TetheringStation.dll->TetheringStationFreeMemory
[i] [12600][10184][SystemSettings.exe] Start Address of Thread 7ffb6c88eac0 in C:\WINDOWS\SYSTEM32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [12600][11816][SystemSettings.exe] Start Address of Thread 7ffb6c88eac0 in C:\WINDOWS\SYSTEM32\wlanapi.dll->WlanQueryVirtualInterfaceType
[i] [12600][4228][SystemSettings.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12600][13828][SystemSettings.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [12600][12884][SystemSettings.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12600][9104][SystemSettings.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12600][13492][SystemSettings.exe] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [12600][13076][SystemSettings.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [12600][14660][SystemSettings.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [12600][9804][SystemSettings.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16356][12380][UserOOBEBroker.exe] Start Address of Thread 7ff68b477390 in C:\Windows\System32\oobe\UserOOBEBroker.exe->UnknownFunction
[i] [16356][14288][UserOOBEBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13924][8716][RuntimeBroker.exe] Start Address of Thread 7ff691526740 in C:\Windows\System32\RuntimeBroker.exe->UnknownFunction
[i] [13924][9172][RuntimeBroker.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [13924][16752][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13924][12284][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13924][12552][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13924][8324][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13924][2580][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13924][10552][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13924][9112][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13924][19472][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13924][18676][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13924][22300][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][8292][SearchIndexer.exe] Start Address of Thread 7ff604caa630 in C:\WINDOWS\system32\SearchIndexer.exe->UnknownFunction
[i] [956][14632][SearchIndexer.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [956][8848][SearchIndexer.exe] Start Address of Thread 7ffb52798de0 in c:\windows\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [956][13808][SearchIndexer.exe] Start Address of Thread 7ffb52798de0 in c:\windows\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [956][2592][SearchIndexer.exe] Start Address of Thread 7ffb52798de0 in c:\windows\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [956][16360][SearchIndexer.exe] Start Address of Thread 7ffb47f5f740 in C:\WINDOWS\system32\tquery.dll->DllCanUnloadNow
[i] [956][15568][SearchIndexer.exe] Start Address of Thread 7ffb4af253c0 in C:\Program Files\Common Files\Microsoft Shared\Ink\IpsPlugin.dll->DllGetClassObject
[i] [956][4284][SearchIndexer.exe] Start Address of Thread 7ffb4827ac70 in C:\WINDOWS\system32\MSSRCH.DLL->CSearchServiceObj::CSearchServiceObj
[i] [956][8508][SearchIndexer.exe] Start Address of Thread 7ffb4827a120 in C:\WINDOWS\system32\MSSRCH.DLL->CSearchServiceObj::CSearchServiceObj
[i] [956][11428][SearchIndexer.exe] Start Address of Thread 7ffb48271cf0 in C:\WINDOWS\system32\MSSRCH.DLL->CSearchServiceObj::Initialize
[i] [956][15288][SearchIndexer.exe] Start Address of Thread 7ffb48260380 in C:\WINDOWS\system32\MSSRCH.DLL->CSearchServiceObj::~CSearchServiceObj
[i] [956][10668][SearchIndexer.exe] Start Address of Thread 7ffb47f5f740 in C:\WINDOWS\system32\tquery.dll->DllCanUnloadNow
[i] [956][4068][SearchIndexer.exe] Start Address of Thread 7ffb47f5f740 in C:\WINDOWS\system32\tquery.dll->DllCanUnloadNow
[i] [956][16092][SearchIndexer.exe] Start Address of Thread 7ffb47f5f740 in C:\WINDOWS\system32\tquery.dll->DllCanUnloadNow
[i] [956][11592][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][5248][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][17384][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][16888][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][22916][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][1000][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][4840][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][19112][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][5184][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][22748][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][15424][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][4248][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][23220][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][8340][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][10616][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][11752][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][8772][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][11100][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][20356][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][21016][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][15996][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][1716][SearchIndexer.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [956][8532][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][2508][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][23236][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][20340][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][11496][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][18944][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][17736][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][1136][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][13860][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][20468][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][7824][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][16004][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][5344][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][18444][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][22872][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][23284][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][22260][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][20616][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][18188][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][18424][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][3368][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][720][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][10576][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][14984][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][20544][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][3576][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][17140][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [956][22256][SearchIndexer.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [244][15652][msedgewebview2.exe] Start Address of Thread 7ff7cc7c1690 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedgewebview2.exe->INetworkConnectionFactory::operator=
[i] [244][10420][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][10196][msedgewebview2.exe] Start Address of Thread 7ff7cc752d10 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedgewebview2.exe->INetworkConnectionFactory::operator=
[i] [244][15600][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [244][9160][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][13812][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][4212][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][15696][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][16316][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][8128][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][10720][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][10692][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][10928][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][13868][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][12792][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][10168][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][14228][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][9596][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][8524][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][7320][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][12780][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][16296][msedgewebview2.exe] Start Address of Thread 7ffb4a752270 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\oneds.dll->Microsoft::Applications::Events::EventProperty::EventProperty
[i] [244][9228][msedgewebview2.exe] Start Address of Thread 7ffb4a752270 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\oneds.dll->Microsoft::Applications::Events::EventProperty::EventProperty
[i] [244][18284][msedgewebview2.exe] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [244][18428][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [244][9304][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][21896][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [244][16860][msedgewebview2.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [244][18252][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [244][16260][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [244][2688][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [244][12304][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [244][19000][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [244][23392][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [244][21872][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][13368][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [244][9456][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6624][13004][msedgewebview2.exe] Start Address of Thread 7ff7cc7c1690 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedgewebview2.exe->INetworkConnectionFactory::operator=
[i] [6624][12360][msedgewebview2.exe] Start Address of Thread 7ff7cc7fdba0 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedgewebview2.exe->INetworkConnectionFactory::operator=
[i] [6624][10944][msedgewebview2.exe] Start Address of Thread 7ff7cc91a780 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedgewebview2.exe->IsSandboxedProcess
[i] [6624][11872][msedgewebview2.exe] Start Address of Thread 7ff7cc91a780 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedgewebview2.exe->IsSandboxedProcess
[i] [6624][16128][msedgewebview2.exe] Start Address of Thread 7ff7cc91a780 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedgewebview2.exe->IsSandboxedProcess
[i] [6624][12412][msedgewebview2.exe] Start Address of Thread 7ff7cc757a30 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedgewebview2.exe->INetworkConnectionFactory::operator=
[i] [6624][7048][msedgewebview2.exe] Start Address of Thread 7ff7cc757a30 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedgewebview2.exe->INetworkConnectionFactory::operator=
[i] [6624][11188][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11936][3356][msedgewebview2.exe] Start Address of Thread 7ff7cc7c1690 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedgewebview2.exe->INetworkConnectionFactory::operator=
[i] [11936][14112][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [11936][12456][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [11936][13408][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [11936][15272][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [11936][11716][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [11936][1492][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [11936][12276][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11936][12548][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [11936][8148][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [11936][4380][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [11936][9156][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [11936][8180][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [11936][15940][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [11936][17980][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11936][14924][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8304][11004][msedgewebview2.exe] Start Address of Thread 7ff7cc7c1690 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedgewebview2.exe->INetworkConnectionFactory::operator=
[i] [8304][10800][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8304][14916][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8304][9024][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8304][12972][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8304][5832][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8304][7124][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8304][18376][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8304][20884][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8304][12712][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7172][11564][msedgewebview2.exe] Start Address of Thread 7ff7cc7c1690 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedgewebview2.exe->INetworkConnectionFactory::operator=
[i] [7172][12224][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [7172][16152][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [7172][12708][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [7172][12052][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [7172][1472][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [7172][17260][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [7172][16308][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8836][8328][msedgewebview2.exe] Start Address of Thread 7ff7cc7c1690 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedgewebview2.exe->INetworkConnectionFactory::operator=
[i] [8836][12104][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8836][15584][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8836][13900][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8836][716][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8836][3308][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8836][12268][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8836][15660][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8836][724][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8836][8300][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8836][13580][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8836][12320][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8836][5856][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8836][15404][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [8836][21232][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [15904][4480][msedgewebview2.exe] Start Address of Thread 7ff7cc7c1690 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedgewebview2.exe->INetworkConnectionFactory::operator=
[i] [15904][15332][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15904][13676][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15904][10320][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15904][8568][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15904][4520][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15904][16352][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [15904][7712][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15904][15348][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15904][15624][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15904][10780][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15904][14472][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15904][5204][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15904][8296][msedgewebview2.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\EdgeWebView\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15904][22712][msedgewebview2.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2716][7676][Video.UI.exe] Start Address of Thread 7ff7b97235f0 in C:\Program Files\WindowsApps\Microsoft.ZuneVideo_10.21111.10511.0_x64__8wekyb3d8bbwe\Video.UI.exe->UnknownFunction
[i] [2716][7780][Video.UI.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [2716][6580][Video.UI.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\shcore.dll->Ordinal172
[i] [2716][16216][Video.UI.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [2716][13684][Video.UI.exe] Start Address of Thread 7ffb68714070 in C:\Program Files\WindowsApps\Microsoft.VCLibs.140.00_14.0.30704.0_x64__8wekyb3d8bbwe\CONCRT140_APP.dll->Concurrency::set_task_execution_resources
[i] [2716][13028][Video.UI.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [2716][12748][Video.UI.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\shcore.dll->SHStrDupW
[i] [2716][15112][Video.UI.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [2716][11780][Video.UI.exe] Start Address of Thread 7ffb52798de0 in c:\windows\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [2716][7188][Video.UI.exe] Start Address of Thread 7ffb52798de0 in c:\windows\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [2716][7700][Video.UI.exe] Start Address of Thread 7ffb5f13f150 in C:\Windows\System32\MrmCoreR.dll->ShouldMergeInproc
[i] [2716][9060][Video.UI.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2716][14396][Video.UI.exe] Start Address of Thread 7ffb706abeb0 in C:\WINDOWS\System32\CRYPT32.dll->CertFreeCTLContext
[i] [2716][7592][Video.UI.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [2716][22420][Video.UI.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2716][17244][Video.UI.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [2716][17264][Video.UI.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2716][16032][Video.UI.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4988][9556][RuntimeBroker.exe] Start Address of Thread 7ff691526740 in C:\Windows\System32\RuntimeBroker.exe->UnknownFunction
[i] [4988][2600][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14484][10708][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 2486e40fe96 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\ServiceHub\controller\Microsoft.ServiceHub.Controller.exe->UnknownFunction
[i] [14484][1600][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb50d67c40 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->GC_Initialize
[i] [14484][3988][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [14484][6544][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb50bd9d10 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [14484][4712][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb52a08e40 in C:\WINDOWS\SYSTEM32\rasman.dll->RasSignalMonitorThreadExit
[i] [14484][12724][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb50d21ac0 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->GetMetaDataPublicInterfaceFromInternal
[i] [14484][15804][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14484][11500][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14484][7936][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14484][11636][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [14484][13972][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [9508][13792][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [9508][11356][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [9508][10148][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9508][15848][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5668][15520][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [5668][15952][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [5668][1292][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5188][12828][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [5188][4628][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [5188][23004][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [15780][6492][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [15780][10296][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [15780][20908][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9472][12812][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [9472][2560][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [9472][22700][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4012][6604][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [4012][2364][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [4012][15056][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8200][11528][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [8200][12376][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [8200][9308][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8200][8080][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7716][11884][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [7716][2212][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [7716][18880][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12684][9220][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [12684][8876][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [12684][16028][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5564][11064][git-bash.exe] Start Address of Thread c11520 in C:\Program Files\Git\git-bash.exe->UnknownFunction
[i] [5564][3380][git-bash.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1672][12216][mintty.exe] Start Address of Thread 100401000 in C:\Program Files\Git\usr\bin\mintty.exe->UnknownFunction
[i] [1672][14260][mintty.exe] Start Address of Thread 180046eb0 in C:\Program Files\Git\usr\bin\msys-2.0.dll->setprogname
[i] [1672][8136][mintty.exe] Start Address of Thread 180046eb0 in C:\Program Files\Git\usr\bin\msys-2.0.dll->setprogname
[i] [1672][7372][mintty.exe] Start Address of Thread 180046eb0 in C:\Program Files\Git\usr\bin\msys-2.0.dll->setprogname
[i] [1672][8916][mintty.exe] Start Address of Thread 180046eb0 in C:\Program Files\Git\usr\bin\msys-2.0.dll->setprogname
[i] [1672][8496][mintty.exe] Start Address of Thread 180046eb0 in C:\Program Files\Git\usr\bin\msys-2.0.dll->setprogname
[i] [1672][11000][mintty.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1672][13500][mintty.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5868][11704][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [5868][7832][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [5868][8900][conhost.exe] Start Address of Thread 7ff62eef4a90 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [5868][19620][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10380][6164][bash.exe] Start Address of Thread 100401000 in C:\Program Files\Git\usr\bin\mintty.exe->UnknownFunction
[i] [10380][8488][bash.exe] Start Address of Thread 180046eb0 in C:\Program Files\Git\usr\bin\msys-2.0.dll->setprogname
[i] [10380][12368][bash.exe] Start Address of Thread 180046eb0 in C:\Program Files\Git\usr\bin\msys-2.0.dll->setprogname
[i] [10380][22984][bash.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8792][5292][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [8792][6964][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [8792][16412][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2804][11684][ServiceHub.TestWindowStoreHost.exe] Start Address of Thread 1e5a6e53072 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\ServiceHub\Hosts\ServiceHub.Host.CLR.AnyCPU\ServiceHub.TestWindowStoreHost.exe->UnknownFunction
[i] [2804][11444][ServiceHub.TestWindowStoreHost.exe] Start Address of Thread 7ffb50d67c40 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->GC_Initialize
[i] [2804][11648][ServiceHub.TestWindowStoreHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [2804][776][ServiceHub.TestWindowStoreHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [2804][12808][ServiceHub.TestWindowStoreHost.exe] Start Address of Thread 7ffb50bd9d10 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [2804][4128][ServiceHub.TestWindowStoreHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2804][22176][ServiceHub.TestWindowStoreHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [2804][13704][ServiceHub.TestWindowStoreHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [13612][3196][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [13612][3972][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [13612][12016][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17152][1196][cmd.exe] Start Address of Thread 7ff79a6e8f50 in C:\WINDOWS\system32\cmd.exe->UnknownFunction
[i] [17152][17420][cmd.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17152][11236][cmd.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17300][17344][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [17300][17356][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [17300][5744][conhost.exe] Start Address of Thread 7ff62eef4a90 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [17300][5684][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17300][17400][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17096][16552][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 1631d120000 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\ServiceHub\Hosts\ServiceHub.Host.CLR.x64\ServiceHub.DataWarehouseHost.exe->UnknownFunction
[i] [17096][736][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50d67c40 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->GC_Initialize
[i] [17096][17128][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [17096][8364][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [17096][2572][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bd9d10 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [17096][15896][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17096][5208][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17096][7868][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17096][17024][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17096][17268][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17096][7380][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17096][8284][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17096][17176][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17096][16996][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [17096][9208][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb52a08e40 in C:\WINDOWS\SYSTEM32\rasman.dll->RasSignalMonitorThreadExit
[i] [17096][17368][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb55de9ae0 in C:\WINDOWS\WinSxS\amd64_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.19041.1466_none_91a4907ccc87e3b8\gdiplus.dll->GdiplusStartup
[i] [17096][2764][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [17096][13012][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [17096][6032][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [17096][7056][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [17096][15732][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [17096][14828][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [17096][19536][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17096][22064][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17096][14032][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17096][21960][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [17096][14272][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [17096][6180][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [17096][18644][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [17316][16792][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [17316][5560][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [17316][20684][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [15252][16112][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\System32\svchost.exe->UnknownFunction
[i] [15252][12900][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [15252][23112][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [15252][4864][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17068][17544][taskhostw.exe] Start Address of Thread 7ff6e0905bf0 in C:\WINDOWS\system32\taskhostw.exe->UnknownFunction
[i] [17068][18084][taskhostw.exe] Start Address of Thread 7ff6e09012d0 in C:\WINDOWS\system32\taskhostw.exe->UnknownFunction
[i] [17068][4756][taskhostw.exe] Start Address of Thread 7ffb578f20f0 in c:\windows\system32\wdi.dll->WdipLaunchLocalHost
[i] [17068][11744][taskhostw.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13008][17288][Microsoft.Photos.exe] Start Address of Thread 7ff66793b000 in C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2021.21090.10008.0_x64__8wekyb3d8bbwe\Microsoft.Photos.exe->UnknownFunction
[i] [13008][8000][Microsoft.Photos.exe] Start Address of Thread 7ffb2e49c130 in C:\Program Files\WindowsApps\Microsoft.NET.Native.Runtime.2.2_2.2.28604.0_x64__8wekyb3d8bbwe\mrt100_app.dll->RhpSendCustomEventToDebugger
[i] [13008][15892][Microsoft.Photos.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [13008][17308][Microsoft.Photos.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\SHCORE.dll->Ordinal172
[i] [13008][16820][Microsoft.Photos.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [13008][1048][Microsoft.Photos.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [13008][3728][Microsoft.Photos.exe] Start Address of Thread 7ffb5f13f150 in C:\Windows\System32\MrmCoreR.dll->ShouldMergeInproc
[i] [13008][10560][Microsoft.Photos.exe] Start Address of Thread 7ffb68714070 in C:\Program Files\WindowsApps\Microsoft.VCLibs.140.00_14.0.30704.0_x64__8wekyb3d8bbwe\CONCRT140_APP.dll->Concurrency::set_task_execution_resources
[i] [13008][11320][Microsoft.Photos.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\SHCORE.dll->SHStrDupW
[i] [13008][7196][Microsoft.Photos.exe] Start Address of Thread 7ffb72dc4fe0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleasePool
[i] [13008][10640][Microsoft.Photos.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [13008][7160][Microsoft.Photos.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [13008][14992][Microsoft.Photos.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13008][8012][Microsoft.Photos.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [13008][5280][Microsoft.Photos.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12084][5240][RuntimeBroker.exe] Start Address of Thread 7ff691526740 in C:\Windows\System32\RuntimeBroker.exe->UnknownFunction
[i] [12084][23264][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12084][4868][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18648][18668][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\System32\svchost.exe->UnknownFunction
[i] [18648][18720][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [18648][16320][svchost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [18648][18856][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18648][18848][svchost.exe] Start Address of Thread 7ffb52798de0 in c:\windows\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [18648][18908][svchost.exe] Start Address of Thread 7ffb52798de0 in c:\windows\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [18648][18904][svchost.exe] Start Address of Thread 7ffb52798de0 in c:\windows\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [18648][18684][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18648][17328][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18648][14644][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18648][1140][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18648][19660][svchost.exe] Start Address of Thread 7ffb683b1760 in C:\WINDOWS\system32\SSDPAPI.dll->RegisterServiceEx
[i] [18648][6672][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18648][23212][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18648][19724][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11372][9436][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\System32\svchost.exe->UnknownFunction
[i] [11372][17352][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [11372][5192][svchost.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [11372][17376][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11372][23520][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22440][22444][YourPhone.exe] Start Address of Thread 7ff612739000 in C:\Program Files\WindowsApps\Microsoft.YourPhone_1.21113.36.0_x64__8wekyb3d8bbwe\YourPhone.exe->UnknownFunction
[i] [22440][16884][YourPhone.exe] Start Address of Thread 7ffb2e49c130 in C:\Program Files\WindowsApps\Microsoft.NET.Native.Runtime.2.2_2.2.28604.0_x64__8wekyb3d8bbwe\mrt100_app.dll->RhpSendCustomEventToDebugger
[i] [22440][19808][YourPhone.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [22440][19368][YourPhone.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\SHCORE.dll->Ordinal172
[i] [22440][19284][YourPhone.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [22440][14836][YourPhone.exe] Start Address of Thread 7ffb5f13f150 in C:\Windows\System32\MrmCoreR.dll->ShouldMergeInproc
[i] [22440][18476][YourPhone.exe] Start Address of Thread 7ffb68714070 in C:\Program Files\WindowsApps\Microsoft.VCLibs.140.00_14.0.30704.0_x64__8wekyb3d8bbwe\CONCRT140_APP.dll->Concurrency::set_task_execution_resources
[i] [22440][16464][YourPhone.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\SHCORE.dll->SHStrDupW
[i] [22440][19224][YourPhone.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [22440][8448][YourPhone.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22440][18964][YourPhone.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [22440][17684][YourPhone.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [21888][21928][RuntimeBroker.exe] Start Address of Thread 7ff691526740 in C:\Windows\System32\RuntimeBroker.exe->UnknownFunction
[i] [21888][2652][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [21888][10596][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22436][19632][pwahelper.exe] Start Address of Thread 7ff76a641f50 in C:\Program Files (x86)\Microsoft\Edge\Application\pwahelper.exe->Ordinal0
[i] [22436][17508][pwahelper.exe] Start Address of Thread 7ffb2e9eee40 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\pwahelper.dll->edge_pwahelper::PwaHelperImpl::PinTileToStart
[i] [22436][11336][pwahelper.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22436][4044][pwahelper.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22436][15180][pwahelper.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [22024][19428][msedge.exe] Start Address of Thread 7ff6b20a1690 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [22024][22084][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][7740][msedge.exe] Start Address of Thread 7ff6b2032d10 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [22024][17824][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22024][8168][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][17084][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][3740][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][22368][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][21540][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][21592][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][2300][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][19728][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][19732][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][16540][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][18412][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][21796][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][20500][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][11508][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][13724][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][6460][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][20632][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][18740][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][20664][msedge.exe] Start Address of Thread 7ffb02a277b0 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\oneauth.dll->MATSEndWamAction
[i] [22024][280][msedge.exe] Start Address of Thread 7ffb4a752270 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\oneds.dll->Microsoft::Applications::Events::EventProperty::EventProperty
[i] [22024][20412][msedge.exe] Start Address of Thread 7ffb4a752270 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\oneds.dll->Microsoft::Applications::Events::EventProperty::EventProperty
[i] [22024][17364][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22024][16628][msedge.exe] Start Address of Thread 7ffb2e39bd50 in C:\Windows\System32\MsSpellCheckingFacility.dll->DllUnregisterServer
[i] [22024][1968][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22024][4204][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][6540][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22024][12172][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][15396][msedge.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [22024][5452][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22024][20716][msedge.exe] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [22024][5288][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22024][19328][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3076][19952][msedge.exe] Start Address of Thread 7ff6b20a1690 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [3076][12068][msedge.exe] Start Address of Thread 7ff6b20ddba0 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [3076][18936][msedge.exe] Start Address of Thread 7ff6b21fa780 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->IsSandboxedProcess
[i] [3076][12232][msedge.exe] Start Address of Thread 7ff6b21fa780 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->IsSandboxedProcess
[i] [3076][13432][msedge.exe] Start Address of Thread 7ff6b21fa780 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->IsSandboxedProcess
[i] [3076][21244][msedge.exe] Start Address of Thread 7ff6b2037a30 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [3076][11852][msedge.exe] Start Address of Thread 7ff6b2037a30 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [3076][12728][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13708][19984][msedge.exe] Start Address of Thread 7ff6b20a1690 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [13708][21572][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13708][21912][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13708][22200][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13708][2040][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13708][15912][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13708][1972][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13708][648][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13708][20724][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13708][22128][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13708][10580][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13708][20332][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13708][20904][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13708][7760][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13708][3892][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13708][19884][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13708][10648][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13708][23268][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [15152][19400][msedge.exe] Start Address of Thread 7ff6b20a1690 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [15152][19612][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15152][21120][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15152][10172][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15152][16624][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [15152][16420][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15152][21212][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15152][13436][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15152][23548][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [15152][10652][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15152][17052][msedge.exe] Start Address of Thread 7ffb6fbd1010 in C:\WINDOWS\system32\mswsock.dll->UnknownFunction
[i] [15152][22856][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15152][6468][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [15152][1588][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [21376][20568][msedge.exe] Start Address of Thread 7ff6b20a1690 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [21376][3480][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [21376][21188][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [21376][12356][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [21376][18920][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [21376][10612][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [21376][20648][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [21376][19812][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18888][17432][msedge.exe] Start Address of Thread 7ff6b20a1690 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [18888][4848][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][20424][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][19396][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][16132][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18888][2500][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][18160][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][20092][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][16072][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][19804][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][5884][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][4908][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][18312][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][10704][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][21976][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][19760][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][2604][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][8232][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][19584][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][6584][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18888][22900][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7608][21476][msedge.exe] Start Address of Thread 7ff6b20a1690 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [7608][19916][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [7608][5296][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [7608][19704][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [7608][19992][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [7608][20768][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [7608][17692][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [7608][2484][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18636][19796][msedge.exe] Start Address of Thread 7ff6b20a1690 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [18636][17256][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18636][20748][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18636][15760][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18636][8912][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18636][7980][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18636][7820][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18636][5300][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18636][17728][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [19832][9900][slack.exe] Start Address of Thread 7ff7e0f16540 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [19832][16612][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [19832][19752][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [19832][10628][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [19832][4348][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [19832][22160][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [19832][19120][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [19832][5100][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [19832][20192][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [16736][6576][RtkUWP.exe] Start Address of Thread 7ff646f7269c in C:\Program Files\WindowsApps\RealtekSemiconductorCorp.RealtekAudioControl_1.1.137.0_x64__dt26b99r8h8gj\RtkUWP.exe->VSDesignerDllMain
[i] [16736][10472][RtkUWP.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [16736][21028][RtkUWP.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\SHCORE.dll->Ordinal172
[i] [16736][17948][RtkUWP.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [16736][9012][RtkUWP.exe] Start Address of Thread 7ffb5f13f150 in C:\Windows\System32\MrmCoreR.dll->ShouldMergeInproc
[i] [16736][21488][RtkUWP.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16736][4088][RtkUWP.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [16736][17372][RtkUWP.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [16736][17720][RtkUWP.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16736][2960][RtkUWP.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16672][20888][RuntimeBroker.exe] Start Address of Thread 7ff691526740 in C:\Windows\System32\RuntimeBroker.exe->UnknownFunction
[i] [16672][1680][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18068][19252][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\System32\svchost.exe->UnknownFunction
[i] [18068][9816][svchost.exe] Start Address of Thread 7ffb52798de0 in c:\windows\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [18068][2340][svchost.exe] Start Address of Thread 7ffb52798de0 in c:\windows\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [18068][8100][svchost.exe] Start Address of Thread 7ffb52798de0 in c:\windows\system32\ESENT.dll->JetEnableMultiInstanceA
[i] [18068][20784][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2892][21900][Teams.exe] Start Address of Thread 7ff699475a70 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_random
[i] [2892][15544][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [2892][18276][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [2892][20640][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [2892][18192][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2892][21772][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [2892][4920][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [2892][18384][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [2892][11364][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [2892][15504][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [2892][17920][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [2892][9692][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [2892][16980][Teams.exe] Start Address of Thread 7ff6959b13d0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\Teams\current\Teams.exe->uv_cond_signal
[i] [2892][17764][Teams.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10836][12120][HxD.exe] Start Address of Thread 9199c0 in C:\Program Files\HxD\HxD.exe->UnknownFunction
[i] [10836][7140][HxD.exe] Start Address of Thread 40e8a0 in C:\Program Files\HxD\HxD.exe->UnknownFunction
[i] [10836][23128][HxD.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [12756][C:\Windows\System32\svchost.exe] not analysed 5
[i] [10448][8816][SnippingTool.exe] Start Address of Thread 7ff6af2136d0 in C:\WINDOWS\system32\SnippingTool.exe->UnknownFunction
[i] [10448][19716][SnippingTool.exe] Start Address of Thread 7ffb55de9ae0 in C:\WINDOWS\WinSxS\amd64_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.19041.1466_none_91a4907ccc87e3b8\gdiplus.dll->GdiplusStartup
[i] [10448][20128][SnippingTool.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [10448][7940][SnippingTool.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [10448][7240][SnippingTool.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [10448][13488][SnippingTool.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [10448][12688][SnippingTool.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [10448][20316][SnippingTool.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [10448][6664][SnippingTool.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [10448][4732][SnippingTool.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8212][17272][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\System32\svchost.exe->UnknownFunction
[i] [8212][18116][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8212][1368][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8212][20788][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8212][17276][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8212][16476][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17884][20408][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\System32\svchost.exe->UnknownFunction
[i] [17884][18016][svchost.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [17884][21852][svchost.exe] Start Address of Thread 7ffb6ac91450 in c:\windows\system32\lmhsvc.dll->ServiceMain
[i] [17884][17660][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16872][14248][WUDFHost.exe] Start Address of Thread 7ff745b60d40 in C:\Windows\System32\WUDFHost.exe->UnknownFunction
[i] [16872][20596][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16872][12396][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16872][11144][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16872][21144][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16872][19564][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18744][1976][WUDFHost.exe] Start Address of Thread 7ff745b60d40 in C:\Windows\System32\WUDFHost.exe->UnknownFunction
[i] [18744][22088][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18744][2236][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18744][17872][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18744][5672][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18744][21168][WUDFHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13744][14320][svchost.exe] Start Address of Thread 7ff606834e80 in C:\WINDOWS\System32\svchost.exe->UnknownFunction
[i] [13744][20292][svchost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22124][10028][slack.exe] Start Address of Thread 7ff7e0f16540 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->cppgc::internal::WriteBarrier::DijkstraMarkingBarrierRangeSlow
[i] [22124][13204][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [22124][20368][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [22124][16156][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [22124][16056][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [22124][8336][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22124][16404][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [22124][12644][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [22124][18112][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [22124][20452][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [22124][17880][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [22124][6176][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [22124][16864][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [22124][14332][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [22124][12132][slack.exe] Start Address of Thread 7ff7df2bc660 in C:\Users\Ollie Whitehouse\AppData\Local\slack\app-4.23.0\slack.exe->uv_os_getpid
[i] [22124][21744][slack.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20988][5912][ShellExperienceHost.exe] Start Address of Thread 7ff6d6c9ec00 in C:\WINDOWS\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe->UnknownFunction
[i] [20988][11208][ShellExperienceHost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [20988][11776][ShellExperienceHost.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\SHCORE.dll->Ordinal172
[i] [20988][21464][ShellExperienceHost.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [20988][19104][ShellExperienceHost.exe] Start Address of Thread 7ffb5f13f150 in C:\Windows\System32\MrmCoreR.dll->ShouldMergeInproc
[i] [20988][460][ShellExperienceHost.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\SHCORE.dll->Ordinal172
[i] [20988][7284][ShellExperienceHost.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [20988][17636][ShellExperienceHost.exe] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [20988][8164][ShellExperienceHost.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\SHCORE.dll->SHStrDupW
[i] [20988][22116][ShellExperienceHost.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\SHCORE.dll->Ordinal172
[i] [20988][11016][ShellExperienceHost.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [20988][21720][ShellExperienceHost.exe] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [20988][18340][ShellExperienceHost.exe] Start Address of Thread 7ffb6957f500 in C:\WINDOWS\SYSTEM32\AUDIOSES.DLL->DllGetActivationFactory
[i] [20988][22968][ShellExperienceHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20988][21644][ShellExperienceHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20988][7792][ShellExperienceHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20988][11748][ShellExperienceHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20988][18976][ShellExperienceHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20988][17656][ShellExperienceHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20988][17812][ShellExperienceHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20988][10872][ShellExperienceHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20988][23356][ShellExperienceHost.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\SHCORE.dll->SHStrDupW
[i] [20988][10620][ShellExperienceHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20988][22396][ShellExperienceHost.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [20988][972][ShellExperienceHost.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [20988][19864][ShellExperienceHost.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [20988][4328][ShellExperienceHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][23368][SearchApp.exe] Start Address of Thread 7ff7f40f4980 in C:\WINDOWS\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe->UnknownFunction
[i] [23364][20152][SearchApp.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [23364][23452][SearchApp.exe] Start Address of Thread 7ffb71bfc7a0 in C:\WINDOWS\System32\SHCORE.dll->Ordinal172
[i] [23364][22608][SearchApp.exe] Start Address of Thread 7ffb5dc6a4e0 in C:\Windows\System32\Windows.UI.Xaml.dll->DllCanUnloadNow
[i] [23364][23484][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][20676][SearchApp.exe] Start Address of Thread 7ffb5f13f150 in C:\Windows\System32\MrmCoreR.dll->ShouldMergeInproc
[i] [23364][23488][SearchApp.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\SHCORE.dll->SHStrDupW
[i] [23364][22620][SearchApp.exe] Start Address of Thread 7ffb57a74e60 in C:\WINDOWS\system32\directmanipulation.dll->UnknownFunction
[i] [23364][22612][SearchApp.exe] Start Address of Thread 7ffb2579dd40 in C:\WINDOWS\SYSTEM32\edgehtml.dll->InitializeLocalHtmlEngine
[i] [23364][22616][SearchApp.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [23364][22604][SearchApp.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [23364][11488][SearchApp.exe] Start Address of Thread 7ffb2577e9b0 in C:\WINDOWS\SYSTEM32\edgehtml.dll->Ordinal128
[i] [23364][22340][SearchApp.exe] Start Address of Thread 7ffb2587b2b0 in C:\WINDOWS\SYSTEM32\edgehtml.dll->InitializeLocalHtmlEngine
[i] [23364][16428][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][12576][SearchApp.exe] Start Address of Thread 7ffb2587b2b0 in C:\WINDOWS\SYSTEM32\edgehtml.dll->InitializeLocalHtmlEngine
[i] [23364][11132][SearchApp.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [23364][16500][SearchApp.exe] Start Address of Thread 7ffb2587b2b0 in C:\WINDOWS\SYSTEM32\edgehtml.dll->InitializeLocalHtmlEngine
[i] [23364][20232][SearchApp.exe] Start Address of Thread 7ffb2588bfb0 in C:\WINDOWS\SYSTEM32\edgehtml.dll->InitializeLocalHtmlEngine
[i] [23364][23040][SearchApp.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [23364][19896][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][12536][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][21112][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][4152][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][19484][SearchApp.exe] Start Address of Thread 7ffb706abeb0 in C:\WINDOWS\System32\CRYPT32.dll->CertFreeCTLContext
[i] [23364][17712][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][17628][SearchApp.exe] Start Address of Thread 7ffb256190b0 in C:\WINDOWS\SYSTEM32\edgehtml.dll->Ordinal128
[i] [23364][3888][SearchApp.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [23364][22000][SearchApp.exe] Start Address of Thread 7ffb25576d40 in C:\WINDOWS\SYSTEM32\edgehtml.dll->Streams_CreateByteChunk
[i] [23364][13640][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][16452][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][2448][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][9240][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][16324][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][8312][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][15916][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][22532][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][12796][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][11908][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][15720][SearchApp.exe] Start Address of Thread 7ffb2587b2b0 in C:\WINDOWS\SYSTEM32\edgehtml.dll->InitializeLocalHtmlEngine
[i] [23364][12732][SearchApp.exe] Start Address of Thread 7ffb2587b2b0 in C:\WINDOWS\SYSTEM32\edgehtml.dll->InitializeLocalHtmlEngine
[i] [23364][10192][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][20496][SearchApp.exe] Start Address of Thread 7ffb71be5960 in C:\WINDOWS\System32\SHCORE.dll->SHStrDupW
[i] [23364][11544][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][2680][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][22180][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][17652][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][9432][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][13760][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][18808][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][13996][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][17236][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][9712][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][23228][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][20460][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][16952][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][5232][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][18800][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23364][11644][SearchApp.exe] Start Address of Thread 7ffb254f9580 in C:\WINDOWS\SYSTEM32\edgehtml.dll->UnknownFunction
[i] [23364][23540][SearchApp.exe] Start Address of Thread 7ffb5daaf670 in C:\Windows\System32\Windows.UI.Xaml.dll->GetErrorContextIndex
[i] [23364][20236][SearchApp.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22552][23324][OneDrive.exe] Start Address of Thread 7ff6c7e81a30 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\OneDrive\OneDrive.exe->UnknownFunction
[i] [22552][23296][OneDrive.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [22552][2372][OneDrive.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [22552][23372][OneDrive.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [22552][22816][OneDrive.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [22552][23276][OneDrive.exe] Start Address of Thread 7ffb326b58a0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\OneDrive\21.245.1128.0002\SyncEngine.DLL->CreateDirectoryListing
[i] [22552][23232][OneDrive.exe] Start Address of Thread 7ffb326b58a0 in C:\Users\Ollie Whitehouse\AppData\Local\Microsoft\OneDrive\21.245.1128.0002\SyncEngine.DLL->CreateDirectoryListing
[i] [22552][23336][OneDrive.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [22552][18728][OneDrive.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [22552][7408][OneDrive.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [22552][20384][OneDrive.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [22552][10716][OneDrive.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [22552][20168][OneDrive.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [22552][22032][OneDrive.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [22552][15384][OneDrive.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22552][4580][OneDrive.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22552][19520][OneDrive.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [4636][23472][RuntimeBroker.exe] Start Address of Thread 7ff691526740 in C:\Windows\System32\RuntimeBroker.exe->UnknownFunction
[i] [4636][5276][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4636][544][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4636][16488][RuntimeBroker.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [4636][21172][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4636][19332][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4636][20076][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4636][21148][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4636][1144][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4636][19052][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4636][21844][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4636][21092][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4636][17008][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [4636][19648][RuntimeBroker.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [21576][4496][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [21576][10360][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][7524][chrome.exe] Start Address of Thread 7ff77414d070 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [21576][8612][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][12440][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][12436][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][23516][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [21576][18516][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][17968][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][20948][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][23316][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][20164][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][22928][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][22924][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][17536][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][5348][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][19340][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][11620][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][4200][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][8044][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][2584][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][20968][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [21576][13152][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [21576][8004][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][20528][chrome.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [21576][6388][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [21576][16440][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][9700][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][20764][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21576][20980][chrome.exe] Start Address of Thread 7ffb706abeb0 in C:\WINDOWS\System32\CRYPT32.dll->CertFreeCTLContext
[i] [8520][22880][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [8520][22264][chrome.exe] Start Address of Thread 7ff7740bea70 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->Ordinal0
[i] [8520][17340][chrome.exe] Start Address of Thread 7ff774159320 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [8520][944][chrome.exe] Start Address of Thread 7ff774159320 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [8520][16052][chrome.exe] Start Address of Thread 7ff774159320 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [8520][14868][chrome.exe] Start Address of Thread 7ff7740dbf10 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->Ordinal0
[i] [8520][3428][chrome.exe] Start Address of Thread 7ff7740dbf10 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->Ordinal0
[i] [8520][13084][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22584][22972][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [22584][3780][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22584][16304][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22584][5464][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22584][17776][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22584][22348][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22584][20160][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22584][21556][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22584][7876][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22584][22672][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22584][10016][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22584][13552][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22584][20268][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22584][21732][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [1560][22172][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [1560][4140][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [1560][20900][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [1560][16388][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [1560][17552][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1560][3532][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [1560][14728][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [1560][14796][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [1560][12580][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1560][16544][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [1560][9608][chrome.exe] Start Address of Thread 7ffb6fbd1010 in C:\WINDOWS\system32\mswsock.dll->UnknownFunction
[i] [1560][22956][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [1560][19320][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [1560][3508][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [2544][16912][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [2544][9680][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [2544][6596][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [2544][21512][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [2544][12352][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [2544][12588][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [2544][21320][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [2544][20448][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2544][19504][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21968][23144][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [21968][19212][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21968][21412][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21968][16516][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21968][21616][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21968][3664][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [21968][22248][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21968][22140][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21968][1700][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21968][2536][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21968][20148][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21968][18460][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21968][13700][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21968][16840][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [21968][1944][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9688][16728][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [9688][19028][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [9688][13944][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [9688][8776][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [9688][12752][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [9688][12028][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [9688][3944][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [9688][11012][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [9688][22520][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [9688][22212][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [9688][12928][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [9688][18972][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [9688][12136][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [9688][21184][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [9688][1348][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10772][19292][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [10772][20540][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [10772][10276][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [10772][21500][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [10772][17232][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [10772][10328][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [10772][6216][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [10772][21400][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [10772][20972][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [10772][4960][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [10772][18524][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [10772][23056][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [10772][10988][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [10772][8684][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [10772][17284][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22004][22828][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [22004][23428][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22004][18056][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22004][21984][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22004][16608][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22004][13100][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22004][1720][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22004][1568][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22004][7460][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22004][1032][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22004][12152][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22004][20728][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22004][18408][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22004][17028][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22004][3676][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7324][15988][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [7324][22012][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7324][15856][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7324][19876][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7324][23044][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7324][19792][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7324][11432][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7324][10304][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7324][2412][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7324][15936][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7324][9124][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7324][9212][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7324][14788][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7324][12932][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7324][7412][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7324][22148][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7324][19824][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7324][10344][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [17868][23164][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [17868][2440][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [17868][20264][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [17868][20812][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [17868][20288][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [17868][756][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [17868][14340][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17868][12256][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [17868][11964][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [22644][6844][msedge.exe] Start Address of Thread 7ff6b20a1690 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [22644][20392][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22644][23272][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22644][21656][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22644][21776][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22644][20940][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22644][13656][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22644][23528][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22644][21688][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22644][13596][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22644][20388][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22644][20524][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22644][15644][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22644][16180][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22644][18952][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22644][20124][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [22644][8628][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13916][15196][msedge.exe] Start Address of Thread 7ff6b20a1690 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [13916][20436][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13916][19652][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13916][19176][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13916][3612][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13916][20144][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13916][10744][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13916][19432][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13916][20932][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13916][13888][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13916][11104][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13916][15408][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13916][22684][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13916][11624][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13916][18716][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [13916][15428][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13916][17992][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6840][19216][msedge.exe] Start Address of Thread 7ff6b20a1690 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [6840][22008][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [6840][18492][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [6840][21824][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [6840][13016][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [6840][15472][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6840][9348][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [6840][19172][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [6840][11876][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [6840][23240][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [6840][9948][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [6840][9820][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [6840][11228][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [6840][14752][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [6840][964][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6840][20060][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18164][20916][msedge.exe] Start Address of Thread 7ff6b20a1690 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [18164][13576][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18164][22852][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18164][18236][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18164][8944][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18164][10936][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18164][23448][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18164][19160][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18164][17188][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18164][11708][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18164][21712][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18164][17800][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18164][1104][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18164][21268][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18164][21160][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [2456][12696][msedge.exe] Start Address of Thread 7ff6b20a1690 in C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe->INetworkConnectionFactory::operator=
[i] [2456][6276][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [2456][7580][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [2456][19656][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [2456][9396][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [2456][2740][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2456][14700][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [2456][23184][msedge.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [2456][13964][msedge.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16200][16416][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [16200][18040][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16200][15564][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16200][10152][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16200][19424][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16200][21052][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16200][14040][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16200][4004][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16200][21668][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16200][17860][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16200][7084][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16200][17792][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16200][12072][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16200][9232][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16200][2152][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20484][8636][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [20484][18028][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [20484][18572][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [20484][17616][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [20484][7500][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [20484][22540][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20484][17292][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [20484][22864][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [20484][3600][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [20484][21004][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [20484][18768][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [20484][9320][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [20484][16060][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [20484][3812][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [20484][20004][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16100][18268][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [16100][12196][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16100][21632][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16100][15276][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16100][9116][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16100][8976][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16100][19892][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16100][15868][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16100][1608][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16100][12892][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16100][21468][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16100][21804][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16100][21600][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16100][2164][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16100][13336][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16100][10740][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7704][21752][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [7704][3692][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7704][20956][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7704][19872][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7704][18220][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7704][3748][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [7704][20536][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7704][21560][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7704][21180][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7704][17320][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7704][22272][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7704][23100][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7704][6728][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7704][13780][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [7704][1616][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23360][3120][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [23360][19048][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23360][16760][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23360][23500][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23360][21792][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23360][15364][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23360][5976][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23360][2404][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23360][20304][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23360][15676][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23360][20656][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23360][20960][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23360][9036][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23360][13072][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23360][23496][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23360][20188][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23360][23116][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13688][19692][ScriptedSandbox64.exe] Start Address of Thread 7ff613f3559c in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [13688][21224][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e030 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [13688][19540][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e2d0 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [13688][16568][ScriptedSandbox64.exe] Start Address of Thread 7ff613f27a14 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [13688][21944][ScriptedSandbox64.exe] Start Address of Thread 7ff613f27b78 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [13688][1844][ScriptedSandbox64.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [13688][20024][ScriptedSandbox64.exe] Start Address of Thread 7ffaffd3dae0 in C:\Windows\System32\mshtml.dll->DllGetClassObject
[i] [13688][20100][ScriptedSandbox64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13688][4900][ScriptedSandbox64.exe] Start Address of Thread 7ffaffd3dae0 in C:\Windows\System32\mshtml.dll->DllGetClassObject
[i] [13688][17132][ScriptedSandbox64.exe] Start Address of Thread 7ffaffce3ab0 in C:\Windows\System32\mshtml.dll->InitializeLocalHtmlEngine
[i] [13688][20620][ScriptedSandbox64.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [13688][15920][ScriptedSandbox64.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [13688][20628][ScriptedSandbox64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13688][23256][ScriptedSandbox64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [19084][19192][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [19084][6684][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19084][1460][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19084][12508][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19084][16144][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19084][9504][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [19084][9260][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19084][20016][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19084][22896][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19084][5408][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19084][13064][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19084][2044][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19084][22384][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19084][17676][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19084][1108][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [19348][23480][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [19348][20732][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19348][5448][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19348][632][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19348][12248][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19348][948][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [19348][21932][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19348][19720][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19348][11888][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19348][19196][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19348][6872][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19348][18692][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19348][9412][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19348][20044][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [19348][16160][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11376][7220][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [11376][20344][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11376][3956][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11376][8120][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11376][4456][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11376][9644][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11376][16776][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11376][19920][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11376][19076][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11376][11932][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11376][18836][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11376][19680][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11376][16956][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11376][7312][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11376][13856][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23536][17312][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [23536][18628][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23536][22184][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23536][9540][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23536][17936][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23536][16240][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23536][8576][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23536][10264][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23536][17864][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23536][16600][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23536][4832][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23536][20088][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23536][20996][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23536][20952][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23536][22676][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23536][22344][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [23536][11276][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16724][22512][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [16724][14264][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][18804][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][9448][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][21680][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][660][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16724][10568][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][20464][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][17116][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][20792][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][19552][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][1704][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][22380][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][11832][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][7340][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][11164][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16724][5200][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [16724][23108][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14456][21176][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [14456][19188][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [14456][7776][conhost.exe] Start Address of Thread 7ff62eef4a90 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [14456][22820][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14456][13880][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14456][22432][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14152][2620][AUDIODG.EXE] Start Address of Thread 7ff6ed58cc30 in C:\WINDOWS\system32\AUDIODG.EXE->UnknownFunction
[i] [14152][16768][AUDIODG.EXE] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [14152][2168][AUDIODG.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14152][17072][AUDIODG.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14152][5216][AUDIODG.EXE] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23308][2064][notepad++.exe] Start Address of Thread 7ff76e2c2ec4 in C:\Program Files\Notepad++\notepad++.exe->UnknownFunction
[i] [23308][3552][notepad++.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23308][17480][notepad++.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [23308][10400][notepad++.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [8960][19616][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [8960][9080][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [8960][14388][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [8960][21332][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [8960][15212][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [8960][1688][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8960][19376][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [8960][8732][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [8960][17500][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [8960][5016][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [8960][22028][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [8960][13344][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [8960][16484][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [8960][8812][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [8960][6680][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [8960][12204][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [8960][17848][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18356][21536][identity_helper.exe] Start Address of Thread 7ff75e7c6980 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\identity_helper.exe->Ordinal0
[i] [18356][11080][identity_helper.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18356][18788][identity_helper.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18356][21152][identity_helper.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18356][17424][identity_helper.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18356][21012][identity_helper.exe] Start Address of Thread 7ffaf4c78160 in C:\Program Files (x86)\Microsoft\Edge\Application\97.0.1072.55\msedge.dll->ChromeMain
[i] [18356][20328][identity_helper.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [18356][5632][identity_helper.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18356][20840][identity_helper.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [18356][4604][identity_helper.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [13776][12908][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [13776][15844][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [13776][18100][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5808][2452][smartscreen.exe] Start Address of Thread 7ff721f274d0 in C:\Windows\System32\smartscreen.exe->UnknownFunction
[i] [5808][12960][smartscreen.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5808][9976][smartscreen.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5808][21748][smartscreen.exe] Start Address of Thread 7ffb70521b70 in C:\WINDOWS\System32\ucrtbase.dll->configthreadlocale
[i] [5808][17804][smartscreen.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [5808][4560][smartscreen.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [5808][10820][smartscreen.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5808][4816][smartscreen.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [5808][3856][smartscreen.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [15392][13208][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 223beeffe96 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\ServiceHub\controller\Microsoft.ServiceHub.Controller.exe->UnknownFunction
[i] [15392][4028][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb50d67c40 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->GC_Initialize
[i] [15392][20696][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [15392][18204][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [15392][19696][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [15392][8896][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb50bd9d10 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [15392][23188][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb52a08e40 in C:\WINDOWS\SYSTEM32\rasman.dll->RasSignalMonitorThreadExit
[i] [15392][20516][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb50d21ac0 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->GetMetaDataPublicInterfaceFromInternal
[i] [15392][17988][Microsoft.ServiceHub.Controller.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [15716][19488][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [15716][17228][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [15716][12988][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16328][19100][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [16328][5044][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [16328][1860][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [19312][17672][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [19312][18620][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [19312][18004][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [11460][20828][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [11460][20240][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11460][14808][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11460][8104][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11460][9188][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11460][19228][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [11460][17416][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16796][8676][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [16796][21884][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [16796][21760][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [6356][7844][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [6356][21044][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [6356][18508][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3656][8400][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [3656][16336][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [3656][20668][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [3656][21132][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2472][1028][chrome.exe] Start Address of Thread 7ff7741afdf0 in C:\Program Files (x86)\Google\Chrome\Application\chrome.exe->IsSandboxedProcess
[i] [2472][19836][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [2472][17168][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [2472][20880][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [2472][15768][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [2472][19976][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [2472][1236][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [2472][5420][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [2472][22136][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [2472][16932][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [2472][19572][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [2472][20780][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [2472][17996][chrome.exe] Start Address of Thread 7ffad0c804e0 in C:\Program Files (x86)\Google\Chrome\Application\97.0.4692.71\chrome.dll->ChromeMain
[i] [2472][13284][chrome.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16588][5624][msvsmon.exe] Start Address of Thread 7ff7a49a4818 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\Remote Debugger\x64\msvsmon.exe->OnAbnormalAbort
[i] [16588][2820][msvsmon.exe] Start Address of Thread 7ff7a4991eb8 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\Remote Debugger\x64\msvsmon.exe->OnAbnormalAbort
[i] [16588][13616][msvsmon.exe] Start Address of Thread 7ffb1ca6f1a0 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\Remote Debugger\x64\vsdebugeng.dll->ProcDkmWorkListSetDescription
[i] [16588][22964][msvsmon.exe] Start Address of Thread 7ffb1ca527cc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\Remote Debugger\x64\vsdebugeng.dll->DkmDllSetRootProcessId
[i] [16588][19480][msvsmon.exe] Start Address of Thread 7ffb1c9d8e0c in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\Remote Debugger\x64\vsdebugeng.dll->ProcDkmGetExtendedPart
[i] [16588][22664][msvsmon.exe] Start Address of Thread 7ffb272596e8 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\Remote Debugger\x64\vsdebugeng.impl.dll->ReleaseForeground
[i] [16588][10880][msvsmon.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16588][13424][msvsmon.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [16588][20204][msvsmon.exe] Start Address of Thread 7ffb50d67c40 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->GC_Initialize
[i] [16588][16816][msvsmon.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [20068][18992][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 1f788ac0000 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\ServiceHub\Hosts\ServiceHub.Host.CLR.x64\ServiceHub.DataWarehouseHost.exe->UnknownFunction
[i] [20068][12296][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50d67c40 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->GC_Initialize
[i] [20068][6248][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [20068][17820][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20068][17208][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20068][20504][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [20068][21640][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bd9d10 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [20068][19404][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [20068][5828][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20068][22932][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20068][21920][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20068][9476][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20068][16468][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20068][17576][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20068][13080][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20068][17640][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20068][1224][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb52a08e40 in C:\WINDOWS\SYSTEM32\rasman.dll->RasSignalMonitorThreadExit
[i] [20068][20028][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [20068][21136][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb55de9ae0 in C:\WINDOWS\WinSxS\amd64_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.19041.1466_none_91a4907ccc87e3b8\gdiplus.dll->GdiplusStartup
[i] [20068][8112][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [20068][11308][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [20068][21988][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [20068][22904][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [20068][13664][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [20068][11668][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [20068][17916][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [20068][16648][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [20068][19288][ServiceHub.DataWarehouseHost.exe] Start Address of Thread 7ffb50bdb540 in C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll->CoUninitializeEE
[i] [20400][2904][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [20400][21840][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [20400][22756][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [15604][19124][StandardCollector.Service.exe] Start Address of Thread 7ff73ed11ef0 in C:\Program Files (x86)\Microsoft Visual Studio\Shared\Common\DiagnosticsHub.Collection.Service\StandardCollector.Service.exe->UnknownFunction
[i] [15604][9016][StandardCollector.Service.exe] Start Address of Thread 7ffb71fedf40 in C:\WINDOWS\System32\sechost.dll->WaitServiceState
[i] [15604][20196][StandardCollector.Service.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [15604][22104][StandardCollector.Service.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [15604][16136][StandardCollector.Service.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [15604][11452][StandardCollector.Service.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [15604][20112][StandardCollector.Service.exe] Start Address of Thread 7ffb35297b30 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Team Tools\DiagnosticsHub\Collector\DiagnosticsHub.StandardCollector.Runtime.dll->UnknownFunction
[i] [15604][2660][StandardCollector.Service.exe] Start Address of Thread 7ffb35297b30 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Team Tools\DiagnosticsHub\Collector\DiagnosticsHub.StandardCollector.Runtime.dll->UnknownFunction
[i] [15604][2356][StandardCollector.Service.exe] Start Address of Thread 7ffb72dc4fe0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleasePool
[i] [15604][16312][StandardCollector.Service.exe] Start Address of Thread 7ffb35297b30 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Team Tools\DiagnosticsHub\Collector\DiagnosticsHub.StandardCollector.Runtime.dll->UnknownFunction
[i] [15604][12008][StandardCollector.Service.exe] Start Address of Thread 7ffb72dc4fe0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleasePool
[i] [15604][9760][StandardCollector.Service.exe] Start Address of Thread 7ffb35297b30 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Team Tools\DiagnosticsHub\Collector\DiagnosticsHub.StandardCollector.Runtime.dll->UnknownFunction
[i] [15604][17380][StandardCollector.Service.exe] Start Address of Thread 7ffb72dc4fe0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleasePool
[i] [15604][3100][StandardCollector.Service.exe] Start Address of Thread 7ffb35297b30 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Team Tools\DiagnosticsHub\Collector\DiagnosticsHub.StandardCollector.Runtime.dll->UnknownFunction
[i] [15604][15588][StandardCollector.Service.exe] Start Address of Thread 7ffb72dc4fe0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleasePool
[i] [15604][22892][StandardCollector.Service.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [15604][11600][StandardCollector.Service.exe] Start Address of Thread 7ffb35297b30 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Team Tools\DiagnosticsHub\Collector\DiagnosticsHub.StandardCollector.Runtime.dll->UnknownFunction
[i] [15604][8388][StandardCollector.Service.exe] Start Address of Thread 7ffb35297b30 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Team Tools\DiagnosticsHub\Collector\DiagnosticsHub.StandardCollector.Runtime.dll->UnknownFunction
[i] [15604][18876][StandardCollector.Service.exe] Start Address of Thread 7ffb72dc4fe0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleasePool
[i] [15604][1468][StandardCollector.Service.exe] Start Address of Thread 7ffb35297b30 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Team Tools\DiagnosticsHub\Collector\DiagnosticsHub.StandardCollector.Runtime.dll->UnknownFunction
[i] [15604][9776][StandardCollector.Service.exe] Start Address of Thread 7ffb72dc4fe0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleasePool
[i] [15604][16436][StandardCollector.Service.exe] Start Address of Thread 7ffb72dc4fe0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleasePool
[i] [21156][17224][conhost.exe] Start Address of Thread 7ff62ef03ac0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [21156][19304][conhost.exe] Start Address of Thread 7ff62ef0cae0 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [21156][11400][conhost.exe] Start Address of Thread 7ff62eef4a90 in C:\WINDOWS\system32\conhost.exe->UnknownFunction
[i] [21156][17444][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [21156][19024][conhost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22516][9764][MEMGUARD.exe] Start Address of Thread 7ff734f41023 in C:\Data\NCC\!Code\Slop\MEMGUARD\x64\Debug\MEMGUARD.exe->ILT+30(mainCRTStartup)
[i] [22516][18584][MEMGUARD.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22516][4240][MEMGUARD.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [22516][9668][MEMGUARD.exe] Start Address of Thread 1e8c7330000 in UnknownModule->UnknownFunction
[i] [22516][7772][MEMGUARD.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14464][14840][msvsmon.exe] Start Address of Thread 7ff7a49a4818 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\Remote Debugger\x64\msvsmon.exe->OnAbnormalAbort
[i] [14464][17040][msvsmon.exe] Start Address of Thread 7ff7a4991eb8 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\Remote Debugger\x64\msvsmon.exe->OnAbnormalAbort
[i] [14464][9180][msvsmon.exe] Start Address of Thread 7ffb1ca6f1a0 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\Remote Debugger\x64\vsdebugeng.dll->ProcDkmWorkListSetDescription
[i] [14464][9808][msvsmon.exe] Start Address of Thread 7ffb1ca527cc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\Remote Debugger\x64\vsdebugeng.dll->DkmDllSetRootProcessId
[i] [14464][18096][msvsmon.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14464][4720][msvsmon.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14464][10904][msvsmon.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14464][16660][msvsmon.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [14464][17148][msvsmon.exe] Start Address of Thread 7ffb1c9d8e0c in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\Remote Debugger\x64\vsdebugeng.dll->ProcDkmGetExtendedPart
[i] [19676][996][ScriptedSandbox64.exe] Start Address of Thread 7ff613f3559c in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][18152][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e030 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][22488][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e2d0 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][20964][ScriptedSandbox64.exe] Start Address of Thread 7ff613f27a14 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][15872][ScriptedSandbox64.exe] Start Address of Thread 7ff613f27b78 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][18240][ScriptedSandbox64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [19676][19140][ScriptedSandbox64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [19676][16236][ScriptedSandbox64.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [19676][17220][ScriptedSandbox64.exe] Start Address of Thread 7ffaffd3dae0 in C:\Windows\System32\mshtml.dll->DllGetClassObject
[i] [19676][5460][ScriptedSandbox64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [19676][9792][ScriptedSandbox64.exe] Start Address of Thread 7ffaffd3dae0 in C:\Windows\System32\mshtml.dll->DllGetClassObject
[i] [19676][5124][ScriptedSandbox64.exe] Start Address of Thread 7ffaffce3ab0 in C:\Windows\System32\mshtml.dll->InitializeLocalHtmlEngine
[i] [19676][21836][ScriptedSandbox64.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [19676][15368][ScriptedSandbox64.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [19676][16848][ScriptedSandbox64.exe] Start Address of Thread 7ffb72c5afb0 in C:\WINDOWS\System32\msvcrt.dll->endthreadex
[i] [19676][7464][ScriptedSandbox64.exe] Start Address of Thread 7ffaffd3dae0 in C:\Windows\System32\mshtml.dll->DllGetClassObject
[i] [19676][7552][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][7784][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][16984][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][20336][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][16764][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][22588][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][21456][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][420][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][18824][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][19928][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][21372][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][13032][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][2692][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][13940][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][14424][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][3248][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][18504][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][1440][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][10492][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][17900][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][11804][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][2428][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][23476][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][21728][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][10452][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][17020][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][14492][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][17200][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][19272][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][2244][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][18892][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][2900][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][10096][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][17928][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][22292][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][19960][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][8992][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][17836][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][20360][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e4fc in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [19676][2720][ScriptedSandbox64.exe] Start Address of Thread 7ff613f2e820 in C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\PrivateAssemblies\ScriptedSandbox64.exe->UnknownFunction
[i] [17588][C:\Windows\System32\svchost.exe] not analysed 5
[i] [1328][C:\Windows\System32\svchost.exe] not analysed 5
[i] [13276][C:\Windows\System32\svchost.exe] not analysed 5
[i] [1220][UNKNOWN] not analysed 31
[i] [20208][18764][SearchProtocolHost.exe] Start Address of Thread 7ff6f7c28220 in C:\WINDOWS\system32\SearchProtocolHost.exe->UnknownFunction
[i] [20208][9832][SearchProtocolHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20208][10860][SearchProtocolHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20208][21528][SearchProtocolHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20208][17104][SearchProtocolHost.exe] Start Address of Thread 7ff6f7c22890 in C:\WINDOWS\system32\SearchProtocolHost.exe->UnknownFunction
[i] [20208][2768][SearchProtocolHost.exe] Start Address of Thread 7ff6f7c173b0 in C:\WINDOWS\system32\SearchProtocolHost.exe->UnknownFunction
[i] [20208][16376][SearchProtocolHost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [20208][1372][SearchProtocolHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20208][3240][SearchProtocolHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20208][7368][SearchProtocolHost.exe] Start Address of Thread 7ffb2e511c00 in C:\PROGRA~1\MICROS~1\Office16\MAPIPH.DLL->DllUnregisterServer
[i] [20208][21352][SearchProtocolHost.exe] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [20208][9640][SearchProtocolHost.exe] Start Address of Thread 7ffb473e3188 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal899
[i] [20208][3744][SearchProtocolHost.exe] Start Address of Thread 7ffb356dd740 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso40uiwin32client.dll->Ordinal957
[i] [20208][22660][SearchProtocolHost.exe] Start Address of Thread 7ffb356ede34 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso40uiwin32client.dll->Ordinal452
[i] [20208][5628][SearchProtocolHost.exe] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [20208][21424][SearchProtocolHost.exe] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [20208][22096][SearchProtocolHost.exe] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [20208][18036][SearchProtocolHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20208][17076][SearchProtocolHost.exe] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [20208][17624][SearchProtocolHost.exe] Start Address of Thread 7ffb473e0748 in C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll->Ordinal720
[i] [20208][21672][SearchProtocolHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20556][6508][SearchFilterHost.exe] Start Address of Thread 7ff6e55a82f0 in C:\WINDOWS\system32\SearchFilterHost.exe->UnknownFunction
[i] [20556][7112][SearchFilterHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20556][17156][SearchFilterHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20556][16124][SearchFilterHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20556][19784][SearchFilterHost.exe] Start Address of Thread 7ffb71d4add0 in C:\WINDOWS\System32\combase.dll->RoGetServerActivatableClasses
[i] [20556][5340][SearchFilterHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20556][22832][SearchFilterHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [20556][21340][SearchFilterHost.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8380][17808][d-thread-start.exe] Start Address of Thread 7ff7a1741b84 in C:\Data\NCC\!Code\Git.Public\DetectWindowsCopyOnWriteForAPI\d-cow\x64\Release\d-thread-start.exe->wmainCRTStartup
[i] [8380][12100][d-thread-start.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8380][784][d-thread-start.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] [8380][15616][d-thread-start.exe] Start Address of Thread 7ffb72dc2ad0 in C:\WINDOWS\SYSTEM32\ntdll.dll->TpReleaseCleanupGroupMembers
[i] Total of 355 processes - didn't open 20 - total of 2983 threads - 2 start in unknown modules
```

