DLL Load Reason and Date/Time Stamp Enumerator for Windows
======================
Enumerates which DLLs are loaded within a process, the reason for the load, when it happened and the delta of the load from processes creation. This will help identify anomalous libraries which have been loaded due to code injection. 

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
[i] [1072][lsass.exe] Load Reason for lsass.exe is Dynamic Load - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for ntdll.dll is Static Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for KERNEL32.DLL is Dynamic Load - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for KERNELBASE.dll is Static Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for RPCRT4.dll is Static Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for lsasrv.dll is Dynamic Load - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for ucrtbase.dll is Static Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for WS2_32.dll is Static Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for sechost.dll is Static Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for WLDAP32.dll is Static Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for SspiCli.dll is Static Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for MSASN1.dll is Static Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for samsrv.dll is Delayload Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for bcrypt.dll is Static Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for CRYPT32.dll is Static Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for ncrypt.dll is Delayload Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for NTASN1.dll is Delayload Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for Wldp.dll is Delayload Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for msvcrt.dll is Static Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for advapi32.dll is Static Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for bcryptprimitives.dll is Dynamic Load - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for msprivs.DLL is Dynamic Load - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for netprovfw.dll is Delayload Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for JOINUTIL.DLL is Dynamic Forwarder Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for negoexts.DLL is Dynamic Load - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for CRYPTSP.dll is Static Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for CRYPTBASE.dll is Static Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for kerberos.DLL is Dynamic Load - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for msvcp_win.dll is Static Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for KerbClientShared.dll is Dynamic Load - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for cryptdll.dll is Dynamic Load - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for mswsock.dll is Dynamic Load - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for msv1_0.DLL is Dynamic Load - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for NtlmShared.dll is Static Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for netlogon.DLL is Dynamic Load - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for powrprof.dll is Static Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for USERENV.dll is Static Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for gmsaclient.dll is Static Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for netutils.dll is Static Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for logoncli.dll is Static Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for DNSAPI.dll is Static Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for IPHLPAPI.DLL is Delayload Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for NSI.dll is Delayload Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for UMPDC.dll is Delayload Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for tspkg.DLL is Dynamic Load - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for pku2u.DLL is Dynamic Load - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for cloudAP.DLL is Dynamic Load - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for profapi.dll is Delayload Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for aadcloudap.dll is Dynamic Load - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for combase.dll is Static Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for wkscli.dll is Static Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for msvcp110_win.dll is Static Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for MicrosoftAccountCloudAP.dll is Dynamic Load - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for DPAPI.DLL is Static Forwarder Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for rsaenh.dll is Dynamic Load - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for wdigest.DLL is Dynamic Load - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for schannel.DLL is Dynamic Load - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for efslsaext.dll is Dynamic Load - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for shcore.dll is Static Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for dpapisrv.dll is Dynamic Load - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for SspiSrv.dll is Delayload Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for KDCPW.DLL is Dynamic Load - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for scecli.DLL is Dynamic Load - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for winsta.dll is Delayload Dependency - loaded @ 2022-01-04 15:23:25 - Delta 0
[i] [1072][lsass.exe] Load Reason for wevtapi.dll is Delayload Dependency - loaded @ 2022-01-04 15:23:30 - Delta 5
[i] [1072][lsass.exe] Load Reason for ncryptsslp.dll is Dynamic Load - loaded @ 2022-01-04 15:23:36 - Delta 11
[i] [1072][lsass.exe] Load Reason for ncryptprov.dll is Dynamic Load - loaded @ 2022-01-04 15:23:36 - Delta 11
[i] [1072][lsass.exe] Load Reason for dssenh.dll is Dynamic Load - loaded @ 2022-01-04 15:23:36 - Delta 11
[i] [1072][lsass.exe] Load Reason for gpapi.dll is Delayload Dependency - loaded @ 2022-01-04 15:23:36 - Delta 11
[i] [1072][lsass.exe] Load Reason for mskeyprotect.dll is Dynamic Load - loaded @ 2022-01-04 15:23:36 - Delta 11
[i] [1072][lsass.exe] Load Reason for keyiso.dll is Dynamic Load - loaded @ 2022-01-04 15:23:38 - Delta 13
[i] [1072][lsass.exe] Load Reason for AUTHZ.dll is Delayload Dependency - loaded @ 2022-01-04 15:23:38 - Delta 13
[i] [1072][lsass.exe] Load Reason for secur32.dll is Delayload Dependency - loaded @ 2022-01-04 15:23:44 - Delta 19
[i] [1072][lsass.exe] Load Reason for wtsapi32.dll is Delayload Dependency - loaded @ 2022-01-04 15:23:44 - Delta 19
[i] [1072][lsass.exe] Load Reason for SecureTimeAggregator.dll is Dynamic Load - loaded @ 2022-01-04 15:23:57 - Delta 32
[i] [1072][lsass.exe] Load Reason for DSROLE.dll is Static Dependency - loaded @ 2022-01-04 15:23:57 - Delta 32
[i] [1072][lsass.exe] Load Reason for kernel.appcore.dll is Dynamic Load - loaded @ 2022-01-04 15:23:57 - Delta 32
[i] [1072][lsass.exe] Load Reason for cryptnet.dll is Dynamic Load - loaded @ 2022-01-04 15:23:58 - Delta 33
[i] [1072][lsass.exe] Load Reason for ngcpopkeysrv.dll is Dynamic Load - loaded @ 2022-01-04 15:24:08 - Delta 43
[i] [1072][lsass.exe] Load Reason for OLEAUT32.dll is Static Dependency - loaded @ 2022-01-04 15:24:08 - Delta 43
[i] [1072][lsass.exe] Load Reason for DEVOBJ.dll is Static Dependency - loaded @ 2022-01-04 15:24:08 - Delta 43
[i] [1072][lsass.exe] Load Reason for cfgmgr32.dll is Static Dependency - loaded @ 2022-01-04 15:24:08 - Delta 43
[i] [1072][lsass.exe] Load Reason for PCPKsp.dll is Dynamic Load - loaded @ 2022-01-04 15:24:08 - Delta 43
[i] [1072][lsass.exe] Load Reason for ntmarta.dll is Static Dependency - loaded @ 2022-01-04 15:24:08 - Delta 43
[i] [1072][lsass.exe] Load Reason for tbs.dll is Delayload Dependency - loaded @ 2022-01-04 15:24:08 - Delta 43
[i] [1072][lsass.exe] Load Reason for imagehlp.dll is Static Dependency - loaded @ 2022-01-04 15:24:08 - Delta 43
[i] [1072][lsass.exe] Load Reason for DSPARSE.dll is Delayload Dependency - loaded @ 2022-01-04 15:24:09 - Delta 44
[i] [1072][lsass.exe] Load Reason for efssvc.dll is Dynamic Load - loaded @ 2022-01-04 15:25:49 - Delta 144
[i] [1072][lsass.exe] Load Reason for EFSCORE.dll is Dynamic Load - loaded @ 2022-01-04 15:25:49 - Delta 144
[i] [1072][lsass.exe] Load Reason for WINHTTP.dll is Static Dependency - loaded @ 2022-01-04 15:25:49 - Delta 144
[i] [1072][lsass.exe] Load Reason for iertutil.dll is Static Dependency - loaded @ 2022-01-04 15:25:49 - Delta 144
[i] [1072][lsass.exe] Load Reason for edpauditapi.dll is Delayload Dependency - loaded @ 2022-01-04 15:25:49 - Delta 144
[i] [1072][lsass.exe] Load Reason for tdh.dll is Static Dependency - loaded @ 2022-01-04 15:25:49 - Delta 144
[i] [1072][lsass.exe] Load Reason for efsext.dll is Delayload Dependency - loaded @ 2022-01-04 15:25:49 - Delta 144
[i] [1072][lsass.exe] Load Reason for SHELL32.dll is Static Dependency - loaded @ 2022-01-04 15:25:49 - Delta 144
[i] [1072][lsass.exe] Load Reason for USER32.dll is Static Dependency - loaded @ 2022-01-04 15:25:49 - Delta 144
[i] [1072][lsass.exe] Load Reason for win32u.dll is Static Dependency - loaded @ 2022-01-04 15:25:49 - Delta 144
[i] [1072][lsass.exe] Load Reason for GDI32.dll is Static Dependency - loaded @ 2022-01-04 15:25:49 - Delta 144
[i] [1072][lsass.exe] Load Reason for gdi32full.dll is Static Dependency - loaded @ 2022-01-04 15:25:49 - Delta 144
[i] [1072][lsass.exe] Load Reason for DUI70.dll is Static Dependency - loaded @ 2022-01-04 15:25:49 - Delta 144
[i] [1072][lsass.exe] Load Reason for usermgrcli.dll is Delayload Dependency - loaded @ 2022-01-04 15:25:49 - Delta 144
[i] [1072][lsass.exe] Load Reason for cryptngc.dll is Delayload Dependency - loaded @ 2022-01-04 15:25:49 - Delta 144
[i] [1072][lsass.exe] Load Reason for ngcksp.dll is Dynamic Load - loaded @ 2022-01-04 15:25:49 - Delta 144
[i] [1072][lsass.exe] Load Reason for feclient.dll is Delayload Dependency - loaded @ 2022-01-04 15:25:49 - Delta 144
[i] [1072][lsass.exe] Load Reason for EFSUTIL.dll is Delayload Dependency - loaded @ 2022-01-04 15:25:49 - Delta 144
[i] [1072][lsass.exe] Load Reason for policymanager.dll is Delayload Dependency - loaded @ 2022-01-04 15:25:49 - Delta 144
[i] [1072][lsass.exe] Load Reason for vaultsvc.dll is Dynamic Load - loaded @ 2022-01-04 15:25:52 - Delta 147
[i] [1072][lsass.exe] Load Reason for clbcatq.dll is Delayload Dependency - loaded @ 2022-01-04 15:25:52 - Delta 147
[i] [1072][lsass.exe] Load Reason for certpoleng.dll is Delayload Dependency - loaded @ 2022-01-04 16:10:11 - Delta 2806
[i] [1072][lsass.exe] Load Reason for WINNSI.DLL is Delayload Dependency - loaded @ 2022-01-05 15:23:43 - Delta 86418
[i] [1072][lsass.exe] Load Reason for dhcpcsvc6.DLL is Delayload Dependency - loaded @ 2022-01-05 15:23:43 - Delta 86418
[i] [1072][lsass.exe] Load Reason for dhcpcsvc.DLL is Delayload Dependency - loaded @ 2022-01-05 15:23:43 - Delta 86418
[i] [1072][lsass.exe] Load Reason for webio.dll is Delayload Dependency - loaded @ 2022-01-05 15:23:43 - Delta 86418
[i] [1072][lsass.exe] Load Reason for rasadhlp.dll is Dynamic Load - loaded @ 2022-01-05 15:23:43 - Delta 86418
[i] [1072][lsass.exe] Load Reason for fwpuclnt.dll is Dynamic Load - loaded @ 2022-01-05 15:23:43 - Delta 86418
```