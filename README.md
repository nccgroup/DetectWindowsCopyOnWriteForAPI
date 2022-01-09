Windows Process Property Enumeration Tools for Threat Hunting
======================

Background
-------------
The purpose of these tools is to enumerate traits of Windows processes that support the detection of process injection tradecraft used by threat actors.

Tools
-------------
* d-cow - Windows Copy on Write Detector for shared Windows APIs (e.g. EtwEventWrite) to detect in memory patching
* d-criticalsections - Enumerates how many critical sections a Windows process has
* d-dr-registers - Enumerates processes which have debug registers set indicating hardware breakpoints
* d-nonmodulecallstack - Enumerates the call stack and associated modules and functions for all threads
* d-peb-dll-loadreason - Enumerates the reason and the date/time stamp along with a delta from the main binary for DLL loading
* d-teb - Enumerate threads which are impersonating other users
* d-threat-start - Enumerate the starting address and which module that points to for each thread
* d-vehimplant - Enumerate the Vectored Exception Handlers and which modules they point to
* d-vehlab - sandbox for the VEH work
