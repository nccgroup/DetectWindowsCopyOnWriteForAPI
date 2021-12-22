Windows Copy on Write Detector
======================

A copy on write detector for Windows APIs across processes.

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

https://github.com/nccgroup/DetectWindowsCopyOnWriteForAPI

Released under AGPL see LICENSE for more information

Blog
-------------
TBC

Hypothesis
-------------
By default Microsoft Windows will back copies of the same DLL against the same physical memory to save space. When a patch occurs a copy on write operation will happen.

From the Microsoft documentation:
https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery

*If a shared copy-on-write page is modified, it becomes private to the process that modified the page. However, the VirtualQuery function will continue to report such pages as MEM_MAPPED (for data views) or MEM_IMAGE (for executable image views) rather than MEM_PRIVATE. To detect whether copy-on-write has occurred for a specific page, either access the page or lock it using the VirtualLock function to make sure the page is resident in memory, then use the QueryWorkingSetEx function to check the Shared bit in the extended working set information for the page. If the Shared bit is clear, the page is private.*

Due to this bahaviour we can:
* Open processes
* Search for the address of EtwEventWrite
* Use QueryWorkingSetEx to check the page is shared OR not
* If not then it is an indication a patch has occurred

This should be a performant way to detect any memory patches to the .text section of DLLs.

Compatibility
-------------
Only Windows 10/11 tested

What it does
-------------
* GetProcAddress of EtwEventWrite
* Open processes
* Validate that NTDLL.dll is loaded and that EtwEventWrite is within the .text segement
* Use QueryWorkingSetEx to check the page is shared OR not
* If not then it is an indication a patch has occurred and alert

Running
-------------

The below is an example where we have patched the EtwEventWrite function

```
x64\Release>d-cow.exe
[i] Running..
[i] [11960][Calculator.exe] EtwEventWrite is located in NONE shared memory - indication of copy of write
```

Prior work
-------------
thanks for Peter Winter-Smith for pointing out this technique is implemented in Moneta by Forrest Orr

https://github.com/forrest-orr/moneta/blob/master/Source/Subregions.cpp

Offesnive tradecraft we detect
-------------
* https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/
* https://github.com/outflanknl/TamperETW
* https://github.com/ajpc500/BOFs/blob/main/ETW/etw.c
* https://github.com/boku7/injectEtwBypass
