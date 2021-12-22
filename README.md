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
By default Microsoft will back copies of the same DLL against the same physical memory to save space. When a patch occurs a copy on write operation will happen.

From the Microsoft documentation:
https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery

*If a shared copy-on-write page is modified, it becomes private to the process that modified the page. However, the VirtualQuery function will continue to report such pages as MEM_MAPPED (for data views) or MEM_IMAGE (for executable image views) rather than MEM_PRIVATE. To detect whether copy-on-write has occurred for a specific page, either access the page or lock it using the VirtualLock function to make sure the page is resident in memory, then use the QueryWorkingSetEx function to check the Shared bit in the extended working set information for the page. If the Shared bit is clear, the page is private.*

Due to this bahaviour we can:
* Open processes
* Search for the address of ETWPrint
* Use QueryWorkingSetEx to check the page is shared OR not
* If not then it is an indication a patch has occurred


Compatibility
-------------
Only Windows 10/11 is supported / tested

What it does
-------------
Simply:
* Open processes
* Search for the address of ETWPrint
* Use QueryWorkingSetEx to check the page is shared OR not
* If not then it is an indication a patch has occurred


Running
-------------

The below is an example where we have patched the ETWPrint function

```
x64\Release>d-cow.exe
[i] Running..
[i] [11960][Calculator.exe] ETWrite is located in NONE shared memory - indication of copy of write
```

