# BatDLLLoader

```
######     #    ####### ######  #       #       #       #######    #    ######  ####### ######  
#     #   # #      #    #     # #       #       #       #     #   # #   #     # #       #     # 
#     #  #   #     #    #     # #       #       #       #     #  #   #  #     # #       #     # 
######  #     #    #    #     # #       #       #       #     # #     # #     # #####   ######  
#     # #######    #    #     # #       #       #       #     # ####### #     # #       #   #   
#     # #     #    #    #     # #       #       #       #     # #     # #     # #       #    #  
######  #     #    #    ######  ####### ####### ####### ####### #     # ######  ####### #     # 
```

BatBasic BatDLL BatLoader and BatInjection into a BatProcess.

### BatBypass
- The current loader will bypass Defender (11/15/2023)
- The current loader will probably bypass other EDR like CrowdStrike, Avast. (Will be tester)

### ProcessInjection
- LoadLibraryA + VirtualAllocEx + CreateRemoteThread

### Code Modification
You need to modify this part of the code before you hope running your DLL's

```
FARPROC entry_point = GetProcAddress(dll, "StartW");
```

### Usage
You need to specify the PID and the DLL to inject

```
C:\Users\admin\Desktop>DLLLoadPID.exe
Usage: DLLLoadPID.exe <PID> <DLL>
```
With the proper DLLMain function of your DLL.
CobaltStrike DLL starts with a **StartW**.

```
Z:\>dumpbin /exports batmen.dll
Microsoft (R) COFF/PE Dumper Version 13.37.31337.0
Copyright (C) Microsoft Corporation.  All rights reserved.


Dump of file batmen.dll

File Type: DLL

  Section contains the following exports for temp.dll

    00000000 characteristics
    6511AD1C time date stamp Mon Sep 25 11:54:04 2023
        0.00 version
           1 ordinal base
           5 number of functions
           5 number of names

    ordinal hint RVA      name

          1    0 00001977 DllGetClassObject
          2    1 00001937 DllMain
          3    2 00001971 DllRegisterServer
          4    3 00001974 DllUnregisterServer
          5    4 00001980 StartW
```

