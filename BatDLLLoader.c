#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>

/*
######     #    ####### ######  #       #       #       #######    #    ######  ####### ######  
#     #   # #      #    #     # #       #       #       #     #   # #   #     # #       #     # 
#     #  #   #     #    #     # #       #       #       #     #  #   #  #     # #       #     # 
######  #     #    #    #     # #       #       #       #     # #     # #     # #####   ######  
#     # #######    #    #     # #       #       #       #     # ####### #     # #       #   #   
#     # #     #    #    #     # #       #       #       #     # #     # #     # #       #    #  
######  #     #    #    ######  ####### ####### ####### ####### #     # ######  ####### #     # 

*/


int main(int argc, char* argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <PID> <DLL>\n", argv[0]);
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    LPVOID dll = LoadLibraryA(argv[2]);
    if (dll == NULL)
    {
        DWORD error = GetLastError();
        printf("Error loading DLL: %s\n", argv[2]);
        printf("Error code: %d\n", error);
        return 1;
    }

    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (process == NULL)
    {
        DWORD error = GetLastError();
        printf("Error opening process: %d\n", pid);
        printf("Error code: %d\n", error);
        return 1;
    }

    LPVOID remote_dll = VirtualAllocEx(process, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remote_dll == NULL)
    {
        DWORD error = GetLastError();
        printf("Error allocating memory in remote process: %d\n", pid);
        printf("Error code: %d\n", error);
        return 1;
    }

    BOOL success = WriteProcessMemory(process, remote_dll, dll, 4096, NULL);
    if (!success)
    {
        DWORD error = GetLastError();
        printf("Error writing DLL to remote process: %d\n", pid);
        printf("Error code: %d\n", error);
        return 1;
    }

    HANDLE thread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, (LPVOID)remote_dll, 0, NULL);
    if (thread == NULL)
    {
        DWORD error = GetLastError();
        printf("Error creating remote thread: %d\n", pid);
        printf("Error code: %d\n", error);
        return 1;
    }

    WaitForSingleObject(thread, INFINITE);

    CloseHandle(thread);
    CloseHandle(process);

    // Get the DLL's entry point.
    FARPROC entry_point = GetProcAddress(dll, "StartW");
    if (entry_point == NULL)
    {
        DWORD error = GetLastError();
        printf("Error getting DLL entry point: %s\n", argv[2]);
        printf("Error code: %d\n", error);
        return 1;
    }

    // Call the DLL's entry point.
    BOOL result = (*entry_point)(NULL, DLL_PROCESS_ATTACH, NULL);
    if (!result)
    {
        DWORD error = GetLastError();
        printf("Error calling DLL entry point: %s\n", argv[2]);
        printf("Error code: %d\n", error);
        return 1;
    }

    // Free the DLL.
    FreeLibrary(dll);

    return 0;
}
