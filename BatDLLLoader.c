#include <windows.h>
#include <stdio.h>

/*
######     #    ####### ######  #       #       #       #######    #    ######  ####### ######  
#     #   # #      #    #     # #       #       #       #     #   # #   #     # #       #     # 
#     #  #   #     #    #     # #       #       #       #     #  #   #  #     # #       #     # 
######  #     #    #    #     # #       #       #       #     # #     # #     # #####   ######  
#     # #######    #    #     # #       #       #       #     # ####### #     # #       #   #   
#     # #     #    #    #     # #       #       #       #     # #     # #     # #       #    #  
######  #     #    #    ######  ####### ####### ####### ####### #     # ######  ####### #     # 
v2.0
*/


void HandleError(const char* action, DWORD errorCode) {
    LPVOID lpMsgBuf;
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0, NULL);

    printf("Error %s: %d - %s\n", action, errorCode, lpMsgBuf);

    LocalFree(lpMsgBuf);
}

// Function to inject a DLL into a remote process and execute code in that process.
void InjectDllAndExecute(DWORD pid, const char* dllPath, const char* entryPoint) {
    // Open the target process with the required permissions.
    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (process == NULL) {
        HandleError("opening process", GetLastError());
        return;
    }

    // Allocate memory in the target process for the DLL path.
    LPVOID remoteDllPath = VirtualAllocEx(process, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (remoteDllPath == NULL) {
        HandleError("allocating memory in remote process", GetLastError());
        CloseHandle(process);
        return;
    }

    // Write the DLL path to the target process.
    SIZE_T bytesWritten;
    BOOL success = WriteProcessMemory(process, remoteDllPath, dllPath, strlen(dllPath) + 1, &bytesWritten);
    if (!success || bytesWritten != strlen(dllPath) + 1) {
        HandleError("writing to remote process memory", GetLastError());
        VirtualFreeEx(process, remoteDllPath, 0, MEM_RELEASE);
        CloseHandle(process);
        return;
    }

    // Get the address of LoadLibraryA in the current process.
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC loadLibrary = GetProcAddress(kernel32, "LoadLibraryA");

    // Create a remote thread in the target process to load the DLL.
    HANDLE remoteThread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibrary, remoteDllPath, 0, NULL);
    if (remoteThread == NULL) {
        HandleError("creating remote thread", GetLastError());
        VirtualFreeEx(process, remoteDllPath, 0, MEM_RELEASE);
        CloseHandle(process);
        return;
    }

    // Wait for the remote thread to finish.
    WaitForSingleObject(remoteThread, INFINITE);

    // Clean up resources.
    CloseHandle(remoteThread);
    VirtualFreeEx(process, remoteDllPath, 0, MEM_RELEASE);
    CloseHandle(process);
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        printf("Usage: %s <PID> <DLL> <ENTRY_POINT>\n", argv[0]);
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    const char* dllPath = argv[2];
    const char* entryPoint = argv[3];

    // Inject DLL and execute code in the target process.
    InjectDllAndExecute(pid, dllPath, entryPoint);

    return 0;
}
