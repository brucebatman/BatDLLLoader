#include <windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <wchar.h>


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

BOOL InjectDll(DWORD procID, const char* dllName) {
    if (procID == 0) {
        return FALSE;
    }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
    if (hProc == NULL) {
        wprintf(L"Error opening process. Error code: %lu\n", GetLastError());
        return FALSE;
    }

    WCHAR fullDllName[MAX_PATH];
    GetFullPathNameW(dllName, MAX_PATH, fullDllName, NULL);
    wprintf(L"[+] Acquired full DLL path: %s\n", fullDllName);

    LPVOID remoteString = VirtualAllocEx(hProc, NULL, wcslen(fullDllName) * sizeof(WCHAR) + sizeof(WCHAR), MEM_COMMIT, PAGE_READWRITE);
    if (remoteString == NULL) {
        wprintf(L"Error allocating memory in the remote process. Error code: %lu\n", GetLastError());
        CloseHandle(hProc);
        return FALSE;
    }

    if (!WriteProcessMemory(hProc, remoteString, fullDllName, wcslen(fullDllName) * sizeof(WCHAR) + sizeof(WCHAR), NULL)) {
        wprintf(L"Error writing to the remote process. Error code: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remoteString, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }

    HMODULE kernel32 = GetModuleHandle(L"kernel32.dll");
    if (kernel32 == NULL) {
        wprintf(L"Error getting handle to kernel32.dll. Error code: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remoteString, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }

    LPVOID loadLibrary = (LPVOID)GetProcAddress(kernel32, "LoadLibraryW");
    if (loadLibrary == NULL) {
        wprintf(L"Error getting address of LoadLibraryW. Error code: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remoteString, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibrary, remoteString, 0, NULL);
    if (hThread == NULL) {
        wprintf(L"Error creating remote thread. Error code: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remoteString, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    VirtualFreeEx(hProc, remoteString, 0, MEM_RELEASE);
    CloseHandle(hProc);

    return TRUE;
}

DWORD GetProcIDByPartialName(const wchar_t* partialName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        wprintf(L"Error creating process snapshot. Error code: %lu\n", GetLastError());
        return 0;
    }

    PROCESSENTRY32 procEntry;
    ZeroMemory(&procEntry, sizeof(PROCESSENTRY32));
    procEntry.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnap, &procEntry)) {
        wprintf(L"Error getting process snapshot. Error code: %lu\n", GetLastError());
        CloseHandle(hSnap);
        return 0;
    }

    do {
        if (wcsstr(procEntry.szExeFile, partialName) != NULL) {
            CloseHandle(hSnap);
            return procEntry.th32ProcessID;
        }
    } while (Process32Next(hSnap, &procEntry));

    CloseHandle(hSnap);
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 3) {
        wprintf(L"Sample Usage:\n");
        wprintf(L"%s <name of process> <path of dll to load>\n", argv[0]);
        return 0;
    }

    const wchar_t* processName = argv[1];
    const wchar_t* dllName = argv[2];
    DWORD procID = GetProcIDByPartialName(processName);

    if (procID == 0) {
        wprintf(L"Could not find process %s\n", processName);
        return 1;
    }

    wprintf(L"[+] Got process ID for %s PID: %lu\n", processName, procID);

    if (InjectDll(procID, dllName)) {
        wprintf(L"DLL now injected!\n");
    }
    else {
        wprintf(L"DLL couldn't be injected\n");
    }

    return 0;
}
