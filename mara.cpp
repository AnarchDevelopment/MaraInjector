#include <windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>
#include <vector>

DWORD GetProcId(const char* procName) {
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry);

        if (Process32First(hSnap, &procEntry)) {
            do {
                char output[MAX_PATH];
#ifdef UNICODE
                // Convert WCHAR to char for comparison with procName (which is char*)
                WideCharToMultiByte(CP_ACP, 0, procEntry.szExeFile, -1, output, MAX_PATH, NULL, NULL);
#else
                strcpy_s(output, procEntry.szExeFile);
#endif
                if (_stricmp(output, procName) == 0) {
                    procId = procEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &procEntry));
        }
    }
    CloseHandle(hSnap);
    return procId;
}

int performInjection(DWORD procId, const wchar_t* dllPath) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, procId);

    if (hProc && hProc != INVALID_HANDLE_VALUE) {
        // Allocate memory for the DLL path in the target process
        size_t pathLen = (wcslen(dllPath) + 1) * sizeof(wchar_t);
        void* loc = VirtualAllocEx(hProc, 0, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        
        if (!loc) {
            std::cerr << "Error: Failed to allocate memory in target process (Error: " << GetLastError() << ")" << std::endl;
            CloseHandle(hProc);
            return 1;
        }

        // Write the DLL path to the allocated memory
        if (!WriteProcessMemory(hProc, loc, dllPath, pathLen, 0)) {
            std::cerr << "Error: Failed to write memory in target process (Error: " << GetLastError() << ")" << std::endl;
            VirtualFreeEx(hProc, loc, 0, MEM_RELEASE);
            CloseHandle(hProc);
            return 1;
        }

        // Start a remote thread that calls LoadLibraryW with the DLL path
        HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, loc, 0, 0);

        if (hThread) {
            // Wait for the thread to finish executing LoadLibraryW
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        } else {
            std::cerr << "Error: Failed to create remote thread (Error: " << GetLastError() << ")" << std::endl;
            VirtualFreeEx(hProc, loc, 0, MEM_RELEASE);
            CloseHandle(hProc);
            return 1;
        }
        
        // Clean up the allocated memory
        VirtualFreeEx(hProc, loc, 0, MEM_RELEASE);
        CloseHandle(hProc);
    } else {
        std::cerr << "Error: Failed to open process (Error: " << GetLastError() << "). Try running as administrator." << std::endl;
        return 1;
    }
    
    return 0;
}

int main(int argc, char* argv[]) {
    // Set console title
    SetConsoleTitleA("MaraInjector - Fate Logic");

    if (argc != 3) {
        std::cout << "MaraInjector - Based on FateInjector logic" << std::endl;
        std::cout << "usage: mara.exe {process} {path-to-dll}" << std::endl;
        return 1;
    }

    const char* processName = argv[1];
    const char* dllPath = argv[2];

    // Check if DLL exists
    DWORD dwAttrib = GetFileAttributesA(dllPath);
    if (dwAttrib == INVALID_FILE_ATTRIBUTES || (dwAttrib & FILE_ATTRIBUTE_DIRECTORY)) {
        std::cerr << "Error: DLL file not found or invalid: " << dllPath << std::endl;
        return 1;
    }

    DWORD procId = GetProcId(processName);
    if (!procId) {
        std::cerr << "Error: Process '" << processName << "' not found." << std::endl;
        return 1;
    }

    // Convert dllPath to wchar_t for LoadLibraryW
    int len = MultiByteToWideChar(CP_ACP, 0, dllPath, -1, NULL, 0);
    std::vector<wchar_t> wDllPath(len);
    MultiByteToWideChar(CP_ACP, 0, dllPath, -1, wDllPath.data(), len);

    // Get full path of DLL if possible
    wchar_t fullPath[MAX_PATH];
    if (GetFullPathNameW(wDllPath.data(), MAX_PATH, fullPath, NULL)) {
        std::wcout << L"Injecting: " << fullPath << L" into " << processName << L" (PID: " << procId << L")..." << std::endl;
        if (performInjection(procId, fullPath) == 0) {
            std::cout << "Successfully injected!" << std::endl;
        } else {
            return 1;
        }
    } else {
        std::wcout << L"Injecting: " << wDllPath.data() << L" into " << processName << L" (PID: " << procId << L")..." << std::endl;
        if (performInjection(procId, wDllPath.data()) == 0) {
            std::cout << "Successfully injected!" << std::endl;
        } else {
            return 1;
        }
    }

    return 0;
}
