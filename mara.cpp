#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <TlHelp32.h>
#include <shellapi.h>
#include <iostream>
#include <string>
#include <vector>

DWORD GetProcId(const char *procName)
{
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry);

        if (Process32First(hSnap, &procEntry))
        {
            do
            {
                char output[256] = "error"; // convert wchar* to char*
                sprintf(output, "%ws", procEntry.szExeFile);
                if (!_stricmp(output, procName))
                {
                    procId = procEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &procEntry));
        }
    }
    CloseHandle(hSnap);
    return procId;
}

int performInjection(DWORD procId, const wchar_t *dllPath)
{
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, procId);

    if (hProc && hProc != INVALID_HANDLE_VALUE)
    {
        void *loc = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        WriteProcessMemory(hProc, loc, dllPath, wcslen(dllPath) * 2 + 2, 0); // length * 2 for bytes + 2 for end string

        HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, loc, 0, 0); // using LoadLibraryW instead of LoadLibraryA to allow wchar

        if (hThread)
        {
            CloseHandle(hThread);
        }
    }
    if (hProc)
    {
        CloseHandle(hProc);
    }
    return 0;
}

int main(int argc, char* argv[]) {
    // Check Admin rights
    BOOL fIsRunAsAdmin = FALSE;
    PSID pAdministratorsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(
        &NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &pAdministratorsGroup))
    {
        CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin);
        FreeSid(pAdministratorsGroup);
    }

    if (!fIsRunAsAdmin) {
        char szPath[MAX_PATH];
        if (GetModuleFileNameA(NULL, szPath, ARRAYSIZE(szPath))) {
            std::string args = "";
            for (int i = 1; i < argc; i++) {
                args += "\"";
                args += argv[i];
                args += "\" ";
            }
            
            SHELLEXECUTEINFOA sei = { sizeof(sei) };
            sei.fMask = SEE_MASK_NOCLOSEPROCESS;
            sei.lpVerb = "runas";
            sei.lpFile = szPath;
            sei.lpParameters = args.c_str();
            sei.hwnd = NULL;
            sei.nShow = SW_SHOWNORMAL; // Ensure it opens not fullscreen
            
            if (ShellExecuteExA(&sei)) {
                // Wait for the elevated process to finish if needed, or just exit.
                // We'll just exit so the launcher doesn't hang waiting if it doesn't need to.
                return 0; 
            }
        }
        std::cerr << "Failed to elevate privileges." << std::endl;
        return 1;
    }

    // Set console title
    SetConsoleTitleA("MaraInjector");

    // Make sure it's not fullscreen by restoring the window
    HWND consoleWindow = GetConsoleWindow();
    if (consoleWindow) {
        ShowWindow(consoleWindow, SW_SHOWNORMAL);
    }

    if (argc != 3) {
        std::cout << "MaraInjector" << std::endl;
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

    // Convert dllPath to wchar_t for performInjection
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
