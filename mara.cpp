#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <AclApi.h>
#include <Sddl.h>

// Based on Wunkolo's UWPDumper:
// https://github.com/Wunkolo/UWPDumper/blob/9fb0a040e674521c1413276bcea6e4e708f34d19/UWPInjector/source/main.cpp#L226
void SetAccessControl(std::wstring& ExecutableName, const wchar_t* AccessString)
{
    PSECURITY_DESCRIPTOR SecurityDescriptor = nullptr;
    EXPLICIT_ACCESSW ExplicitAccess = { 0 };

    ACL* AccessControlCurrent = nullptr;
    ACL* AccessControlNew = nullptr;

    SECURITY_INFORMATION SecurityInfo = DACL_SECURITY_INFORMATION;
    PSID SecurityIdentifier = nullptr;

    if (GetNamedSecurityInfoW(
        ExecutableName.c_str(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        &AccessControlCurrent,
        nullptr,
        &SecurityDescriptor
    ) == ERROR_SUCCESS)
    {
        ConvertStringSidToSidW(AccessString, &SecurityIdentifier);
        if (SecurityIdentifier != nullptr)
        {
            ExplicitAccess.grfAccessPermissions = GENERIC_READ | GENERIC_EXECUTE;
            ExplicitAccess.grfAccessMode = SET_ACCESS;
            ExplicitAccess.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
            ExplicitAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ExplicitAccess.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
            ExplicitAccess.Trustee.ptstrName = reinterpret_cast<wchar_t*>(SecurityIdentifier);

            if (SetEntriesInAclW(
                1,
                &ExplicitAccess,
                AccessControlCurrent,
                &AccessControlNew
            ) == ERROR_SUCCESS)
            {
                SetNamedSecurityInfoW(
                    const_cast<wchar_t*>(ExecutableName.c_str()),
                    SE_FILE_OBJECT,
                    SecurityInfo,
                    nullptr,
                    nullptr,
                    AccessControlNew,
                    nullptr
                );
            }
        }
    }
    if (SecurityDescriptor)
    {
        LocalFree(reinterpret_cast<HLOCAL>(SecurityDescriptor));
    }
    if (AccessControlNew)
    {
        LocalFree(reinterpret_cast<HLOCAL>(AccessControlNew));
    }
}

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
    // Set console title
    SetConsoleTitleA("MaraInjector");

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

    // Convert dllPath to wchar_t for SetAccessControl and performInjection
    int len = MultiByteToWideChar(CP_ACP, 0, dllPath, -1, NULL, 0);
    std::vector<wchar_t> wDllPathVec(len);
    MultiByteToWideChar(CP_ACP, 0, dllPath, -1, wDllPathVec.data(), len);

    // Get full path of DLL
    wchar_t fullPath[MAX_PATH];
    const wchar_t* finalPath = wDllPathVec.data();
    if (GetFullPathNameW(wDllPathVec.data(), MAX_PATH, fullPath, NULL)) {
        finalPath = fullPath;
    }

    std::wstring wStrPath(finalPath);

    std::wcout << L"Injecting: " << wStrPath << L" into " << processName << L" (PID: " << procId << L")..." << std::endl;

    // Grant UWP app container (ALL_APP_PACKAGES) read+execute access to the DLL
    // SID S-1-15-2-1 = ALL_APPLICATION_PACKAGES (required for Minecraft UWP)
    SetAccessControl(wStrPath, L"S-1-15-2-1");

    performInjection(procId, wStrPath.c_str());

    std::cout << "Successfully injected!" << std::endl;

    return 0;
}
