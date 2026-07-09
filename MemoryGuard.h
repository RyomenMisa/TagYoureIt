#pragma once
#include <windows.h>

class MemoryGuard {
public:
    static MemoryGuard& GetInstance();
    bool InstallHooks();
    void RemoveHooks();

    typedef LPVOID(WINAPI* VirtualAllocEx_t)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    static VirtualAllocEx_t OriginalVirtualAllocEx;

private:
    MemoryGuard();
    ~MemoryGuard();

    BYTE originalBytes[12];
};

