#include "MemoryGuard.h"
#include "Logger.h"
#include "HeuristicEngine.h"
#include <iostream>

MemoryGuard::VirtualAllocEx_t MemoryGuard::OriginalVirtualAllocEx = nullptr;

MemoryGuard& MemoryGuard::GetInstance() {
    static MemoryGuard instance;
    return instance;
}

MemoryGuard::MemoryGuard() {
    memset(originalBytes, 0, 12); // Чистим 12 байт
}

MemoryGuard::~MemoryGuard() {
    RemoveHooks();
}

LPVOID WINAPI HookedVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    // 1. Мгновенно снимаем хук при входе
    MemoryGuard::GetInstance().RemoveHooks();

    DWORD targetPID = GetProcessId(hProcess);
    DWORD currentPID = GetCurrentProcessId();

    if (targetPID != currentPID && targetPID != 0) {
        Logger::GetInstance().Log(LogLevel::ALERT,
            L"[ЗАЩИТА ПАМЯТИ] Перехват VirtualAllocEx! Попытка инъекции. Цель PID: " + std::to_wstring(targetPID));
    }

    // 2. Вызываем оригинальную системную функцию
    LPVOID result = VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);

    // 3. Возвращаем хук на место
    MemoryGuard::GetInstance().InstallHooks();

    return result;
}

bool MemoryGuard::InstallHooks() {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) return false;

    OriginalVirtualAllocEx = (VirtualAllocEx_t)GetProcAddress(hKernel32, "VirtualAllocEx");
    if (!OriginalVirtualAllocEx) return false;

    DWORD oldProtect;
    VirtualProtect(OriginalVirtualAllocEx, 12, PAGE_EXECUTE_READWRITE, &oldProtect);

    // Сохраняем 12 оригинальных байт
    memcpy(originalBytes, OriginalVirtualAllocEx, 12);

    // x64 Абсолютный прыжок (12 байт): 
    // MOV RAX, <Наш 64-битный адрес>
    // JMP RAX
    BYTE patch[12] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };
    uint64_t hookAddr = (uint64_t)HookedVirtualAllocEx;
    memcpy(&patch[2], &hookAddr, 8); // Вшиваем адрес функции в байт-код

    // Устанавливаем патч
    memcpy(OriginalVirtualAllocEx, patch, 12);
    VirtualProtect(OriginalVirtualAllocEx, 12, oldProtect, &oldProtect);
    return true;
}

void MemoryGuard::RemoveHooks() {
    if (!OriginalVirtualAllocEx) return;

    DWORD oldProtect;
    VirtualProtect(OriginalVirtualAllocEx, 12, PAGE_EXECUTE_READWRITE, &oldProtect);

    // Возвращаем родные 12 байт на место
    memcpy(OriginalVirtualAllocEx, originalBytes, 12);

    VirtualProtect(OriginalVirtualAllocEx, 12, oldProtect, &oldProtect);
}
