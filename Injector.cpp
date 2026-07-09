#include "Injector.h"
#include "Logger.h"

Injector& Injector::GetInstance() {
    static Injector instance;
    return instance;
}

Injector::Injector() {}
Injector::~Injector() {}

bool Injector::InjectDLL(DWORD processID, const std::wstring& dllPath) {
    // 1. Открываем процесс с правами на запись и создание удаленных потоков
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (hProcess == NULL) {
        // Уровень WARNING, так как к некоторым системным процессам Windows нас просто не пустит (и это нормально)
        Logger::GetInstance().Log(LogLevel::WARNING, L"[ИНЪЕКЦИЯ] Отказ в доступе (Access Denied) к PID: " + std::to_wstring(processID));
        return false;
    }

    // 2. Выделяем память в чужом процессе под строку с путем к DLL
    size_t pathSize = (dllPath.length() + 1) * sizeof(wchar_t);
    LPVOID allocatedMem = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (allocatedMem == NULL) {
        CloseHandle(hProcess);
        return false;
    }

    // 3. Записываем путь к нашей DLL в эту выделенную память
    if (!WriteProcessMemory(hProcess, allocatedMem, dllPath.c_str(), pathSize, NULL)) {
        VirtualFreeEx(hProcess, allocatedMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // 4. Находим адрес функции LoadLibraryW в библиотеке kernel32.dll
    // Эта функция загружает любую DLL в память процесса
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryW");

    // 5. КУЛЬМИНАЦИЯ: Запускаем удаленный поток в чужом процессе!
    // Мы говорим ему: "Выполни LoadLibraryW и передай ей путь к нашей DLL"
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, allocatedMem, 0, NULL);
    if (hThread == NULL) {
        VirtualFreeEx(hProcess, allocatedMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Ждем, пока DLL загрузится, и убираем за собой мусор (очищаем выделенную память)
    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, allocatedMem, 0, MEM_RELEASE);

    CloseHandle(hThread);
    CloseHandle(hProcess);

    Logger::GetInstance().Log(LogLevel::INFO, L"[ИНЪЕКЦИЯ] Защитная DLL успешно внедрена в PID: " + std::to_wstring(processID));
    return true;
}
