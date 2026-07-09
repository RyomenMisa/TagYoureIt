#include "MemoryScanner.h"
#include "Logger.h"
#include "MitigationManager.h"

MemoryScanner& MemoryScanner::GetInstance() {
    static MemoryScanner instance;
    return instance;
}

MemoryScanner::MemoryScanner() {}
MemoryScanner::~MemoryScanner() {}

// Быстрый алгоритм поиска подстроки в массиве байтов
bool MemoryScanner::PatternMatch(const BYTE* data, size_t dataLength, const std::vector<BYTE>& signature) {
    if (signature.empty() || dataLength < signature.size()) return false;

    for (size_t i = 0; i <= dataLength - signature.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < signature.size(); ++j) {
            if (data[i + j] != signature[j]) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

bool MemoryScanner::ScanProcessRAM(DWORD pid, const std::vector<BYTE>& signature, const std::wstring& ruleName) {
    // 1. Открываем процесс с правами на чтение памяти и получение информации
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) return false;

    unsigned char* address = nullptr;
    MEMORY_BASIC_INFORMATION mbi;

    // 2. Цикл обхода страниц памяти (VirtualQueryEx возвращает инфу о каждом блоке памяти)
    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) != 0) {
        // Нас интересует только выделенная (MEM_COMMIT) и читаемая память (PAGE_READWRITE или PAGE_EXECUTE_READWRITE)
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE)) {

            std::vector<BYTE> buffer(mbi.RegionSize);
            SIZE_T bytesRead;

            // 3. Выкачиваем кусок памяти процесса в наш буфер
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead)) {
                // 4. Запускаем поиск сигнатуры внутри этого куска
                if (PatternMatch(buffer.data(), bytesRead, signature)) {
                    Logger::GetInstance().Log(LogLevel::CRITICAL,
                        L"[YARA ТРЕВОГА] В оперативной памяти PID: " + std::to_wstring(pid) +
                        L" обнаружена сигнатура угрозы: " + ruleName);

                    // Обнаружен скрытый паразит! Уничтожаем процесс
                    MitigationManager::GetInstance().KillDangerousProcess(pid);
                    CloseHandle(hProcess);
                    return true;
                }
            }
        }
        // Переходим к следующему адресу памяти
        address += mbi.RegionSize;
    }

    CloseHandle(hProcess);
    return false;
}