#include "MemoryScanner.h"
#include "ProcessMonitor.h"
#include "Logger.h"
#include "ConfigManager.h"
#include "HeuristicEngine.h"
#include <tlhelp32.h>

ProcessMonitor& ProcessMonitor::GetInstance() {
    static ProcessMonitor instance;
    return instance;
}

ProcessMonitor::ProcessMonitor() : isRunning(false) {}

ProcessMonitor::~ProcessMonitor() {
    Stop();
}

void ProcessMonitor::Start() {
    if (!isRunning) {
        isRunning = true;
        monitorThread = std::thread(&ProcessMonitor::MonitorLoop, this);
        Logger::GetInstance().Log(LogLevel::INFO, L"Сенсор телеметрии процессов [Process Monitor] успешно запущен.");
    }
}

void ProcessMonitor::Stop() {
    if (isRunning) {
        isRunning = false;
        if (monitorThread.joinable()) {
            monitorThread.join();
        }
        Logger::GetInstance().Log(LogLevel::INFO, L"Сенсор телеметрии процессов остановлен.");
    }
}

std::wstring ProcessMonitor::GetProcessPath(DWORD processID) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processID);
    if (hProcess == NULL) return L"";

    wchar_t buffer[MAX_PATH];
    DWORD bufferSize = MAX_PATH;
    std::wstring path = L"";

    if (QueryFullProcessImageNameW(hProcess, 0, buffer, &bufferSize)) {
        path = buffer;
    }
    CloseHandle(hProcess);
    return path;
}

void ProcessMonitor::MonitorLoop() {
    // ПЕРВИЧНОЕ НАПОЛНЕНИЕ БАЗЫ
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot, &processEntry)) {
            do {
                if (processEntry.th32ProcessID == 0) continue;
                knownProcesses[processEntry.th32ProcessID] = processEntry.szExeFile;
            } while (Process32NextW(hSnapshot, &processEntry));
        }
        CloseHandle(hSnapshot);
    }

    // БЕСКОНЕЧНЫЙ ДОЗОР
    while (isRunning) {
        hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W processEntry;
            processEntry.dwSize = sizeof(PROCESSENTRY32W);

            std::map<DWORD, std::wstring> currentProcesses;

            if (Process32FirstW(hSnapshot, &processEntry)) {
                do {
                    if (processEntry.th32ProcessID == 0) continue;

                    DWORD pid = processEntry.th32ProcessID;
                    std::wstring exeName = processEntry.szExeFile;

                    currentProcesses[pid] = exeName;

                    // ДИФФЕРЕНЦИАЛЬНЫЙ АНАЛИЗ: Засекли новый процесс!
                    if (knownProcesses.find(pid) == knownProcesses.end()) {
                        std::wstring fullPath = GetProcessPath(pid);

                        if (ConfigManager::GetInstance().IsWhitelisted(exeName)) {
                            Logger::GetInstance().Log(LogLevel::INFO,
                                L"[СЕНСОР] Пропущен доверенный процесс: " + exeName +
                                L" (PID: " + std::to_wstring(pid) + L") [Белый список]");
                        }
                        else {
                            // 1. Фиксируем и логируем запуск
                            std::wstring logMessage = L"[ТЕЛЕМЕТРИЯ] Обнаружен запуск: " + exeName +
                                L" | PID: " + std::to_wstring(pid) +
                                L" | PPID: " + std::to_wstring(processEntry.th32ParentProcessID) +
                                L" | Путь: " + (fullPath.empty() ? L"Доступ ограничен (SYSTEM/Защищен)" : fullPath);

                            Logger::GetInstance().Log(LogLevel::WARNING, logMessage);

                            // 2. МОЗГ: Отдаем процесс Эвристическому движку
                            // Теперь HeuristicEngine сам сверит его с rules.txt и убьет любую угрозу
                            HeuristicEngine::GetInstance().AnalyzeProcessLaunch(pid, exeName, fullPath);

                            // 3. ДОПОЛНИТЕЛЬНО: YARA-сканирование памяти в фоне
                            std::thread([pid]() {
                                Sleep(2000);
                                std::string targetStr = "EVIL_HACKER_MALWARE";
                                std::vector<BYTE> signature(targetStr.begin(), targetStr.end());

                                MemoryScanner::GetInstance().ScanProcessRAM(pid, signature, L"Win.Trojan.GenericMemoryPattern");
                                }).detach();
                        }
                    }

                } while (Process32NextW(hSnapshot, &processEntry));
            }
            CloseHandle(hSnapshot);
            knownProcesses = currentProcesses;
        }
        Sleep(100);
    }
}