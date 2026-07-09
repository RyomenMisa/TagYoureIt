#include "HeuristicEngine.h"
#include "Logger.h"
#include "ConfigManager.h"
#include "MitigationManager.h"
#include "Injector.h"
#include <algorithm>
#include <tlhelp32.h>

HeuristicEngine& HeuristicEngine::GetInstance() {
    static HeuristicEngine instance;
    return instance;
}

HeuristicEngine::HeuristicEngine() {}
HeuristicEngine::~HeuristicEngine() {}

std::wstring GetSensorDllPath() {
    wchar_t buffer[MAX_PATH];
    GetModuleFileNameW(NULL, buffer, MAX_PATH);
    std::wstring exePath(buffer);
    size_t pos = exePath.find_last_of(L"\\/");
    return exePath.substr(0, pos + 1) + L"EdrSensor.dll";
}

std::wstring GetProcessNameByID(DWORD pid) {
    std::wstring name = L"unknown";
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnapshot, &processEntry)) {
            do {
                if (processEntry.th32ProcessID == pid) {
                    name = processEntry.szExeFile;
                    break;
                }
            } while (Process32NextW(hSnapshot, &processEntry));
        }
        CloseHandle(hSnapshot);
    }
    return name;
}

void HeuristicEngine::AnalyzeProcessLaunch(DWORD pid, const std::wstring& exeName, const std::wstring& fullPath) {
    std::wstring exeLower = exeName;
    std::transform(exeLower.begin(), exeLower.end(), exeLower.begin(), ::tolower);
    std::wstring pathLower = fullPath;
    std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::tolower);

    std::wstring dllPath = GetSensorDllPath();
    Injector::GetInstance().InjectDLL(pid, dllPath);

    Logger::GetInstance().Log(LogLevel::INFO, L"[ЭВРИСТИКА] Начался анализ процесса: " + exeName);

    int riskScore = 0;
    std::wstring diagnosis = L"Поведение в пределах нормы";

    if (pathLower.find(L"\\temp\\") != std::wstring::npos ||
        pathLower.find(L"\\appdata\\") != std::wstring::npos) {
        riskScore += 40;
        diagnosis = L"[Запуск из ненадежной директории]";
    }

    // Извлекаем PPID и имя родителя
    DWORD ppid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnapshot, &processEntry)) {
            do {
                if (processEntry.th32ProcessID == pid) {
                    ppid = processEntry.th32ParentProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot, &processEntry));
        }
        CloseHandle(hSnapshot);
    }

    std::wstring parentName = GetProcessNameByID(ppid);
    std::wstring parentLower = parentName;
    std::transform(parentLower.begin(), parentLower.end(), parentLower.begin(), ::tolower);


    const auto& rules = ConfigManager::GetInstance().GetBehaviorRules();
    Logger::GetInstance().Log(LogLevel::INFO, L"[ЭВРИСТИКА] Загружено правил для проверки: " + std::to_wstring(rules.size()));

    // ==========================================
    // УМНАЯ И ГИБКАЯ ПРОВЕРКА ПРАВИЛ
    // ==========================================
    for (const auto& rule : rules) {
        // 1. Готовим имя потомка (Child)
        std::wstring ruleChildLower = rule.childName;
        std::transform(ruleChildLower.begin(), ruleChildLower.end(), ruleChildLower.begin(), ::tolower);
        ruleChildLower.erase(std::remove(ruleChildLower.begin(), ruleChildLower.end(), L'\r'), ruleChildLower.end());
        ruleChildLower.erase(std::remove(ruleChildLower.begin(), ruleChildLower.end(), L'\n'), ruleChildLower.end());
        ruleChildLower.erase(std::remove(ruleChildLower.begin(), ruleChildLower.end(), L' '), ruleChildLower.end());

        if (ruleChildLower.empty()) continue;

        // 2. Готовим имя родителя (Parent) из правила
        std::wstring ruleParentLower = rule.parentName;
        std::transform(ruleParentLower.begin(), ruleParentLower.end(), ruleParentLower.begin(), ::tolower);
        ruleParentLower.erase(std::remove(ruleParentLower.begin(), ruleParentLower.end(), L'\r'), ruleParentLower.end());
        ruleParentLower.erase(std::remove(ruleParentLower.begin(), ruleParentLower.end(), L'\n'), ruleParentLower.end());
        ruleParentLower.erase(std::remove(ruleParentLower.begin(), ruleParentLower.end(), L' '), ruleParentLower.end());

        // 3. Сверяем потомка (Цель)
        bool childMatch = (exeLower == ruleChildLower || pathLower.find(ruleChildLower) != std::wstring::npos);

        // 4. Сверяем родителя (ЕСЛИ ОН ВООБЩЕ УКАЗАН)
        bool parentMatch = true; // По умолчанию считаем, что родитель не важен
        if (!ruleParentLower.empty()) {
            // Если в правиле прописан родитель, он ОБЯЗАН совпасть с реальным родителем
            parentMatch = (parentLower == ruleParentLower);
        }

        // 5. Выносим приговор
        if (childMatch && parentMatch) {
            riskScore += (rule.score > 0) ? rule.score : 100;
            std::wstring rName = rule.ruleName.empty() ? L"Угроза" : rule.ruleName;
            diagnosis = L"[ДЕТЕКТ: " + rName + L"] Опасная цепочка процессов!";
            break;
        }
    }

    if (riskScore > 0) {
        LogLevel level = (riskScore >= ConfigManager::GetInstance().GetRiskThreshold()) ? LogLevel::ALERT : LogLevel::WARNING;
        Logger::GetInstance().Log(level, L"[EDR АНАЛИЗ] " + exeName + L" | Риск: " + std::to_wstring(riskScore) + L" | Вердикт: " + diagnosis);
    }
    else {
        Logger::GetInstance().Log(LogLevel::INFO, L"[ЭВРИСТИКА] Угрозы не найдены. " + exeName + L" признан чистым.");
    }

    if (riskScore >= ConfigManager::GetInstance().GetRiskThreshold()) {
        TriggerMitigation(pid, exeName, fullPath, diagnosis);
    }
}

void HeuristicEngine::TriggerMitigation(DWORD pid, const std::wstring& exeName, const std::wstring& fullPath, const std::wstring& diagnosis) {
    Logger::GetInstance().Log(LogLevel::CRITICAL,
        L"[EDR ПРИГОВОР] ПРИСТУПАЮ К ЛИКВИДАЦИИ: " + exeName + L" (PID: " + std::to_wstring(pid) + L"). Причина: " + diagnosis);

    MitigationManager::GetInstance().KillDangerousProcess(pid);
}