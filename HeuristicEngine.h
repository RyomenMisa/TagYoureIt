#pragma once
#include <string>
#include <windows.h>

class HeuristicEngine {
public:
    static HeuristicEngine& GetInstance();

    // √лавна€ функци€: постановка диагноза процессу на основе его поведени€
    void AnalyzeProcessLaunch(DWORD pid, const std::wstring& exeName, const std::wstring& fullPath);

private:
    HeuristicEngine();
    ~HeuristicEngine();

    // ‘ункци€ передачи процесса на экстренную изол€цию
    void TriggerMitigation(DWORD pid, const std::wstring& exeName, const std::wstring& fullPath, const std::wstring& diagnosis);
};
