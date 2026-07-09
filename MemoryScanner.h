#pragma once
#include <windows.h>
#include <vector>
#include <string>

class MemoryScanner {
public:
    static MemoryScanner& GetInstance();

    // Главная функция: сканирует память процесса по PID на наличие вредоносной сигнатуры
    bool ScanProcessRAM(DWORD pid, const std::vector<BYTE>& signature, const std::wstring& ruleName);

private:
    MemoryScanner();
    ~MemoryScanner();

    // Вспомогательная функция поиска сигнатуры в байтовом буфере
    bool PatternMatch(const BYTE* data, size_t dataLength, const std::vector<BYTE>& signature);
};
