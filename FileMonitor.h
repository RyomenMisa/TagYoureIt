#pragma once
#include <windows.h>
#include <string>
#include <thread>
#include <atomic>

class FileMonitor {
public:
    static FileMonitor& GetInstance();

    // Запуск мониторинга конкретной папки (например, C:\Temp)
    void Start(const std::wstring& directoryToWatch);
    void Stop();

private:
    FileMonitor();
    ~FileMonitor();

    std::thread monitorThread;
    std::atomic<bool> isRunning;
    HANDLE hDirectory; // Дескриптор (ручка) наблюдаемой папки

    void MonitorLoop();
};
