#pragma once
#include <windows.h>
#include <string>
#include <map>
#include <thread>
#include <atomic>

class ProcessMonitor {
public:
    static ProcessMonitor& GetInstance();

    // Запуск фонового мониторинга
    void Start();
    // Корректная остановка фонового потока
    void Stop();

private:
    ProcessMonitor();
    ~ProcessMonitor();

    std::thread monitorThread;      // Поток, в котором крутится радар
    std::atomic<bool> isRunning;    // Атомарный флаг состояния потока

    // Карта для хранения уже известных процессов (PID -> Имя файла)
    std::map<DWORD, std::wstring> knownProcesses;

    // Главный рабочий цикл сенсора
    void MonitorLoop();

    // Внутренняя утилита для получения реального пути к файлу на диске
    std::wstring GetProcessPath(DWORD processID);
};
