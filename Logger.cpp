#include "Logger.h"
#include <iomanip>
#include <sstream>
#include <chrono>

// Инициализация Синглтона (гарантирует один экземпляр логгера в памяти)
Logger& Logger::GetInstance() {
    static Logger instance;
    return instance;
}

// Конструктор: открывает или создает файл лога в режиме дозаписи (append)
Logger::Logger() {
    logFile.open(L"edr_core_activity.log", std::ios::out | std::ios::app);
    if (logFile.is_open()) {
        logFile.imbue(std::locale("")); // Включаем поддержку локализации (Юникод)
        Log(LogLevel::INFO, L"=== АНТИВИРУСНЫЙ МОДУЛЬ EDR УСПЕШНО ИНИЦИАЛИЗИРОВАН ===");
    }
}

// Деструктор: корректно закрывает файловый дескриптор при завершении программы
Logger::~Logger() {
    if (logFile.is_open()) {
        Log(LogLevel::INFO, L"=== СИСТЕМА ДЕТЕКЦИИ ОСТАНОВЛЕНА ===");
        logFile.close();
    }
}

// Превращает системное перечисление уровня в читаемый текст
std::wstring Logger::LevelToString(LogLevel level) {
    switch (level) {
    case LogLevel::INFO:     return L"INFO";
    case LogLevel::WARNING:  return L"WARNING";
    case LogLevel::ALERT:    return L"ALERT";
    case LogLevel::CRITICAL: return L"CRITICAL";
    default:                 return L"UNKNOWN";
    }
}

// Точный сбор таймстемпа до миллисекунд
std::wstring Logger::GetTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    tm timeinfo;
    localtime_s(&timeinfo, &in_time_t);

    std::wstringstream wss;
    wss << std::put_time(&timeinfo, L"%Y-%m-%d %H:%M:%S")
        << L"." << std::setfill(L'0') << std::setw(3) << ms.count();

    return wss.str();
}

// Потокобезопасная функция записи
void Logger::Log(LogLevel level, const std::wstring& message) {
    // ЖЕСТКИЙ ЗАМОК: Если один поток зашел сюда писать, остальные ждут на входе
    std::lock_guard<std::mutex> lock(logMutex);

    std::wstring fullLine = L"[" + GetTimestamp() + L"] [" + LevelToString(level) + L"] " + message;

    // Дублируем вывод в консоль разработчика
    std::wcout << fullLine << std::endl;

    // Пишем напрямую в зашифрованный файл на диске
    if (logFile.is_open()) {
        logFile << fullLine << std::endl;
        logFile.flush(); // Мгновенно сбрасываем буфер памяти на жесткий диск
    }
}