#pragma once
#include <string>
#include <fstream>
#include <mutex>
#include <iostream>

// Перечисление уровней угрозы
enum class LogLevel {
    INFO,
    WARNING,
    ALERT,
    CRITICAL
};

// Класс Логгера (Используем паттерн Синглтон, чтобы логгер был один на всю программу)
class Logger {
public:
    // Получение единственного экземпляра логгера
    static Logger& GetInstance();

    // Главная функция записи
    void Log(LogLevel level, const std::wstring& message);

private:
    Logger();  // Приватный конструктор
    ~Logger(); // Приватный деструктор

    std::wofstream logFile; // Поток для записи в файл
    std::mutex logMutex;    // Замок (мьютекс) для защиты от столкновения потоков

    // Вспомогательная функция для получения текущего времени
    std::wstring GetTimestamp();
    // Вспомогательная функция для конвертации уровня в текст
    std::wstring LevelToString(LogLevel level);
};
