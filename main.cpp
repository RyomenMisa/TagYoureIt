#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include "Logger.h"
#include "ProcessMonitor.h"
#include "FileMonitor.h"
#include "MemoryGuard.h"
#include "NetworkMonitor.h"
#include "ConfigManager.h"
#include <shlobj.h>
#include <fstream>

// Функция для получения пути к Temp
std::wstring GetUniversalTempPath() {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    return std::wstring(tempPath);
}

void DeployHoneypot() {
    wchar_t desktopPath[MAX_PATH];

    // Получаем путь к Рабочему столу
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, desktopPath))) {
        std::wstring honeypotPath = std::wstring(desktopPath) + L"\\crypto_wallet_seed.txt";

        DWORD dwAttrib = GetFileAttributesW(honeypotPath.c_str());
        if (dwAttrib == INVALID_FILE_ATTRIBUTES) {
            std::ofstream outFile(honeypotPath);
            if (outFile.is_open()) {
                outFile << "=== CRYPTO WALLET BACKUP ===\n";
                outFile << "Seed Phrase: abandon ability able about...\n";
                outFile.close();

                // Делаем файл невидимым и системным
                SetFileAttributesW(honeypotPath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

                Logger::GetInstance().Log(LogLevel::INFO, L"[ЛОВУШКА] Стелс-приманка успешно развернута.");
            }
        }
    }
}
int main() {
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);
    std::wcout.imbue(std::locale(""));

    std::wcout << L"=================================================\n";
    std::wcout << L"      TAG, YOU'RE IT // UNIVERSAL EDR AGENT      \n";
    std::wcout << L"=================================================\n\n";

    Logger& logger = Logger::GetInstance();
    ConfigManager& config = ConfigManager::GetInstance();

    // Загружаем конфиги и правила
    config.LoadConfig(L"edr_config.ini");
    config.LoadThreatRules(L"rules.txt");

    // --- АКТИВАЦИЯ ЗАЩИТЫ ПАМЯТИ (HOOKING) ---
    if (MemoryGuard::GetInstance().InstallHooks()) {
        logger.Log(LogLevel::INFO, L"[ЗАЩИТА ПАМЯТИ] Хуки на VirtualAllocEx успешно установлены.");
    }
    else {
        logger.Log(LogLevel::ALERT, L"[ОШИБКА] Не удалось установить хуки защиты памяти!");

    }
    // -----------------------------------------

        // Инициализация логгера и конфига
        Logger::GetInstance().Log(LogLevel::INFO, L"[СИСТЕМА] Запуск ядра EDR...");

        // Автоматически разворачиваем мину-приманку
        DeployHoneypot();
    // 1. Запуск сенсора процессов
    ProcessMonitor& procMonitor = ProcessMonitor::GetInstance();
    procMonitor.Start();
    // Запуск сетевого сенсора
    NetworkMonitor& netMonitor = NetworkMonitor::GetInstance();
    netMonitor.Start();


    // 2. Узнаем универсальный путь и запускаем файловый сенсор
    std::wstring targetZone = GetUniversalTempPath();
    FileMonitor& fileMonitor = FileMonitor::GetInstance();
    fileMonitor.Start(targetZone);

    std::wcout << L"\n[*] ВСЕ СИСТЕМЫ АКТИВНЫ. Агент адаптирован под текущую ОС.\n";
    std::wcout << L"[*] Защищаемая файловая зона: " << targetZone << L"\n";
    std::wcout << L"[*] Для проверки: нажми Win+R, введи %temp% и создай там любой файл.\n";
    std::wcout << L"[*] Для остановки агента нажмите Enter...\n\n";

    // Ждем, пока пользователь не нажмет Enter
    std::cin.get();

    std::wcout << L"\n[*] Корректное завершение работы...\n";

    // Останавливаем потоки
    procMonitor.Stop();
    fileMonitor.Stop();
    netMonitor.Stop();
    // Снимаем хуки, чтобы вернуть Windows в нормальное состояние
    MemoryGuard::GetInstance().RemoveHooks();

    return 0;
}
