#include "FileMonitor.h"
#include "Logger.h"
#include <vector>

FileMonitor& FileMonitor::GetInstance() {
    static FileMonitor instance;
    return instance;
}

FileMonitor::FileMonitor() : isRunning(false), hDirectory(INVALID_HANDLE_VALUE) {}

FileMonitor::~FileMonitor() {
    Stop();
}

void FileMonitor::Start(const std::wstring& directoryToWatch) {
    if (!isRunning) {
        // Открываем папку с правами на чтение её изменений
        hDirectory = CreateFileW(
            directoryToWatch.c_str(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS, // Обязательный флаг для папок
            NULL
        );

        if (hDirectory == INVALID_HANDLE_VALUE) {
            Logger::GetInstance().Log(LogLevel::CRITICAL, L"[СЕНСОР ФАЙЛОВ] Ошибка доступа к директории: " + directoryToWatch);
            return;
        }

        isRunning = true;
        monitorThread = std::thread(&FileMonitor::MonitorLoop, this);
        Logger::GetInstance().Log(LogLevel::INFO, L"[СЕНСОР ФАЙЛОВ] Начат мониторинг зоны: " + directoryToWatch);
    }
}

void FileMonitor::Stop() {
    if (isRunning) {
        isRunning = false;
        if (hDirectory != INVALID_HANDLE_VALUE) {
            // Принудительно прерываем блокирующую операцию чтения
            CancelIoEx(hDirectory, NULL);
            CloseHandle(hDirectory);
            hDirectory = INVALID_HANDLE_VALUE;
        }
        if (monitorThread.joinable()) {
            monitorThread.join();
        }
        Logger::GetInstance().Log(LogLevel::INFO, L"[СЕНСОР ФАЙЛОВ] Мониторинг остановлен.");
    }
}

void FileMonitor::MonitorLoop() {
    const DWORD bufferSize = 1024 * 64; // Буфер на 64 КБ для хранения логов Windows
    std::vector<BYTE> buffer(bufferSize);
    DWORD bytesReturned = 0;

    while (isRunning) {
        // Запрашиваем у Windows список всех изменений в папке
        BOOL result = ReadDirectoryChangesW(
            hDirectory,
            buffer.data(),
            bufferSize,
            TRUE, // Следить за подпапками
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE, // Ловим создание и изменение файлов
            &bytesReturned,
            NULL,
            NULL
        );

        if (result && bytesReturned > 0) {
            FILE_NOTIFY_INFORMATION* fileInfo = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer.data());

            do {
                // Извлекаем имя файла (оно возвращается без нуль-терминатора, поэтому высчитываем длину)
                std::wstring fileName(fileInfo->FileName, fileInfo->FileNameLength / sizeof(WCHAR));

                if (fileInfo->Action == FILE_ACTION_ADDED) {
                    Logger::GetInstance().Log(LogLevel::WARNING, L"[ФАЙЛОВАЯ АНОМАЛИЯ] В защищенной зоне СОЗДАН файл: " + fileName);
                }
                else if (fileInfo->Action == FILE_ACTION_MODIFIED) {
                    Logger::GetInstance().Log(LogLevel::INFO, L"[ФАЙЛОВАЯ АКТИВНОСТЬ] Изменен файл: " + fileName);
                }

                // Переходим к следующей записи в буфере (если файлов изменилось несколько за раз)
                if (fileInfo->NextEntryOffset == 0) break;
                fileInfo = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(reinterpret_cast<BYTE*>(fileInfo) + fileInfo->NextEntryOffset);

            } while (true);
        }
    }
}