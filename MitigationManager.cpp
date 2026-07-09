#include "MitigationManager.h"
#include "Logger.h"
#include <windows.h>
#include <string>

MitigationManager& MitigationManager::GetInstance() {
    static MitigationManager instance;
    return instance;
}

MitigationManager::MitigationManager() {}
MitigationManager::~MitigationManager() {}

bool MitigationManager::KillDangerousProcess(DWORD pid) {
    // 1. Вытаскиваем путь к файлу ПОКА процесс еще жив
    std::wstring exePath = L"";
    HANDLE hProcessPath = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcessPath) {
        wchar_t pathBuf[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcessPath, 0, pathBuf, &size)) {
            exePath = pathBuf;
        }
        CloseHandle(hProcessPath);
    }

    // 2. Открываем процесс для убийства
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess == NULL) {
        return false;
    }

    // 3. Безжалостно убиваем
    bool result = TerminateProcess(hProcess, 1);
    CloseHandle(hProcess);

    if (result) {
        Logger::GetInstance().Log(LogLevel::INFO, L"[МИТИГАЦИЯ] Процесс PID: " + std::to_wstring(pid) + L" был успешно уничтожен.");

        // 4. Если мы смогли узнать путь к файлу — отправляем труп в карантин
        if (!exePath.empty()) {
            Sleep(500); // Даем системе 500мс, чтобы она сняла блокировку с убитого файла
            QuarantineFile(exePath);
        }
    }
    return result;
}

// ЧИСТЫЙ МОДУЛЬ КАРАНТИНА (С телепортацией в папку EDR)
bool MitigationManager::QuarantineFile(const std::wstring& filePath) {
    // 1. Вытаскиваем только имя файла из его полного пути (например, LabRat.exe)
    size_t pos = filePath.find_last_of(L"\\/");
    std::wstring fileName = (pos != std::wstring::npos) ? filePath.substr(pos + 1) : filePath;

    // 2. Узнаем, откуда запущен антивирус (папка EDR_GUI)
    wchar_t buffer[MAX_PATH];
    GetModuleFileNameW(NULL, buffer, MAX_PATH);
    std::wstring exePath(buffer);
    size_t exePos = exePath.find_last_of(L"\\/");
    std::wstring quarantineDir = exePath.substr(0, exePos + 1);

    // 3. Формируем путь для камеры хранения: Папка_Антивируса + Имя_Вируса + .quarantine
    std::wstring quarantinePath = quarantineDir + fileName + L".quarantine";

    // 4. Перемещаем файл из папки пользователя в защищенную зону!
    if (MoveFileW(filePath.c_str(), quarantinePath.c_str())) {
        Logger::GetInstance().Log(LogLevel::INFO, L"[КАРАНТИН] Угроза нейтрализована. Файл телепортирован в изолятор: " + quarantinePath);
        return true;
    }
    else {
        Logger::GetInstance().Log(LogLevel::WARNING, L"[КАРАНТИН] Ошибка переноса. Код системы: " + std::to_wstring(GetLastError()));
        return false;
    }
}