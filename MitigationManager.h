#pragma once
#include <windows.h>
#include <string>

class MitigationManager {
public:
    static MitigationManager& GetInstance();

    // Существующая функция (убивает процесс)
    bool KillDangerousProcess(DWORD pid);

    // НОВАЯ ФУНКЦИЯ: Помещает файл в зашифрованный карантин
    bool QuarantineFile(const std::wstring& filePath);

private:
    MitigationManager();
    ~MitigationManager();
};
