#pragma once
#include <windows.h>
#include <string>

class Injector {
public:
    static Injector& GetInstance();

    // Функция, которая проводит саму инъекцию
    bool InjectDLL(DWORD processID, const std::wstring& dllPath);

private:
    Injector();
    ~Injector();
};

