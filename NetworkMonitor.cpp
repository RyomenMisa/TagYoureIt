#include "NetworkMonitor.h"
#include "Logger.h"
#include "MitigationManager.h"
#include <vector>

NetworkMonitor& NetworkMonitor::GetInstance() {
    static NetworkMonitor instance;
    return instance;
}

NetworkMonitor::NetworkMonitor() : isRunning(false) {}

NetworkMonitor::~NetworkMonitor() {
    Stop();
}

void NetworkMonitor::Start() {
    if (!isRunning) {
        isRunning = true;
        monitorThread = std::thread(&NetworkMonitor::MonitorLoop, this);
        Logger::GetInstance().Log(LogLevel::INFO, L"[СЕТЕВОЙ СЕНСОР] Модуль телеметрии сети успешно запущен.");
    }
}

void NetworkMonitor::Stop() {
    if (isRunning) {
        isRunning = false;
        if (monitorThread.joinable()) {
            monitorThread.join();
        }
    }
}

void NetworkMonitor::MonitorLoop() {
    while (isRunning) {
        DWORD size = 0;
        GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

        std::vector<BYTE> buffer(size);

        if (GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            PMIB_TCPTABLE_OWNER_PID pTcpTable = (PMIB_TCPTABLE_OWNER_PID)buffer.data();

            for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
                DWORD pid = pTcpTable->table[i].dwOwningPid;
                DWORD state = pTcpTable->table[i].dwState;
                DWORD remotePort = ntohs((u_short)pTcpTable->table[i].dwRemotePort);

                if (state == 5) {
                    if (remotePort == 3333 || remotePort == 4444 || remotePort == 14444) {
                        Logger::GetInstance().Log(LogLevel::CRITICAL,
                            L"[СЕТЕВАЯ АНОМАЛИЯ] Подозрительный порт майнера/C2! PID: " + std::to_wstring(pid) +
                            L" | Порт: " + std::to_wstring(remotePort));

                        MitigationManager::GetInstance().KillDangerousProcess(pid);
                    }
                }
            }
        }
        Sleep(2000);
    }
}