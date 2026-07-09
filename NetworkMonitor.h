#pragma once

#define WIN32_LEAN_AND_MEAN 

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <thread>
#include <atomic>
#include <string>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

class NetworkMonitor {
public:
    static NetworkMonitor& GetInstance();
    void Start();
    void Stop();

private:
    NetworkMonitor();
    ~NetworkMonitor();

    void MonitorLoop();

    std::atomic<bool> isRunning;
    std::thread monitorThread;
};