#define NOMINMAX
#include <windows.h>
#include <winhttp.h>
#include <iphlpapi.h>
#include <wincrypt.h>
#include <iostream>
#include <thread>
#include <atomic>
#include <immintrin.h>
#include <cstdint>
#include <limits>
#include <string>
#include <chrono>
#include "syscalls.h"
#pragma comment(linker, "/LTCG")
#pragma comment(lib, "user32.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

DWORD pid;
uintptr_t address;
DWORD nakl;

std::atomic<bool> running(false);
std::atomic<bool> shouldExit(false);
std::atomic<bool> hasBought(false);

POINT BTN, CONF, UP;

LONG axBTN = 0, ayBTN = 0;
LONG axCONF = 0, ayCONF = 0;
LONG axUP = 0, ayUP = 0;

int upd_time = 0;

constexpr const char* DEV_KEY = "fyzov";

static inline void fastClick(LONG ax, LONG ay) noexcept {
    INPUT in[2]{};

    in[0].type = INPUT_MOUSE;
    in[0].mi.dx = ax;
    in[0].mi.dy = ay;
    in[0].mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE_NOCOALESCE;

    in[1].type = INPUT_MOUSE;
    in[1].mi.dwFlags = MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_LEFTUP;

    SendInput(2, in, sizeof(INPUT));
}


inline void set_thread_affinity_for_core(int coreIndex) {
    if (coreIndex >= 0)
        SetThreadAffinityMask(GetCurrentThread(), 1ull << coreIndex);
}

void readerThread(HANDLE hProcess, int readerCore) {
    if (readerCore >= 0)
        set_thread_affinity_for_core(readerCore);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

    uint64_t value = 0;

    INPUT inBuy[2]{};
    INPUT inConf[2]{};
    INPUT inUp[2]{};


    inBuy[0].type = INPUT_MOUSE;
    inBuy[0].mi.dx = axBTN;
    inBuy[0].mi.dy = ayBTN;
    inBuy[0].mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE_NOCOALESCE;

    inBuy[1].type = INPUT_MOUSE;
    inBuy[1].mi.dwFlags = MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_LEFTUP;


    inConf[0].type = INPUT_MOUSE;
    inConf[0].mi.dx = axCONF;
    inConf[0].mi.dy = ayCONF;
    inConf[0].mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE_NOCOALESCE;

    inConf[1].type = INPUT_MOUSE;
    inConf[1].mi.dwFlags = MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_LEFTUP;

    inUp[0].type = INPUT_MOUSE;
    inUp[0].mi.dx = axUP;
    inUp[0].mi.dy = ayUP;
    inUp[0].mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE_NOCOALESCE;

    inUp[1].type = INPUT_MOUSE;
    inUp[1].mi.dwFlags = MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_LEFTUP;

    while (!shouldExit.load(std::memory_order_relaxed)) {
        if (!running.load(std::memory_order_relaxed)) {
            _mm_pause();
            continue;
        }

        Sw3NtReadVirtualMemory(hProcess, (PVOID)address, &value, sizeof(value), nullptr);
        if (value >= nakl && !hasBought.load(std::memory_order_relaxed)) {
            SendInput(2, inBuy, sizeof(INPUT));
            SendInput(2, inConf, sizeof(INPUT));
            SendInput(2, inUp, sizeof(INPUT));

            hasBought.store(true, std::memory_order_relaxed);
        }
        else if (value < nakl) {
            hasBought.store(false, std::memory_order_relaxed);
        }

        _mm_pause();
    }
}


void Updater() {
    while (!shouldExit.load()) {
        if (!running.load()) {
            _mm_pause();
            continue;
        }
        fastClick(axUP, ayUP);
        for (int i = 0; i < upd_time * 10 && !shouldExit.load(); ++i)
            Sleep(10);
    }
}

void hotkeyThread() {
    while (!shouldExit.load()) {
        if (GetAsyncKeyState(VK_F6) & 0x8000) {
            std::cout << "[HOTKEY] Start (F6)\n";
            running.store(true);
            Sleep(200);
        }
        if (GetAsyncKeyState(VK_F7) & 0x8000) {
            std::cout << "[HOTKEY] Stop (F7)\n";
            running.store(false);
            Sleep(200);
        }
        if (GetAsyncKeyState(VK_F8) & 0x8000) {
            std::cout << "[HOTKEY] Exit (F8)\n";
            shouldExit.store(true);
            running.store(false);
            break;
        }
        Sleep(200);
    }
}

int main() {
    SetProcessDPIAware();
    set_thread_affinity_for_core(0);
    std::string enteredKey;
    std::cout << "Enter access key: ";
    std::getline(std::cin, enteredKey);

    if (enteredKey != DEV_KEY) {
        std::cerr << "[ACCESS DENIED] Invalid key!\n";
        ExitProcess(0);
    }
    std::cout << "[OK] Key verified.\n\n";

    std::cout << "Enter PID: ";
    std::cin >> pid;

    std::cout << "Address (hex): 0x";
    std::cin >> std::hex >> address;
    std::cin >> std::dec;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    std::cout << "Stickers: ";
    std::cin >> nakl;

    std::cout << "Buy button (x y): ";
    std::cin >> BTN.x >> BTN.y;

    std::cout << "Confirm button (x y): ";
    std::cin >> CONF.x >> CONF.y;

    std::cout << "Update button (x y): ";
    std::cin >> UP.x >> UP.y;

    std::cout << "Interval between updating (sec): ";
    std::cin >> upd_time;

    int sx = GetSystemMetrics(SM_CXSCREEN);
    int sy = GetSystemMetrics(SM_CYSCREEN);

    axBTN = (LONG)((BTN.x * 65535LL) / (sx - 1));
    ayBTN = (LONG)((BTN.y * 65535LL) / (sy - 1));

    axCONF = (LONG)((CONF.x * 65535LL) / (sx - 1));
    ayCONF = (LONG)((CONF.y * 65535LL) / (sy - 1));

    axUP = (LONG)((UP.x * 65535LL) / (sx - 1));
    ayUP = (LONG)((UP.y * 65535LL) / (sy - 1));

    HANDLE hProcess = NULL;
    CLIENT_ID cid = { (HANDLE)pid, 0 };
    OBJECT_ATTRIBUTES objAttr{};
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    NTSTATUS status = Sw3NtOpenProcess(
        &hProcess,
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        &objAttr,
        &cid
    );

    if (!NT_SUCCESS(status) || !hProcess) {
        std::cerr << "[ERR] Sw3NtOpenProcess failed for pid " << pid
            << " (NTSTATUS=0x" << std::hex << status << ")\n";
        return 1;
    }

    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);

    std::cout << "[OK] Ready. F6 - START, F7 - STOP, F8 - EXIT\n";
    HWND hConsole = GetConsoleWindow();
    SetWindowPos(hConsole, HWND_TOPMOST, 0, 0, 0, 0,
        SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    int readerCore = (si.dwNumberOfProcessors > 1) ? 2 : 0;

    running.store(false);
    shouldExit.store(false);

    std::thread tReader(readerThread, hProcess, readerCore);
    std::thread tUpdater(Updater);
    std::thread tHotkey(hotkeyThread);

    tReader.join();
    tUpdater.join();
    tHotkey.join();

    CloseHandle(hProcess);
    return 0;
}