// unsigned_scanner_qeezy.cpp
// C++17 (MSVC recommended), optimized build flags suggested in build script.
// Author: Made by Qeezy

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <iostream>
#include <filesystem>
#include <vector>
#include <string>
#include <fstream>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <tlhelp32.h>
#include <winternl.h>

#pragma comment(lib, "wintrust")
#pragma comment(lib, "crypt32")
#pragma comment(lib, "ole32")

namespace fs = std::filesystem;

const std::string PROGRAM_NAME = "Unsigned File Scanner";
const std::string AUTHOR = "Made by Qeezy";

// Typedefs for NtQueryInformationProcess (stealth check)
using NtQIP_t = NTSTATUS(WINAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

// --- Anti-debug helpers ----------------------------------------------------
bool IsDebuggerPresentWrapper()
{
    return IsDebuggerPresent() != 0;
}

bool CheckRemoteDebuggerPresentWrapper()
{
    BOOL present = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &present);
    return present != FALSE;
}

bool NtQueryRemoteDebugObjectWinapi()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;
    NtQIP_t NtQueryInformationProcess = (NtQIP_t)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) return false;
    // QueryProcessDebugPort / QueryProcessDebugObjectHandle info
    ULONG_PTR debugPort = 0;
    NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &debugPort, sizeof(debugPort), nullptr);
    if (status == 0 && debugPort != 0) return true;
    return false;
}

bool DetectDebugger()
{
    if (IsDebuggerPresentWrapper()) return true;
    if (CheckRemoteDebuggerPresentWrapper()) return true;
    if (NtQueryRemoteDebugObjectWinapi()) return true;
    // Scan process list for common debugger names (basic)
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                std::wstring name = pe.szExeFile;
                std::transform(name.begin(), name.end(), name.begin(), ::towlower);
                if (name.find(L"ollydbg") != std::wstring::npos ||
                    name.find(L"x64dbg") != std::wstring::npos ||
                    name.find(L"ida64") != std::wstring::npos ||
                    name.find(L"ida") != std::wstring::npos ||
                    name.find(L"windbg") != std::wstring::npos) {
                    CloseHandle(snap);
                    return true;
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }
    return false;
}
// ---------------------------------------------------------------------------

// WinVerifyTrust wrapper: returns true if signature is valid/trusted.
bool IsFileSigned(const std::wstring &filePath)
{
    WINTRUST_FILE_INFO fileInfo;
    memset(&fileInfo, 0, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath.c_str();
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA winTrustData;
    memset(&winTrustData, 0, sizeof(winTrustData));
    winTrustData.cbStruct = sizeof(winTrustData);
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileInfo;
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwStateAction = WTD_STATEACTION_IGNORE;
    winTrustData.dwProvFlags = WTD_REVOCATION_CHECK_NONE; // speed + fewer network checks
    winTrustData.hWVTStateData = NULL;

    LONG status = WinVerifyTrust(NULL, &action, &winTrustData);
    return (status == ERROR_SUCCESS);
}

// Calculate Shannon entropy reading file in chunks
double CalculateEntropy(const std::wstring &filePath)
{
    std::ifstream ifs(filePath, std::ios::binary);
    if (!ifs) return -1.0;

    std::vector<uint64_t> freq(256, 0);
    uint64_t total = 0;
    const size_t BUFSZ = 1 << 20; // 1 MB
    std::vector<char> buf(BUFSZ);

    while (ifs) {
        ifs.read(buf.data(), static_cast<std::streamsize>(BUFSZ));
        std::streamsize r = ifs.gcount();
        if (r <= 0) break;
        for (std::streamsize i = 0; i < r; ++i) {
            unsigned char b = static_cast<unsigned char>(buf[i]);
            freq[b]++;
        }
        total += static_cast<uint64_t>(r);
    }
    ifs.close();
    if (total == 0) return 0.0;

    double ent = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (freq[i] == 0) continue;
        double p = static_cast<double>(freq[i]) / static_cast<double>(total);
        ent += p * std::log2(p);
    }
    ent = -ent;
    return std::round(ent * 10000.0) / 10000.0;
}

// Console color helpers
void SetConsoleColor(WORD attr) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, attr);
}

int main()
{
    // Header
    SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY); // cyan-ish
    std::cout << "=== " << PROGRAM_NAME << " ===\n";
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY); // magenta-ish
    std::cout << AUTHOR << "\n\n";
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    // Anti-debug check
    bool dbg = DetectDebugger();
    if (dbg) {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << "[WARNING] Debugger/analysis environment detected. Continuing anyway.\n\n";
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        // Optional: exit here instead of continuing
        // return 1;
    }

    // Input path
    std::string inputPath;
    std::cout << "Enter the path to scan (ex. C:\\) : ";
    std::getline(std::cin, inputPath);
    if (inputPath.empty()) inputPath = "C:\\";

    fs::path root(inputPath);
    if (!fs::exists(root)) {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cerr << "Path does not exist: " << inputPath << "\nPress Enter to exit...";
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        std::cin.get();
        return 1;
    }

    // Collect files
    std::vector<fs::path> files;
    std::cout << "\n[INFO] Collecting files...\n";
    try {
        for (auto it = fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied);
             it != fs::recursive_directory_iterator(); ++it) {
            try {
                if (!it->is_regular_file()) continue;
                std::string ext = it->path().extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                if (ext == ".exe" || ext == ".dll") {
                    files.push_back(it->path());
                }
            } catch (...) { /* skip */ }
        }
    } catch (const std::exception &e) {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cerr << "Error enumerating files: " << e.what() << "\n";
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    size_t total = files.size();
    std::cout << "[INFO] " << total << " files found. Starting scan...\n\n";

    struct Result { fs::path path; double entropy; };
    std::vector<Result> unsigned_files;

    size_t idx = 0;
    const int barWidth = 40;
    for (const auto &p : files) {
        ++idx;
        // Progress bar
        double perc = (total == 0) ? 100.0 : (100.0 * idx / total);
        int pos = static_cast<int>(barWidth * idx / total);
        std::ostringstream oss;
        oss << "\rScanning: [";
        for (int i = 0; i < barWidth; ++i) {
            if (i < pos) oss << "=";
            else if (i == pos) oss << ">";
            else oss << " ";
        }
        oss << "] " << std::fixed << std::setprecision(1) << perc << "% (" << idx << "/" << total << ")   ";
        std::cout << oss.str();
        std::cout.flush();

        try {
            std::wstring wp = p.wstring();
            bool signed_ok = IsFileSigned(wp);
            if (!signed_ok) {
                double ent = CalculateEntropy(wp);
                unsigned_files.push_back({ p, ent });
            }
        } catch (...) { /* ignore file */ }
    }

    std::cout << std::endl << std::endl;

    SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << "=== RESULTS ===\n";
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    if (!unsigned_files.empty()) {
        for (const auto &r : unsigned_files) {
            SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
            std::cout << "[UNSIGNED] ";
            SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

            std::cout << r.path.string() << " | ";
            if (r.entropy >= 0.0 && r.entropy > 7.5) {
                SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY); // yellow
                std::cout << "Entropy: " << std::fixed << std::setprecision(4) << r.entropy;
                SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            } else if (r.entropy >= 0.0) {
                std::cout << "Entropy: " << std::fixed << std::setprecision(4) << r.entropy;
            } else {
                std::cout << "Entropy: N/A";
            }
            std::cout << "\n";
        }
    } else {
        SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "No unsigned files found.\n";
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    std::cout << "\nPress Enter to exit...";
    std::cin.get();
    return 0;
}
