//------------------------------------------------------------------------------
// compile command: cl.exe /Ox /Zi /EHsc IR.cc
//------------------------------------------------------------------------------

#include <Windows.h>
#include <shellapi.h>

#include <SetupAPI.h>
#include <cfgmgr32.h>
#include <fcntl.h>
#include <hidsdi.h>
#include <io.h>
#include <atomic>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "hid.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

BOOL g_running = true;
HANDLE g_logFile = INVALID_HANDLE_VALUE;
HWND g_hWnd = NULL;
NOTIFYICONDATAW g_nid = {};

const USAGE HID_IR_USAGE_PAGE = 0xFF00;
const USAGE HID_IR_USAGE_ID = 0x1;
const USHORT HID_IR_VENDOR_ID = 0x5131;
const USHORT HID_IR_PRODUCT_ID = 0x2019;
const int SCAN_INTERVAL_S = 10;
const int READ_INTERVAL_MS = 500;
const int WAIT_TIMEOUT_MS = 3000;
const DWORD MAX_LOG_FILE_SIZE = 1 * 1024 * 1024;
const int MAX_LOG_KEPT_LINES = 3000;

#define WM_TRAYICON (WM_USER + 1)
#define ID_TRAY_EXIT 1001
#define ID_TRAY_SHOW_LOG 1002
#define ID_TRAY_AUTOSTART 1003

#define AUTOSTART_REG_KEY L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
#define AUTOSTART_REG_VALUE L"IRReceiver"

#define LOG_FILENAME L"IR.log"

void TrimLogFile() {
  if (GetFileAttributesW(LOG_FILENAME) == INVALID_FILE_ATTRIBUTES) {
    return;
  }

  HANDLE hFile = CreateFileW(LOG_FILENAME, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE) {
    return;
  }

  DWORD fileSize = GetFileSize(hFile, NULL);
  if (fileSize == INVALID_FILE_SIZE || fileSize < MAX_LOG_FILE_SIZE) {
    CloseHandle(hFile);
    return;
  }

  DWORD bytesRead;
  std::vector<char> buffer(fileSize);
  if (!ReadFile(hFile, buffer.data(), fileSize, &bytesRead, NULL)) {
    CloseHandle(hFile);
    return;
  }
  CloseHandle(hFile);

  std::string content(buffer.data(), bytesRead);
  std::vector<std::string> lines;
  std::stringstream ss(content);
  std::string line;

  while (std::getline(ss, line)) {
    if (!line.empty()) {
      line.erase(line.find_last_not_of("\r\n") + 1);
      lines.push_back(line);
    }
  }

  if (lines.size() > MAX_LOG_KEPT_LINES) {
    lines.erase(lines.begin(), lines.end() - MAX_LOG_KEPT_LINES);
  }

  HANDLE hWriteFile =
      CreateFileW(LOG_FILENAME, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hWriteFile != INVALID_HANDLE_VALUE) {
    for (const auto& line : lines) {
      std::string lineWithNewline = line + "\r\n";
      DWORD bytesWritten;
      WriteFile(hWriteFile, lineWithNewline.c_str(), lineWithNewline.length(),
                &bytesWritten, NULL);
    }
    FlushFileBuffers(hWriteFile);
    CloseHandle(hWriteFile);
  }
}

void WriteLog(const std::wstring& message) {
  SYSTEMTIME st;
  GetLocalTime(&st);

  wchar_t timeStr[64];
  swprintf_s(timeStr, L"[%04d-%02d-%02d %02d:%02d:%02d] ", st.wYear, st.wMonth,
             st.wDay, st.wHour, st.wMinute, st.wSecond);

  std::wstring fullMessage = timeStr + message + L"\r\n";

  int utf8Size = WideCharToMultiByte(CP_UTF8, 0, fullMessage.c_str(), -1, NULL,
                                     0, NULL, NULL);
  if (utf8Size > 0) {
    std::vector<char> utf8Buffer(utf8Size);
    WideCharToMultiByte(CP_UTF8, 0, fullMessage.c_str(), -1, utf8Buffer.data(),
                        utf8Size, NULL, NULL);

    DWORD bytesWritten;
    WriteFile(g_logFile, utf8Buffer.data(), utf8Size - 1, &bytesWritten, NULL);
    FlushFileBuffers(g_logFile);
  }
}

struct HidDeviceInfo {
  HANDLE hDevice = INVALID_HANDLE_VALUE;
  DWORD inputReportByteLength = 0;
};

HidDeviceInfo FindTargetDeviceImpl() {
  HidDeviceInfo deviceInfo;

  GUID hidGuid;
  HidD_GetHidGuid(&hidGuid);
  HDEVINFO deviceInfoSet = SetupDiGetClassDevsW(
      &hidGuid, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
  if (deviceInfoSet == INVALID_HANDLE_VALUE) {
    WriteLog(L"无法获取设备列表: " + std::to_wstring(GetLastError()));
    return deviceInfo;
  }

  SP_DEVICE_INTERFACE_DATA deviceInterfaceData = {
      sizeof(SP_DEVICE_INTERFACE_DATA)};
  DWORD deviceIndex = 0;
  while (SetupDiEnumDeviceInterfaces(deviceInfoSet, NULL, &hidGuid, deviceIndex,
                                     &deviceInterfaceData)) {
    deviceIndex++;

    DWORD requiredSize = 0;
    SetupDiGetDeviceInterfaceDetailW(deviceInfoSet, &deviceInterfaceData, NULL,
                                     0, &requiredSize, NULL);

    std::vector<BYTE> detailBuffer(requiredSize);
    PSP_DEVICE_INTERFACE_DETAIL_DATA_W detailData =
        reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA_W>(
            detailBuffer.data());
    detailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);

    if (!SetupDiGetDeviceInterfaceDetailW(deviceInfoSet, &deviceInterfaceData,
                                          detailData, requiredSize, NULL,
                                          NULL)) {
      continue;
    }

    std::wstring devicePath = &detailData->DevicePath[0];
    std::wstring logPrefix =
        L"设备 [" + std::to_wstring(deviceIndex) + L"]: " + devicePath + L"\n";

    HANDLE hDevice =
        CreateFileW(devicePath.c_str(), GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED, NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
      WriteLog(logPrefix + L"    无法打开设备: " +
               std::to_wstring(GetLastError()));
      continue;
    }

    HIDD_ATTRIBUTES attributes;
    attributes.Size = sizeof(HIDD_ATTRIBUTES);
    if (!HidD_GetAttributes(hDevice, &attributes)) {
      WriteLog(logPrefix + L"    无法获取设备属性: " +
               std::to_wstring(GetLastError()));
      CloseHandle(hDevice);
      continue;
    }

    PHIDP_PREPARSED_DATA preparsedData = nullptr;
    if (!HidD_GetPreparsedData(hDevice, &preparsedData)) {
      WriteLog(logPrefix + L"    无法获取预解析数据: " +
               std::to_wstring(GetLastError()));
      CloseHandle(hDevice);
      continue;
    }

    HIDP_CAPS caps;
    if (HidP_GetCaps(preparsedData, &caps) != HIDP_STATUS_SUCCESS) {
      WriteLog(logPrefix + L"    无法获取设备能力: " +
               std::to_wstring(GetLastError()));
      HidD_FreePreparsedData(preparsedData);
      CloseHandle(hDevice);
      continue;
    }

    wchar_t manufacturer[256] = {0};
    if (!HidD_GetManufacturerString(hDevice, manufacturer, 256)) {
      wcscpy_s(manufacturer, L"未知制造商");
    }

    wchar_t product[256] = {0};
    if (!HidD_GetProductString(hDevice, product, 256)) {
      wcscpy_s(product, L"未知产品");
    }

    std::wstringstream info;
    info << logPrefix << std::hex << L"    VID: 0x" << std::setw(4)
         << std::setfill(L'0') << attributes.VendorID << L", PID: 0x"
         << std::setw(4) << std::setfill(L'0') << attributes.ProductID
         << L", UsagePage: 0x" << caps.UsagePage << L", UsageID: 0x"
         << caps.Usage << L", 制造商: " << manufacturer << L", 产品: "
         << product << L", 输入 " << std::dec << caps.InputReportByteLength
         << L" bytes, 输出 " << caps.OutputReportByteLength << L" bytes, 功能 "
         << caps.FeatureReportByteLength << L" bytes";
    WriteLog(info.str());

    HidD_FreePreparsedData(preparsedData);

    if (attributes.VendorID != HID_IR_VENDOR_ID ||
        attributes.ProductID != HID_IR_PRODUCT_ID ||
        caps.UsagePage != HID_IR_USAGE_PAGE || caps.Usage != HID_IR_USAGE_ID) {
      CloseHandle(hDevice);
      continue;
    }

    deviceInfo.hDevice = hDevice;
    deviceInfo.inputReportByteLength = caps.InputReportByteLength;
  }
  SetupDiDestroyDeviceInfoList(deviceInfoSet);

  return deviceInfo;
}

HidDeviceInfo FindTargetDevice() {
  while (g_running) {
    HidDeviceInfo deviceInfo = FindTargetDeviceImpl();
    if (deviceInfo.hDevice != INVALID_HANDLE_VALUE) {
      return deviceInfo;
    }

    WriteLog(L"未找到目标设备 (" + std::to_wstring(SCAN_INTERVAL_S) +
             L" 秒后重试)");
    std::this_thread::sleep_for(std::chrono::seconds(SCAN_INTERVAL_S));
  }

  HidDeviceInfo emptyInfo;
  return emptyInfo;
}

void HandleHIDData(std::vector<BYTE> buffer) {
  if (buffer.size() < 7 || buffer[0] != 0x00 || buffer[1] != 0x29 ||
      buffer[2] != 0x02 || buffer[3] != 0x00 || buffer[4] != 0xFF) {
    return;
  }

  std::wstringstream hexString;
  hexString << std::hex << std::uppercase << L"IR-" << std::setw(2)
            << std::setfill(L'0') << static_cast<int>(buffer[5]) << std::setw(2)
            << std::setfill(L'0') << static_cast<int>(buffer[6]) << L".bat";
  std::wstring scriptName = hexString.str();

  if (GetFileAttributesW(scriptName.c_str()) == INVALID_FILE_ATTRIBUTES) {
    WriteLog(L"未找到脚本 " + scriptName);
    return;
  }

  STARTUPINFOW si = {sizeof(si)};
  PROCESS_INFORMATION pi;
  if (!CreateProcessW(scriptName.c_str(), NULL, NULL, NULL, FALSE,
                      CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
    WriteLog(L"启动脚本 " + scriptName + L" 失败: " +
             std::to_wstring(GetLastError()));
    return;
  }

  WaitForSingleObject(pi.hProcess, INFINITE);
  DWORD exitCode = 0;
  if (GetExitCodeProcess(pi.hProcess, &exitCode)) {
    WriteLog(L"执行脚本 " + scriptName + L" 完成: " +
             std::to_wstring(exitCode));
  } else {
    WriteLog(L"执行脚本 " + scriptName + L" 完成，无法获取返回值: " +
             std::to_wstring(GetLastError()));
  }
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
}

void ReadHIDData(HANDLE hDevice, DWORD inputReportLength) {
  std::vector<BYTE> buffer(inputReportLength);
  DWORD bytesRead = 0;
  OVERLAPPED overlapped = {};
  overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
  if (overlapped.hEvent == NULL) {
    WriteLog(L"创建事件对象失败: " + std::to_wstring(GetLastError()));
    return;
  }

  while (g_running) {
    ResetEvent(overlapped.hEvent);

    BOOL result = ReadFile(hDevice, buffer.data(), inputReportLength,
                           &bytesRead, &overlapped);
    if (!result) {
      DWORD error = GetLastError();
      if (error == ERROR_IO_PENDING) {
        DWORD waitResult =
            WaitForSingleObject(overlapped.hEvent, READ_INTERVAL_MS);
        if (waitResult == WAIT_OBJECT_0) {
          if (!GetOverlappedResult(hDevice, &overlapped, &bytesRead, FALSE)) {
            WriteLog(L"获取结果失败: " + std::to_wstring(GetLastError()));
            continue;
          }
          if (bytesRead == 0) {
            continue;
          }
        } else if (waitResult == WAIT_TIMEOUT) {
          CancelIo(hDevice);
          continue;
        } else {
          WriteLog(L"等待完成失败: " + std::to_wstring(GetLastError()));
          break;
        }
      } else {
        WriteLog(L"读取错误: " + std::to_wstring(error));
        break;
      }
    }

    std::wstringstream signalData;
    signalData << L"收到信号 [";
    for (DWORD i = 0; i < bytesRead; ++i) {
      signalData << std::hex << std::uppercase << std::setw(2)
                 << std::setfill(L'0') << static_cast<int>(buffer[i]) << L" ";
    }
    signalData << L"]";
    WriteLog(signalData.str());
    HandleHIDData(buffer);
  }

  CloseHandle(overlapped.hEvent);
}

DWORD WINAPI HIDMonitorThread(LPVOID lpParam) {
  while (g_running) {
    HidDeviceInfo deviceInfo = FindTargetDevice();
    if (deviceInfo.hDevice != INVALID_HANDLE_VALUE) {
      WriteLog(L"开始接收数据...");
      ReadHIDData(deviceInfo.hDevice, deviceInfo.inputReportByteLength);
      CloseHandle(deviceInfo.hDevice);
    }
  }
  WriteLog(L"工作线程结束");
  return 0;
}

BOOL CreateTrayIcon() {
  g_nid.cbSize = sizeof(NOTIFYICONDATAW);
  g_nid.hWnd = g_hWnd;
  g_nid.uID = 1;
  g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
  g_nid.uCallbackMessage = WM_TRAYICON;
  g_nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
  wcscpy_s(g_nid.szTip, L"IR 接收器");

  return Shell_NotifyIconW(NIM_ADD, &g_nid);
}

BOOL RemoveTrayIcon() {
  return Shell_NotifyIconW(NIM_DELETE, &g_nid);
}

void ShowLogFile() {
  wchar_t logPath[MAX_PATH];
  GetCurrentDirectoryW(MAX_PATH, logPath);
  wcscat_s(logPath, L"\\" LOG_FILENAME);

  ShellExecuteW(NULL, L"open", logPath, NULL, NULL, SW_SHOW);
}

BOOL IsAutoStartEnabled() {
  HKEY hKey;
  LONG result =
      RegOpenKeyExW(HKEY_CURRENT_USER, AUTOSTART_REG_KEY, 0, KEY_READ, &hKey);
  if (result != ERROR_SUCCESS) {
    return FALSE;
  }

  wchar_t exePath[MAX_PATH];
  DWORD dataSize = sizeof(exePath);
  result = RegQueryValueExW(hKey, AUTOSTART_REG_VALUE, NULL, NULL,
                            (LPBYTE)exePath, &dataSize);
  RegCloseKey(hKey);

  if (result != ERROR_SUCCESS) {
    return FALSE;
  }

  wchar_t currentPath[MAX_PATH];
  GetModuleFileNameW(NULL, currentPath, MAX_PATH);
  return _wcsicmp(exePath, currentPath) == 0;
}

BOOL SetAutoStart(BOOL enable) {
  HKEY hKey;
  LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, AUTOSTART_REG_KEY, 0,
                              KEY_SET_VALUE, &hKey);
  if (result != ERROR_SUCCESS) {
    WriteLog(L"无法打开注册表项: " + std::to_wstring(result));
    return FALSE;
  }

  if (enable) {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    result =
        RegSetValueExW(hKey, AUTOSTART_REG_VALUE, 0, REG_SZ, (LPBYTE)exePath,
                       (wcslen(exePath) + 1) * sizeof(wchar_t));
    if (result == ERROR_SUCCESS) {
      WriteLog(L"设置开机自启动成功");
    } else {
      WriteLog(L"设置开机自启动失败: " + std::to_wstring(result));
    }
  } else {
    result = RegDeleteValueW(hKey, AUTOSTART_REG_VALUE);
    if (result == ERROR_SUCCESS) {
      WriteLog(L"删除开机自启动成功");
    } else if (result == ERROR_FILE_NOT_FOUND) {
      WriteLog(L"删除开机自启动时，注册表项不存在");
      result = ERROR_SUCCESS;
    } else {
      WriteLog(L"删除开机自启动失败: " + std::to_wstring(result));
    }
  }

  RegCloseKey(hKey);
  return result == ERROR_SUCCESS;
}

void ShowTrayMenu() {
  POINT pt;
  GetCursorPos(&pt);

  HMENU hMenu = CreatePopupMenu();
  AppendMenuW(hMenu, MF_STRING, ID_TRAY_SHOW_LOG, L"查看日志");
  AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);

  UINT autoStartFlags = MF_STRING;
  if (IsAutoStartEnabled()) {
    autoStartFlags |= MF_CHECKED;
  }
  AppendMenuW(hMenu, autoStartFlags, ID_TRAY_AUTOSTART, L"开机自启动");

  AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
  AppendMenuW(hMenu, MF_STRING, ID_TRAY_EXIT, L"退出");

  SetForegroundWindow(g_hWnd);
  TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, g_hWnd, NULL);
  DestroyMenu(hMenu);
}

LRESULT CALLBACK WindowProc(HWND hWnd,
                            UINT uMsg,
                            WPARAM wParam,
                            LPARAM lParam) {
  switch (uMsg) {
    case WM_TRAYICON:
      if (lParam == WM_RBUTTONUP) {
        ShowTrayMenu();
      }
      break;

    case WM_COMMAND:
      switch (LOWORD(wParam)) {
        case ID_TRAY_EXIT:
          WriteLog(L"主动退出程序");
          PostQuitMessage(0);
          break;
        case ID_TRAY_SHOW_LOG:
          ShowLogFile();
          break;
        case ID_TRAY_AUTOSTART:
          SetAutoStart(!IsAutoStartEnabled());
          break;
      }
      break;

    case WM_DESTROY:
      WriteLog(L"被动退出程序");
      PostQuitMessage(0);
      break;

    default:
      return DefWindowProc(hWnd, uMsg, wParam, lParam);
  }
  return 0;
}

int WINAPI WinMain(HINSTANCE hInstance,
                   HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine,
                   int nCmdShow) {
  TrimLogFile();
  g_logFile = CreateFileW(LOG_FILENAME, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                          OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (g_logFile == INVALID_HANDLE_VALUE) {
    MessageBoxW(
        NULL, (L"创建日志文件失败: " + std::to_wstring(GetLastError())).c_str(),
        L"IR 接收器", MB_OK | MB_ICONERROR);
    return 1;
  }
  SetFilePointer(g_logFile, 0, NULL, FILE_END);

  WriteLog(L"程序启动");

  if (IsAutoStartEnabled()) {
    WriteLog(L"已启用开机自启动");
  } else {
    WriteLog(L"未启用开机自启动");
  }

  WNDCLASSW wc = {};
  wc.lpfnWndProc = WindowProc;
  wc.hInstance = hInstance;
  wc.lpszClassName = L"IRReceiverClass";
  wc.hCursor = LoadCursor(NULL, IDC_ARROW);
  if (!RegisterClassW(&wc)) {
    WriteLog(L"注册窗口类失败: " + std::to_wstring(GetLastError()));
    return 1;
  }

  g_hWnd = CreateWindowExW(0, L"IRReceiverClass", L"IR Receiver", 0, 0, 0, 0, 0,
                           NULL, NULL, hInstance, NULL);
  if (!g_hWnd) {
    WriteLog(L"创建窗口失败: " + std::to_wstring(GetLastError()));
    return 1;
  }

  if (!CreateTrayIcon()) {
    WriteLog(L"创建托盘图标失败: " + std::to_wstring(GetLastError()));
    return 1;
  }

  HANDLE hThread = CreateThread(NULL, 0, HIDMonitorThread, NULL, 0, NULL);
  if (!hThread) {
    WriteLog(L"创建工作线程失败: " + std::to_wstring(GetLastError()));
    if (!RemoveTrayIcon()) {
      WriteLog(L"移除托盘图标失败: " + std::to_wstring(GetLastError()));
    }
    return 1;
  }

  MSG msg;
  while (GetMessage(&msg, NULL, 0, 0)) {
    TranslateMessage(&msg);
    DispatchMessage(&msg);
  }

  g_running = false;
  if (WaitForSingleObject(hThread, WAIT_TIMEOUT_MS) == WAIT_TIMEOUT) {
    WriteLog(L"工作线程无响应，强制结束");
  }
  CloseHandle(hThread);

  if (!RemoveTrayIcon()) {
    WriteLog(L"移除托盘图标失败: " + std::to_wstring(GetLastError()));
  }

  WriteLog(L"程序退出\n\n");
  CloseHandle(g_logFile);

  return 0;
}
