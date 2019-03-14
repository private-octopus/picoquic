// quicwind.cpp : 
// This is an exloration of using Picoquic in a windows desktop app.
// The app itself is a real time version of the picoquic demo.
// The application has two threads: the windows thread and the protocol thread.
// The protocol thread starts a quic context, and runs a loop to execute the
// protocol. It manages the sockets, etc.
//
// The windows thread manages the exchanges:
//   * start a connection to a specific destination (h3 or h09)
//   * ask for additional requests
//   * close the connection.
// The windows will report the last N messages on the UI, based on informations
// from the protocol callback.
// Since application and UI are in different threads, this should demonstrate 
// that the API is thread safe.
//
#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <WinSock2.h>
#include <Windows.h>
#include <tchar.h>
#include <strsafe.h>
#include "quicwind.h"

#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;                                // current instance
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name

// Forward declarations of functions included in this code module:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    StartConnection(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    LoadFile(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    CloseConnection(HWND, UINT, WPARAM, LPARAM);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // TODO: Place code here.

    // Initialize global strings
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_QUICWIND, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // Perform application initialization:
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_QUICWIND));

    MSG msg;

    // Main message loop:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}



//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_QUICWIND));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_QUICWIND);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance; // Store instance handle in our global variable

   HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE: Processes messages for the main window.
//
//  WM_COMMAND  - process the application menu
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            // Parse the menu selections:
            switch (wmId)
            {
            case ID_FILE_CONNECT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_CONNECT), hWnd, StartConnection);
                break;
            case ID_FILE_LOADFILE:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_LOAD_DOC), hWnd, LoadFile);
                break;
            case ID_FILE_CLOSE:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_CLOSE_CNX), hWnd, CloseConnection);
                break;
            case IDM_ABOUT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
                break;
            case IDM_EXIT:
                DestroyWindow(hWnd);
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            TCHAR greeting[] = _T("Hello, Windows desktop!");

            // TODO: Add any drawing code that uses hdc here...
            // Here your application is laid out.
            // For this introduction, we just print out "Hello, Windows desktop!"
            // in the top left corner.
            TextOut(hdc,
                5, 5,
                greeting, (int) _tcslen(greeting));
            // End application-specific layout section.

            EndPaint(hWnd, &ps);
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

// Message handler for connection start.
INT_PTR CALLBACK StartConnection(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    char text[1024];
    int text_len;


    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG: {
        (void)SetDlgItemTextA(hDlg, IDC_PORT_NUMBER, "4433");
        return (INT_PTR)TRUE;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            text_len = GetDlgItemTextA(hDlg, IDC_SERVER_NAME, text, (int)sizeof(text));

            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

// Message handler for file load.
INT_PTR CALLBACK LoadFile(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG: {
        // Add items to list. 
        HWND hwndList = GetDlgItem(hDlg, IDC_CNX_LIST1);
        TCHAR const * listText[3] = { TEXT("Connection 1"), TEXT("Connection 2"), TEXT("Connection 3") };
        for (int i = 0; i < 3; i++)
        {
            int pos = (int)SendMessage(hwndList, LB_ADDSTRING, 0,
                (LPARAM)listText[i]);
            // Set the array index of the player as item data.
            // This enables us to retrieve the item from the array
            // even after the items are sorted by the list box.
            SendMessage(hwndList, LB_SETITEMDATA, pos, (LPARAM)i);
        }
        // Set input focus to the list box.
        SetFocus(hwndList);
        return (INT_PTR)TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

// Message handler for connection close.
INT_PTR CALLBACK CloseConnection(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    int final_rank = -1;

    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG: {
        // Add items to list. 
        HWND hwndList = GetDlgItem(hDlg, IDC_CNX_LIST1);
        TCHAR const * listText[3] = { TEXT("Connection 1"), TEXT("Connection 2"), TEXT("Connection 3") };
        for (int i = 0; i < 3; i++)
        {
            int pos = (int)SendMessage(hwndList, LB_ADDSTRING, 0,
                (LPARAM)listText[i]);
            // Set the array index of the player as item data.
            // This enables us to retrieve the item from the array
            // even after the items are sorted by the list box.
            SendMessage(hwndList, LB_SETITEMDATA, pos, (LPARAM)i);
        }
        // Set selected index.
        int lbItem = (int)SendMessage(hwndList, LB_SETCURSEL, 0, 0);
        // Set input focus to the list box.
        SetFocus(hwndList);
        return (INT_PTR)TRUE;
    }

    case WM_COMMAND: 
        switch (LOWORD(wParam)) {
#if 0
        case IDC_CNX_LIST1:
            switch (HIWORD(wParam))
            {
            case LBN_SELCHANGE:
            {
                HWND hwndList = GetDlgItem(hDlg, IDC_CNX_LIST1);

                // Get selected index.
                int lbItem = (int)SendMessage(hwndList, LB_GETCURSEL, 0, 0);

                // Get item data.
                cnx_rank = (int)SendMessage(hwndList, LB_GETITEMDATA, lbItem, 0);
            }
            }
            break;
#endif
        case IDOK:
        {
            HWND hwndList = GetDlgItem(hDlg, IDC_CNX_LIST1);

            // Get selected index.
            int lbItem = (int)SendMessage(hwndList, LB_GETCURSEL, 0, 0);

            // Get item data.
            final_rank = (int)SendMessage(hwndList, LB_GETITEMDATA, lbItem, 0);

            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        case IDCANCEL:
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
  
        break;
    }
    return (INT_PTR)FALSE;
}