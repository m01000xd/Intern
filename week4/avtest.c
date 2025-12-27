#include <windows.h>
#include <commctrl.h>
#include <shlobj_core.h>
#include <stdio.h>
#include <tchar.h>
#include <fileapi.h>
#include <winnt.h>

#pragma comment(lib, "Comctl32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "User32.lib")

#define IDC_LISTVIEW 1001
HWND hListView;

LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);

// Tạo và khởi tạo ListView
void InitListView(HWND hWnd) {
    hListView = CreateWindowEx(0, WC_LISTVIEW, "",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
        10, 10, 600, 400, hWnd, (HMENU)IDC_LISTVIEW, GetModuleHandle(NULL), NULL);

    ListView_SetExtendedListViewStyle(hListView, LVS_EX_FULLROWSELECT);

    LVCOLUMN lvc = { 0 };
    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;

    lvc.cx = 200; lvc.pszText = (LPSTR)"Filename";
    ListView_InsertColumn(hListView, 0, &lvc);

    lvc.cx = 120; lvc.pszText = (LPSTR)"Entry Point (RVA)";
    ListView_InsertColumn(hListView, 1, &lvc);

    lvc.cx = 100; lvc.pszText = (LPSTR)"Status";
    ListView_InsertColumn(hListView, 2, &lvc);
}

void AddListViewItem(const char* filename, DWORD ep, const char* status) {
    char rva_buf[32];
    sprintf(rva_buf, "0x%X", ep);

    LVITEM lvi = { 0 };
    lvi.mask = LVIF_TEXT;
    lvi.iItem = ListView_GetItemCount(hListView);
    lvi.pszText = (LPSTR)filename;
    ListView_InsertItem(hListView, &lvi);

    ListView_SetItemText(hListView, lvi.iItem, 1, rva_buf);
    ListView_SetItemText(hListView, lvi.iItem, 2, (LPSTR)status);
}

// Hàm xử lý PE file, quét virus, ghi file sạch và hiển thị lên ListView
void ScanAndCleanFiles(HWND hwnd) {
    int totalFiles = 0, infectedFiles = 0, cleanedFiles = 0;
    char src_path[MAX_PATH] = { 0 }, dest_path[MAX_PATH] = { 0 };

    BROWSEINFOA bi = { 0 };
    bi.lpszTitle = "Select infected folder: ";
    LPITEMIDLIST pidl = SHBrowseForFolderA(&bi);
    if (!pidl) return;
    SHGetPathFromIDListA(pidl, src_path);

    bi.lpszTitle = "Select folder to store new file: ";
    pidl = SHBrowseForFolderA(&bi);
    if (!pidl) return;
    SHGetPathFromIDListA(pidl, dest_path);

    char find_path[MAX_PATH];
    snprintf(find_path, MAX_PATH, "%s\\*", src_path);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(find_path, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        totalFiles++;

        char file_path[MAX_PATH];
        snprintf(file_path, MAX_PATH, "%s\\%s", src_path, fd.cFileName);

        HANDLE hFile = CreateFileA(file_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) continue;

        DWORD filesize = GetFileSize(hFile, NULL);
        if (filesize == INVALID_FILE_SIZE || filesize == 0) {
            CloseHandle(hFile);
            continue;
        }

        // Đọc file gốc vào buffer
        BYTE* buffer = (BYTE*)malloc(filesize);
        if (!buffer) {
            CloseHandle(hFile);
            continue;
        }

        DWORD bytesRead;
        if (!ReadFile(hFile, buffer, filesize, &bytesRead, NULL) || bytesRead != filesize) {
            free(buffer);
            CloseHandle(hFile);
            continue;
        }
        CloseHandle(hFile);

        // Tạo vùng nhớ riêng biệt
        BYTE* mem = (BYTE*)VirtualAlloc(NULL, filesize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!mem) {
            free(buffer);
            continue;
        }
        memcpy(mem, buffer, filesize);  // copy nội dung vào vùng memory riêng
        free(buffer); // không dùng buffer nữa

        // Phân tích PE trong vùng nhớ riêng
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)mem;
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
            VirtualFree(mem, 0, MEM_RELEASE);
            continue;
        }

        PIMAGE_NT_HEADERS32 pNt = (PIMAGE_NT_HEADERS32)(mem + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE) {
            VirtualFree(mem, 0, MEM_RELEASE);
            continue;
        }

        PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)((BYTE*)&pNt->OptionalHeader + pNt->FileHeader.SizeOfOptionalHeader);
        PIMAGE_SECTION_HEADER pLast = &pSection[pNt->FileHeader.NumberOfSections - 1];
        BYTE* rawData = mem + pLast->PointerToRawData;

        for (int i = 0; i < pLast->SizeOfRawData - 11; i++) {
            if (memcmp(rawData + i, "Infected...", 11) == 0) {
                infectedFiles++;

                DWORD offset = pNt->OptionalHeader.AddressOfEntryPoint - pLast->VirtualAddress;
                DWORD shellcode_size = (i + 12) - offset;

                AddListViewItem(fd.cFileName, pNt->OptionalHeader.AddressOfEntryPoint, "Infected");
                pNt->OptionalHeader.AddressOfEntryPoint = pNt->OptionalHeader.LoaderFlags;
                pNt->OptionalHeader.LoaderFlags = 0;
                printf("Writing file %s with LoaderFlags = 0x%X\n", fd.cFileName, pNt->OptionalHeader.LoaderFlags);
                memset(rawData + offset, 0, shellcode_size);

                char clean_path[MAX_PATH];
                snprintf(clean_path, MAX_PATH, "%s\\%s", dest_path, fd.cFileName);
                HANDLE hOut = CreateFileA(clean_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
                if (hOut != INVALID_HANDLE_VALUE) {
                    DWORD written = 0;
                    WriteFile(hOut, mem, filesize, &written, NULL);
                    CloseHandle(hOut);
                    cleanedFiles++;
                }
                break;
            }
        }

        VirtualFree(mem, 0, MEM_RELEASE);

    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);

    // Hiển thị kết quả
    char report[256];
    sprintf(report,
        "Scan complete.\n\nTotal files scanned: %d\nInfected files: %d\nCleaned successfully: %d",
        totalFiles, infectedFiles, cleanedFiles
    );
    MessageBoxA(hwnd, report, "Scan Summary", MB_OK | MB_ICONINFORMATION);
}



int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShowCmd) {
    INITCOMMONCONTROLSEX icex = { sizeof(icex), ICC_LISTVIEW_CLASSES };
    InitCommonControlsEx(&icex);

    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = "AntivirusWindow";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClass(&wc);

    HWND hWnd = CreateWindow("AntivirusWindow", "Simple Antivirus GUI",
        WS_OVERLAPPEDWINDOW, 100, 100, 640, 480, NULL, NULL, hInst, NULL);
    ShowWindow(hWnd, nShowCmd);
    UpdateWindow(hWnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM w, LPARAM l) {
    switch (msg) {
    case WM_CREATE:
        InitListView(hWnd);
        ScanAndCleanFiles(hWnd);
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, msg, w, l);
    }
    return 0;
}
