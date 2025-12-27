#include <windows.h>
#include <stdio.h>
#include <fileapi.h>

typedef struct _PEImageFileProcessed {
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;

    BOOL IsDll;
    DWORD ImageBase;
    DWORD SizeOfImage;
    DWORD AddressOfEntryPointOffset;

    WORD NumOfSections;
    PIMAGE_SECTION_HEADER SectionHeaderFirst;

    PIMAGE_DATA_DIRECTORY pDataDirectoryExport;
    PIMAGE_DATA_DIRECTORY pDataDirectoryImport;
    PIMAGE_DATA_DIRECTORY pDataDirectoryReloc;
    PIMAGE_DATA_DIRECTORY pDataDirectoryException;
} PEImageFileProcessed, *PPEImageFileProcessed;

typedef struct BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

LPVOID read_imagefile(LPCSTR filepath){
    HANDLE hFile = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    DWORD filesize = GetFileSize(hFile, NULL);
    DWORD byte_reads = 0;
    
    LPVOID buffer = VirtualAlloc(NULL, filesize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ReadFile(hFile, buffer, filesize, &byte_reads, NULL);
    CloseHandle(hFile);
    return buffer;
}

BOOL process_pefile(LPVOID buffer, PPEImageFileProcessed pPE){
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS32 pNt = (PIMAGE_NT_HEADERS32)((BYTE*)buffer + pDos->e_lfanew);

    if (pDos->e_magic != IMAGE_DOS_SIGNATURE || pNt->Signature != IMAGE_NT_SIGNATURE) {
        printf("Invalid PE file\n");
        return FALSE;
    }

    if (!(pNt->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) {
        printf("Not executable\n");
        return FALSE;
    }

    pPE->FileHeader = pNt->FileHeader;
    pPE->IsDll = (pNt->FileHeader.Characteristics & IMAGE_FILE_DLL) ? TRUE : FALSE;

    if (pNt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        printf("Only PE32 is supported.\n");
        return FALSE;
    }

    IMAGE_OPTIONAL_HEADER32* opt = &pNt->OptionalHeader;
    pPE->OptionalHeader = *opt;
    pPE->ImageBase = opt->ImageBase;
    pPE->SizeOfImage = opt->SizeOfImage;
    pPE->AddressOfEntryPointOffset = opt->AddressOfEntryPoint;

    pPE->pDataDirectoryExport = &opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    pPE->pDataDirectoryImport = &opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    pPE->pDataDirectoryReloc = &opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    pPE->pDataDirectoryException = &opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

    pPE->NumOfSections = pNt->FileHeader.NumberOfSections;
    pPE->SectionHeaderFirst = IMAGE_FIRST_SECTION(pNt);

    return TRUE;
}
/// cap phat bo nho cho buffer can load vao memory
LPVOID alloc_inmemPE(PPEImageFileProcessed pPE, LPVOID inmem){
    return VirtualAlloc((LPVOID)(DWORD)inmem, pPE->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}
/// copy cac header vao buffer can load
void copy_header(PPEImageFileProcessed pPE, LPVOID buffer, LPVOID inmem){
    memcpy(inmem, buffer, pPE->OptionalHeader.SizeOfHeaders);
}
/// copy section
void copy_section(PPEImageFileProcessed pPE, LPVOID buffer, LPVOID inmem){
    for (int i = 0; i < pPE->NumOfSections; i++) {
        IMAGE_SECTION_HEADER section = pPE->SectionHeaderFirst[i];
        memcpy((BYTE*)inmem + section.VirtualAddress, (BYTE*)buffer + section.PointerToRawData, section.SizeOfRawData);
    }
}
///fix relocation
void relocation(PPEImageFileProcessed pPE, LPVOID inmem){
    DWORD delta = (DWORD)(inmem) - pPE->OptionalHeader.ImageBase;
    IMAGE_DATA_DIRECTORY relocDir = *pPE->pDataDirectoryReloc;
    DWORD relocAddr = relocDir.VirtualAddress;
    DWORD relocSize = relocDir.Size;
    DWORD processed = 0;

    while (processed < relocSize) {
        PBASE_RELOCATION_BLOCK pBlock = (PBASE_RELOCATION_BLOCK)((DWORD_PTR)inmem + relocAddr + processed);
        processed += sizeof(BASE_RELOCATION_BLOCK);

        DWORD entryCount = (pBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
        PBASE_RELOCATION_ENTRY entries = (PBASE_RELOCATION_ENTRY)((DWORD_PTR)pBlock + sizeof(BASE_RELOCATION_BLOCK));

        for (DWORD i = 0; i < entryCount; i++) {
            if (entries[i].Type == 0) continue;

            DWORD patchAddr = (DWORD_PTR)inmem + pBlock->PageAddress + entries[i].Offset;
            DWORD value;
            memcpy(&value, (PVOID)patchAddr, sizeof(DWORD));
            value += delta;
            memcpy((PVOID)patchAddr, &value, sizeof(DWORD));
        }

        processed += entryCount * sizeof(BASE_RELOCATION_ENTRY);
    }
}

BOOL fix_import(PPEImageFileProcessed pPE, LPVOID inmem){
    IMAGE_DATA_DIRECTORY importDir = *pPE->pDataDirectoryImport;
    if (importDir.VirtualAddress == 0 || importDir.Size == 0) return TRUE;

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)inmem + importDir.VirtualAddress);
    while (importDesc->Name != 0) {
        LPCSTR dllName = (LPCSTR)((DWORD_PTR)inmem + importDesc->Name);
        HMODULE hDLL = LoadLibraryA(dllName);
        if (!hDLL) {
            printf("[-] Failed to load: %s\n", dllName);
            return FALSE;
        }

        PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)inmem + importDesc->FirstThunk);
        PIMAGE_THUNK_DATA pOrigThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)inmem + importDesc->OriginalFirstThunk);

        while (pOrigThunk->u1.AddressOfData != 0) {
            FARPROC func = NULL;
            if (IMAGE_SNAP_BY_ORDINAL(pOrigThunk->u1.Ordinal)) {
                func = GetProcAddress(hDLL, (LPCSTR)(pOrigThunk->u1.Ordinal & 0xFFFF));
            } else {
                PIMAGE_IMPORT_BY_NAME name = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)inmem + pOrigThunk->u1.AddressOfData);
                func = GetProcAddress(hDLL, name->Name);
            }

            if (!func) {
                printf("[-] Failed to resolve import.\n");
                return FALSE;
            }

            pThunk->u1.Function = (DWORD_PTR)func;
            pThunk++;
            pOrigThunk++;
        }

        importDesc++;
    }

    return TRUE;
}

typedef BOOL(*DLLMAIN)(HINSTANCE, DWORD, LPVOID);
typedef int (*MAIN)(int, char**);
typedef int (WINAPI *WINMAIN)(HINSTANCE, HINSTANCE, LPSTR, int);

void JumpToEntry(PPEImageFileProcessed pPE, LPVOID inmem) {
    LPVOID pEntry = (LPVOID)((DWORD_PTR)inmem + pPE->AddressOfEntryPointOffset);
    WORD subsystem = pPE->OptionalHeader.Subsystem;

    if (pPE->IsDll) {
        ((DLLMAIN)pEntry)((HINSTANCE)inmem, DLL_PROCESS_ATTACH, NULL);
    } else if (subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) {
        ((WINMAIN)pEntry)((HINSTANCE)inmem, NULL, GetCommandLineA(), SW_SHOW);
    } else {
        ((MAIN)pEntry)(1, NULL);
    }
}


int main(int argc, char* argv[]){
    if (argc < 2) {
        printf("Usage: %s <pe32_file>\n", argv[0]);
        return 1;
    }

    LPVOID buffer = read_imagefile(argv[1]);
    if (!buffer) {
        printf("Failed to read PE file.\n");
        return 1;
    }

    PEImageFileProcessed* pe = (PEImageFileProcessed*) malloc(sizeof(PEImageFileProcessed));
    if (!process_pefile(buffer, pe)) {
        printf("Failed to process PE file.\n");
        return 1;
    }

    LPVOID inmem = alloc_inmemPE(pe, NULL);
    if (!inmem) {
        printf("VirtualAlloc failed.\n");
        return 1;
    }

    copy_header(pe, buffer, inmem);
    copy_section(pe, buffer, inmem);
    relocation(pe, inmem);
    fix_import(pe, inmem);
    JumpToEntry(pe, inmem);

    return 0;
}
