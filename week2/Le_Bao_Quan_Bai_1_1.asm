; Định nghĩa extern và section
global _main
extern _SHBrowseForFolderA@4
extern _SHGetPathFromIDListA@8
extern _ExitProcess@4
extern _CoInitialize@4
extern _CoUninitialize@0
extern _FindFirstFileA@8
extern _FindNextFileA@8
extern _FindClose@4
extern _CreateFileA@28
extern _ReadFile@20
extern _VirtualAlloc@16
extern _GetFileSize@8
extern _GetLastError@0
extern _VirtualFree@12
extern _printf
extern _CloseHandle@4

struc BROWSEINFOA
    .hwndOwner          resd 1
    .pidlRoot           resd 1
    .pszDisplayName     resd 1
    .lpszTitle          resd 1
    .ulFlags            resd 1
    .lpfn               resd 1
    .lParam             resd 1
    .iImage             resd 1
endstruc

struc WIN32_FIND_DATA
    .dwFileAttributes    resd 1
    .ftCreationTime      resq 1
    .ftLastAccessTime    resq 1
    .ftLastWriteTime     resq 1
    .nFileSizeHigh       resd 1
    .nFileSizeLow        resd 1
    .dwReserved0         resd 1
    .dwReserved1         resd 1
    .cFileName           resb 260
    .cAlternateFileName  resb 14
    .dwFileType          resd 1
    .dwCreatorType       resd 1
    .wFinderFlags        resw 1
endstruc

struc IMAGE_DOS_HEADER
    .e_magic    resw 1      ; MZ signature
    .e_cblp     resw 1
    .e_cp       resw 1
    .e_crlc     resw 1
    .e_cparhdr  resw 1
    .e_minalloc resw 1
    .e_maxalloc resw 1
    .e_ss       resw 1
    .e_sp       resw 1
    .e_csum     resw 1
    .e_ip       resw 1
    .e_cs       resw 1
    .e_lfarlc   resw 1
    .e_ovno     resw 1
    .e_res      resw 4
    .e_oemid    resw 1
    .e_oeminfo  resw 1
    .e_res2     resw 10
    .e_lfanew   resd 1      ; PE header offset
endstruc

struc IMAGE_FILE_HEADER
    .Machine              resw 1
    .NumberOfSections     resw 1
    .TimeDateStamp        resd 1
    .PointerToSymbolTable resd 1
    .NumberOfSymbols      resd 1
    .SizeOfOptionalHeader resw 1
    .Characteristics      resw 1
endstruc

struc IMAGE_NT_HEADERS
    .Signature resd 1
    .FileHeader resd 1
    .OptionalHeader resd 1
endstruc

struc IMAGE_FILE_HEADER
    .Machine              resw 1
    .NumberOfSections     resw 1
    .TimeDateStamp        resd 1
    .PointerToSymbolTable resd 1
    .NumberOfSymbols      resd 1
    .SizeOfOptionalHeader resw 1
    .Characteristics      resw 1
endstruc

struc IMAGE_OPTIONAL_HEADER32
    .Magic                   resw 1
    .MajorLinkerVersion      resb 1
    .MinorLinkerVersion      resb 1
    .SizeOfCode              resd 1
    .SizeOfInitializedData   resd 1
    .SizeOfUninitializedData resd 1
    .AddressOfEntryPoint     resd 1
    .BaseOfCode              resd 1
    .BaseOfData              resd 1
    .ImageBase               resd 1
    .SectionAlignment        resd 1
    .FileAlignment           resd 1
    .MajorOperatingSystemVersion resw 1
    .MinorOperatingSystemVersion resw 1
    .MajorImageVersion       resw 1
    .MinorImageVersion       resw 1
    .MajorSubsystemVersion   resw 1
    .MinorSubsystemVersion   resw 1
    .Win32VersionValue       resd 1
    .SizeOfImage             resd 1
    .SizeOfHeaders           resd 1
    .CheckSum                resd 1
    .Subsystem               resw 1
    .DllCharacteristics      resw 1
    .SizeOfStackReserve      resd 1
    .SizeOfStackCommit       resd 1
    .SizeOfHeapReserve       resd 1
    .SizeOfHeapCommit        resd 1
    .LoaderFlags             resd 1
    .NumberOfRvaAndSizes     resd 1
    .DataDirectory           resd 16
endstruc

struc IMAGE_DATA_DIRECTORY
    .VirtualAddress resd 1
    .Size resd 1
endstruc

struc IMAGE_SECTION_HEADER
    .Name                 resb 8
    .VirtualSize          resd 1
    .VirtualAddress       resd 1
    .SizeOfRawData        resd 1
    .PointerToRawData     resd 1
    .PointerToRelocations resd 1
    .PointerToLinenumbers resd 1
    .NumberOfRelocations  resw 1
    .NumberOfLinenumbers  resw 1
    .Characteristics      resd 1
endstruc

struc IMAGE_IMPORT_DESCRIPTOR
    .Characteristics resd 1
    .TimeDateStamp resd 1
    .ForwarderChain resd 1
    .Name resd 1
    .FirstThunk resd 1
endstruc

struc IMAGE_EXPORT_DIRECTORY
    .Characteristics       resd 1  ; 4 byte
    .TimeDateStamp         resd 1  ; 4 byte
    .MajorVersion          resw 1  ; 2 byte
    .MinorVersion          resw 1  ; 2 byte
    .Name                  resd 1  ; 4 byte
    .Base                  resd 1  ; 4 byte
    .NumberOfFunctions     resd 1  ; 4 byte
    .NumberOfNames         resd 1  ; 4 byte
    .AddressOfFunctions    resd 1  ; 4 byte
    .AddressOfNames        resd 1  ; 4 byte
    .AddressOfNameOrdinals resd 1  ; 4 byte
endstruc



%define BIF_RETURNONLYFSDIRS 0x00000001
%define INVALID_HANDLE_VALUE -1
%define FILE_ATTRIBUTE_DIRECTORY 0x00000010
%define GENERIC_READ 0x80000000
%define FILE_SHARE_READ 1
%define OPEN_EXISTING 3
%define MEM_COMMIT          0x1000
%define MEM_RESERVE         0x2000
%define PAGE_READWRITE      0x04
%define MEM_RELEASE         0x8000
%define MZ_SIGNATURE 0x5A4D
%define PE_SIGNATURE 0x00004550
%define ERROR_NO_MORE_FILES 18
%define FILE_ATTRIBUTE_NORMAL 0x80


section .bss
    lpbi resb BROWSEINFOA_size
    find_data resb WIN32_FIND_DATA_size
    display_name resb 260
    pidl resd 1
    path resb 260
    search_path resb 260
    edit_path resb 260
    hFind resd 1
    hFile resd 1
    file_size resd 1
    file_buffer resd 1
    bytes_read resd 1
    section_name resb 9

section .data
    select_msg      db "Selecting folder for PE analysis...", 10, 0
    browse_title    db "Select folder to analyze PE files", 0
    format db "Ban da chon: %s", 10, 0
    message db " %s ", 10, 0
    format_dir db "  %s   <DIR>\n", 10, 0        ; TAB TAB <DIR> NEWLINE
    format_file db "  %s   %ld bytes", 10, 0   ; TAB TAB size NEWLINE
    error_open db "Loi mo tep: %d", 10, 0
    error_read db "Loi doc tep: %d", 10, 0
    error_alloc db "Loi cap phat bo nho: %d", 10, 0
    error_size db "Loi lay kich thuoc tep: %d", 10, 0
    dos_header_msg db "IMAGE_DOS_HEADER:", 10, 0
    nt_header_msg db "IMAGE_NT_HEADERS:", 10, 0
    file_header_msg db "IMAGE_FILE_HEADER:",10,0
    section_header_msg db "IMAGE_SECTION_HEADER:", 10, 0
    e_magic db " e_magic: 0x%02hhx", 10, 0
    e_cblp db " e_cblp: 0x%02hhx", 10, 0
    e_cp db " e_cp: 0x%02hhx", 10, 0
    e_crlc db " e_crlc: 0x%02hhx", 10, 0
    e_cparhdr db " e_cparhdr: 0x%02hhx", 10, 0
    e_minalloc db " e_minalloc: 0x%02hhx", 10, 0
    e_maxalloc db " e_maxalloc: 0x%02hhx", 10, 0
    e_ss db " e_ss: 0x%02hhx", 10, 0
    e_sp db " e_sp: 0x%02hhx", 10, 0
    e_csum db " e_csum: 0x%02hhx", 10, 0
    e_ip db " e_ip: 0x%02hhx", 10, 0
    e_cs db " e_cs: 0x%02hhx", 10, 0
    e_lfarlc db " e_lfarlc: 0x%02hhx", 10, 0
    e_ovno db " e_ovno: 0x%02hhx", 10, 0
    e_res0 db " e_res[0]: 0x%02hhx", 10, 0
    e_res1 db " e_res[1]: 0x%02hhx", 10, 0
    e_res2 db " e_res[2]: 0x%02hhx", 10, 0
    e_res3 db " e_res[3]: 0x%02hhx", 10, 0
    e_oemid db " e_oemid: 0x%02hhx", 10, 0
    e_oeminfo db " e_oeminfo: 0x%02hhx", 10, 0
    e_res2_0 db " e_res2[0]: 0x%02hhx", 10, 0
    e_res2_1 db " e_res2[1]: 0x%02hhx", 10, 0
    e_res2_2 db " e_res2[2]: 0x%02hhx", 10, 0
    e_res2_3 db " e_res2[3]: 0x%02hhx", 10, 0
    e_res2_4 db " e_res2[4]: 0x%02hhx", 10, 0
    e_res2_5 db " e_res2[5]: 0x%02hhx", 10, 0
    e_res2_6 db " e_res2[6]: 0x%02hhx", 10, 0
    e_res2_7 db " e_res2[7]: 0x%02hhx", 10, 0
    e_res2_8 db " e_res2[8]: 0x%02hhx", 10, 0
    e_res2_9 db " e_res2[9]: 0x%02hhx", 10, 0
    e_lfanew db " e_lfanew: 0x%x ", 10, 0
    signature db " Signature: 0x%02hhx", 10, 0
    optional_header db "OPTIONAL_HEADER:", 10,0
    machine db " Machine: 0x%02hhx", 10, 0
    number_of_sections db " NumberOfSections: 0x%02hhx", 10, 0
    time_date_stamp db " TimeDateStamp: 0x%02hhx", 10, 0
    pointer_to_symbol_table db " PointerToSymbolTable: 0x%02hhx", 10, 0
    number_of_symbols db " NumberOfSymbols: 0x%02hhx", 10, 0
    size_of_optional_header db " SizeOfOptionalHeader: 0x%02hhx", 10, 0
    characteristics db " Characteristics: 0x%02hhx", 10, 0
    valid_pe_msg db "Valid PE file", 10, 0
    invalid_mz_msg db "Invalid MZ signature", 10, 0
    invalid_pe_msg db "File %s khong phai la file PE", 10, 0
    new_line db "Offset: %d",0
    Magic db "  Magic: 0x%02hhx", 10, 0
    MajorLinkerVersion                    db "  MajorLinkerVersion: 0x%x", 10, 0
    MinorLinkerVersion                    db "  MinorLinkerVersion: 0x%x", 10, 0
    SizeOfCode db "  SizeOfCode: 0x%x", 10, 0
    SizeOfInitializedData                    db "  SizeOfInitializedData: 0x%x", 10, 0
    SizeOfUninitializedData db "  SizeOfUninitializedData: 0x%x", 10, 0
    AddressOfEntryPoint           db "  AddressOfEntryPoint: 0x%x", 10, 0
    BaseOfCode                    db "  BaseOfCode: 0x%x", 10, 0
    BaseOfData                    db "  BaseOfData: 0x%x", 10, 0
    ImageBase                     db "  ImageBase: 0x%x", 10, 0
    SectionAlignment                    db "  SectionAlignment: 0x%x", 10, 0
    FileAlignment                    db "  FileAlignment: 0x%x", 10, 0
    MajorOperatingSystemVersion                    db "  MajorOperatingSystemVersion: 0x%02hhx", 10, 0
    MinorOperatingSystemVersion                    db "  MinorOperatingSystemVersion: 0x%02hhx", 10, 0
    MajorImageVersion                    db "  MajorImageVersion: 0x%02hhx", 10, 0
    MinorImageVersion                    db "  MinorImageVersion: 0x%02hhx", 10, 0
    MajorSubsystemVersion                    db "  MajorSubsystemVersion: 0x%02hhx", 10, 0
    MinorSubsystemVersion                    db "  MinorSubsystemVersion: 0x%02hhx", 10, 0
    Win32VersionValue                    db "  Win32VersionValue: 0x%x", 10, 0
    SizeOfImage                    db "  SizeOfImage: 0x%x", 10, 0
    SizeOfHeaders                    db "  SizeOfHeaders: 0x%x", 10, 0
    CheckSum                    db "  CheckSum: 0x%x", 10, 0
    Subsystem                    db "  Subsystem: 0x%02hhx", 10, 0
    DllCharacteristics                    db "  DllCharacteristics: 0x%02hhx", 10, 0
    SizeOfStackReserve                    db "  SizeOfStackReserve: 0x%x", 10, 0
    SizeOfStackCommit                    db "  SizeOfStackCommit: 0x%x", 10, 0
    SizeOfHeapReserve                    db "  SizeOfHeapReserve: 0x%x", 10, 0
    SizeOfHeapCommit                    db "  SizeOfHeapCommit: 0x%x", 10, 0
    LoaderFlags                    db "  LoaderFlags: 0x%x", 10, 0
    NumberOfRvaAndSizes                    db "  NumberOfRvaAndSizes: 0x%x", 10, 0
    section_name_fmt     db " Section: %.8s", 10, 0
    virtual_size_fmt     db "   VirtualSize:        0x%02hhx", 10, 0
    va_fmt               db "   VirtualAddress:     0x%02hhx", 10, 0
    raw_size_fmt         db "   SizeOfRawData:      0x%02hhx", 10, 0
    ptr_raw_fmt          db "   PointerToRawData:   0x%02hhx", 10, 0
    characteristics_fmt  db "   Characteristics:    0x%02hhx", 10, 0
    close db "Khong tim thay file PE", 10, 0
    test_a db "esi: %d ", 10, 0
    check_msg db "True", 10, 0
    
    

section .text
_main:

    ; Chuẩn bị BROWSEINFO
    mov dword [lpbi + BROWSEINFOA.hwndOwner], 0
    mov dword [lpbi + BROWSEINFOA.pidlRoot], 0
    mov dword [lpbi + BROWSEINFOA.pszDisplayName], display_name
    mov dword [lpbi + BROWSEINFOA.lpszTitle], browse_title
    mov dword [lpbi + BROWSEINFOA.ulFlags], BIF_RETURNONLYFSDIRS
    mov dword [lpbi + BROWSEINFOA.lpfn], 0
    mov dword [lpbi + BROWSEINFOA.lParam], 0
    mov dword [lpbi + BROWSEINFOA.iImage], 0

select_folder:
    push select_msg
    call _printf
    add esp, 4

    lea eax, [lpbi]
    push eax
    call _SHBrowseForFolderA@4
    mov [pidl], eax
    test eax, eax
    jz exit

    push path
    push dword [pidl]
    call _SHGetPathFromIDListA@8
    test eax, eax
    jz exit


    ; Sao chép path và thêm "\\*.*"
    lea edi, [search_path]
    lea esi, [path]
.copy_loop:
    lodsb
    stosb
    test al, al
    jnz .copy_loop
    dec edi
    mov al, '\'
    stosb
    mov al, '*'
    stosb
    mov al, '.'
    stosb
    mov al, '*'
    stosb
    mov al, 0
    stosb


    

find_first_file:
    push find_data
    push search_path
    call _FindFirstFileA@8

    
    mov [hFind], eax
    cmp eax, INVALID_HANDLE_VALUE
    je exit
    
find_next_file:
    mov eax, [find_data + WIN32_FIND_DATA.dwFileAttributes]
    and eax, FILE_ATTRIBUTE_DIRECTORY
    cmp eax, 0
    jne continue_loop
    jmp analyze_path
analyze_path:
    lea esi, [path]
    lea edi, [edit_path]
copy_path:
    lodsb
    stosb
    test al, al
    jnz copy_path
    dec edi
    mov al, '\'
    stosb
    lea esi, [find_data + WIN32_FIND_DATA.cFileName]
copy_filename:
    lodsb
    stosb
    test al, al
    jnz copy_filename

open_file:
    push 0                    ; hTemplateFile
    push FILE_ATTRIBUTE_NORMAL ; dwFlagsAndAttributes
    push OPEN_EXISTING        ; dwCreationDisposition
    push 0                    ; lpSecurityAttributes
    push 0                    ; dwShareMode
    push GENERIC_READ         ; dwDesiredAccess
    push edit_path                  ; lpFileName
    call _CreateFileA@28
    mov [hFile], eax
    cmp eax, INVALID_HANDLE_VALUE
    je exit
get_filesize:
    push 0
    push dword [hFile]
    call _GetFileSize@8
    mov [file_size], eax

    

alloc:
    push PAGE_READWRITE
    push MEM_COMMIT
    push dword [file_size]
    push 0
    call _VirtualAlloc@16
    mov [file_buffer], eax
    cmp eax, 0
    je exit
read_file:
    push 0
    push bytes_read
    push dword [file_size]
    push dword [file_buffer]
    push dword [hFile]
    call _ReadFile@20
    cmp eax, 0
    je exit
    mov eax, [bytes_read]

check:
    mov ebx, [file_buffer]
    cmp word [ebx + IMAGE_DOS_HEADER.e_magic], MZ_SIGNATURE
    je check1
    jmp continue_loop
check1:
    mov ecx, [ebx + IMAGE_DOS_HEADER.e_lfanew]
    add ecx, ebx
    mov esi, ecx
    cmp dword [ecx], PE_SIGNATURE
    je print_pe_file
    jmp continue_loop

print_pe_file:
    push edit_path
    push message
    call _printf
    add esp, 8
    
print_dos_header:
    ; In IMAGE_DOS_HEADER
    push dos_header_msg
    call _printf
    add esp, 4

    push word [ebx + IMAGE_DOS_HEADER.e_magic]
    push e_magic
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_cblp]
    push e_cblp
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_cp]
    push e_cp
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_crlc]
    push e_crlc
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_cparhdr]
    push e_cparhdr
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_minalloc]
    push e_minalloc
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_maxalloc]
    push e_maxalloc
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_ss]
    push e_ss
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_sp]
    push e_sp
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_csum]
    push e_csum
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_ip]
    push e_ip
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_cs]
    push e_cs
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_lfarlc]
    push e_lfarlc
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_ovno]
    push e_ovno
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_res]
    push e_res0
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_res + 2]
    push e_res1
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_res + 4]
    push e_res2
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_res + 6]
    push e_res3
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_oemid]
    push e_oemid
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_oeminfo]
    push e_oeminfo
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_res2]
    push e_res2_0
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_res2 + 2]
    push e_res2_1
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_res2 + 4]
    push e_res2_2
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_res2 + 6]
    push e_res2_3
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_res2 + 8]
    push e_res2_4
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_res2 + 10]
    push e_res2_5
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_res2 + 12]
    push e_res2_6
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_res2 + 14]
    push e_res2_7
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_res2 + 16]
    push e_res2_8
    call _printf
    add esp, 8
    push word [ebx + IMAGE_DOS_HEADER.e_res2 + 18]
    push e_res2_9
    call _printf
    add esp, 8
    push dword [ebx + IMAGE_DOS_HEADER.e_lfanew]
    push e_lfanew
    call _printf
    add esp, 8

print_nt_header:
    push nt_header_msg
    call _printf
    add esp, 4

    push dword [esi + IMAGE_NT_HEADERS.Signature]
    push signature
    call _printf
    add esp, 8

print_file_header:
    ; In IMAGE_FILE_HEADER
    push file_header_msg
    call _printf
    add esp, 4

    add esi, 4

    push word [esi + IMAGE_FILE_HEADER.Machine]
    push machine
    call _printf
    add esp, 8

    push word [esi + IMAGE_FILE_HEADER.NumberOfSections]
    push number_of_sections
    call _printf
    add esp, 8
    push dword [esi + IMAGE_FILE_HEADER.TimeDateStamp]
    push time_date_stamp
    call _printf
    add esp, 8
    push dword [esi + IMAGE_FILE_HEADER.PointerToSymbolTable]
    push pointer_to_symbol_table
    call _printf
    add esp, 8
    push dword [esi + IMAGE_FILE_HEADER.NumberOfSymbols]
    push number_of_symbols
    call _printf
    add esp, 8
    push word [esi + IMAGE_FILE_HEADER.SizeOfOptionalHeader]
    push size_of_optional_header
    call _printf
    add esp, 8
    push word [esi + IMAGE_FILE_HEADER.Characteristics]
    push characteristics
    call _printf
    add esp, 8

print_optional_header:
    add esi, 20
    ; 1. In địa chỉ optional_header (tùy chọn)
    push optional_header
    call _printf
    add esp, 4

    ; 2. Magic
    push word [esi + IMAGE_OPTIONAL_HEADER32.Magic]
    push Magic
    call _printf
    add esp, 8

    ; 3. MajorLinkerVersion
    movzx ecx, byte [esi + IMAGE_OPTIONAL_HEADER32.MajorLinkerVersion]
    push ecx
    push MajorLinkerVersion
    call _printf
    add esp, 8

    ; 4. MinorLinkerVersion
    movzx ecx, byte [esi + IMAGE_OPTIONAL_HEADER32.MinorLinkerVersion]
    push ecx
    push MinorLinkerVersion
    call _printf
    add esp, 8

    ; 5. SizeOfCode
    push dword [esi + IMAGE_OPTIONAL_HEADER32.SizeOfCode]
    push SizeOfCode
    call _printf
    add esp, 8

    ; 6. SizeOfInitializedData
    push dword [esi + IMAGE_OPTIONAL_HEADER32.SizeOfInitializedData]
    push SizeOfInitializedData
    call _printf
    add esp, 8

    ; 7. SizeOfUninitializedData
    push dword [esi + IMAGE_OPTIONAL_HEADER32.SizeOfUninitializedData]
    push SizeOfUninitializedData
    call _printf
    add esp, 8

    ; 8. AddressOfEntryPoint
    push dword [esi + IMAGE_OPTIONAL_HEADER32.AddressOfEntryPoint]
    push AddressOfEntryPoint
    call _printf
    add esp, 8

    ; 9. BaseOfCode
    push dword [esi + IMAGE_OPTIONAL_HEADER32.BaseOfCode]
    push BaseOfCode
    call _printf
    add esp, 8

    ; 10. BaseOfData
    push dword [esi + IMAGE_OPTIONAL_HEADER32.BaseOfData]
    push BaseOfData
    call _printf
    add esp, 8

    ; 11. ImageBase
    push dword [esi + IMAGE_OPTIONAL_HEADER32.ImageBase]
    push ImageBase
    call _printf
    add esp, 8

    ; 12. SectionAlignment
    push dword [esi + IMAGE_OPTIONAL_HEADER32.SectionAlignment]
    push SectionAlignment
    call _printf
    add esp, 8

    ; 13. FileAlignment
    push dword [esi + IMAGE_OPTIONAL_HEADER32.FileAlignment]
    push FileAlignment
    call _printf
    add esp, 8

    ; 14. MajorOperatingSystemVersion
    push word [esi + IMAGE_OPTIONAL_HEADER32.MajorOperatingSystemVersion]
    push MajorOperatingSystemVersion
    call _printf
    add esp, 8

    ; 15. MinorOperatingSystemVersion
    push word [esi + IMAGE_OPTIONAL_HEADER32.MinorOperatingSystemVersion]
    push MinorOperatingSystemVersion
    call _printf
    add esp, 8

    ; 16. MajorImageVersion
    push word [esi + IMAGE_OPTIONAL_HEADER32.MajorImageVersion]
    push MajorImageVersion
    call _printf
    add esp, 8

    ; 17. MinorImageVersion
    push word [esi + IMAGE_OPTIONAL_HEADER32.MinorImageVersion]
    push MinorImageVersion
    call _printf
    add esp, 8

    ; 18. MajorSubsystemVersion
    push word [esi + IMAGE_OPTIONAL_HEADER32.MajorSubsystemVersion]
    push MajorSubsystemVersion
    call _printf
    add esp, 8

    ; 19. MinorSubsystemVersion
    push word [esi + IMAGE_OPTIONAL_HEADER32.MinorSubsystemVersion]
    push MinorSubsystemVersion
    call _printf
    add esp, 8

    ; 20. Win32VersionValue
    push dword [esi + IMAGE_OPTIONAL_HEADER32.Win32VersionValue]
    push Win32VersionValue
    call _printf
    add esp, 8

    ; 21. SizeOfImage
    push dword [esi + IMAGE_OPTIONAL_HEADER32.SizeOfImage]
    push SizeOfImage
    call _printf
    add esp, 8

    ; 22. SizeOfHeaders
    push dword [esi + IMAGE_OPTIONAL_HEADER32.SizeOfHeaders]
    push SizeOfHeaders
    call _printf
    add esp, 8

    ; 23. CheckSum
    push dword [esi + IMAGE_OPTIONAL_HEADER32.CheckSum]
    push CheckSum
    call _printf
    add esp, 8

    ; 24. Subsystem
    push word [esi + IMAGE_OPTIONAL_HEADER32.Subsystem]
    push Subsystem
    call _printf
    add esp, 8

    ; 25. DllCharacteristics
    push word [esi + IMAGE_OPTIONAL_HEADER32.DllCharacteristics]
    push DllCharacteristics
    call _printf
    add esp, 8

    ; 26. SizeOfStackReserve
    push dword [esi + IMAGE_OPTIONAL_HEADER32.SizeOfStackReserve]
    push SizeOfStackReserve
    call _printf
    add esp, 8

    ; 27. SizeOfStackCommit
    push dword [esi + IMAGE_OPTIONAL_HEADER32.SizeOfStackCommit]
    push SizeOfStackCommit
    call _printf
    add esp, 8

    ; 28. SizeOfHeapReserve
    push dword [esi + IMAGE_OPTIONAL_HEADER32.SizeOfHeapReserve]
    push SizeOfHeapReserve
    call _printf
    add esp, 8

    ; 29. SizeOfHeapCommit
    push dword [esi + IMAGE_OPTIONAL_HEADER32.SizeOfHeapCommit]
    push SizeOfHeapCommit
    call _printf
    add esp, 8

    ; 30. LoaderFlags
    push dword [esi + IMAGE_OPTIONAL_HEADER32.LoaderFlags]
    push LoaderFlags
    call _printf
    add esp, 8

    ; 31. NumberOfRvaAndSizes
    push dword [esi + IMAGE_OPTIONAL_HEADER32.NumberOfRvaAndSizes]
    push NumberOfRvaAndSizes
    call _printf
    add esp, 8

print_section_header:
    movzx ecx, word [esi + IMAGE_FILE_HEADER.SizeOfOptionalHeader - 20]
    movzx edi, word [esi + IMAGE_FILE_HEADER.NumberOfSections - 20]
    add esi, ecx
    
    ;Section Header
    push section_header_msg
    call _printf
    add esp, 4

    ; In Name (8 bytes)
   xor ebx, ebx          ; index = 0
.loop_sections:
    cmp ebx, edi
    jge .done

    ; In Name (8 bytes)
    push esi           ; địa chỉ tên section (8 bytes null-terminated hoặc padded)
    push section_name_fmt
    call _printf
    add esp, 8

    ; In VirtualSize
    push dword [esi + 8]
    push virtual_size_fmt
    call _printf
    add esp, 8

    ; In VirtualAddress
    push dword [esi + 12]
    push va_fmt
    call _printf
    add esp, 8

    ; In SizeOfRawData
    push dword [esi + 16]
    push raw_size_fmt
    call _printf
    add esp, 8

    ; In PointerToRawData
    push dword [esi + 20]
    push ptr_raw_fmt
    call _printf
    add esp, 8

    ; In Characteristics
    push dword [esi + 36]
    push characteristics_fmt
    call _printf
    add esp, 8

    add esi, 40         ; sang section header tiếp theo
    inc ebx
    jmp .loop_sections

.done:


continue_loop:
    lea eax, [find_data]
    push eax
    push dword [hFind]
    call _FindNextFileA@8
    cmp eax, 0
    jne find_next_file
    jmp find_error
find_error:
    call _GetLastError@0
    cmp eax, ERROR_NO_MORE_FILES
    je find_close

find_close:
    add esp, 4
    push dword [hFind]
    call _FindClose@4
    


exit:
    push 0
    call _ExitProcess@4


