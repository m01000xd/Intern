section .text
    global _main
    extern _printf
    extern _scanf

_main:

    push tbao
    call _printf
    add esp, 4

    push path_root
    push format
    call _scanf
    add esp, 8


    push tbao1
    call _printf
    add esp, 4

    push path_sub
    push format1
    call _scanf
    add esp, 8

    mov esi, path_root       ; con trỏ tới root
    mov edi, path_sub        ; con trỏ tới sub
    mov al, [esi]
    mov bl, [edi]
    xor ecx, ecx
    xor edx, edx


;chuyen chu hoa cua path_root thanh chu thuong
convert_root:
    mov al, [esi+ ecx]
    cmp al, 0
    je reset_index_root
    cmp al, 'A'
    jl next_char_root
    cmp al, 'Z'
    jg next_char_root
    add byte [esi + ecx], 0x20
;nhay sang ki tu tiep theo
next_char_root:
    inc ecx
    jmp convert_root
;reset lai index cua path_root
reset_index_root:
    xor ecx, ecx
    jmp check_valid_root
    
check_valid_root:
    mov al, [esi+ecx]
    cmp al, 0
    je out
    cmp al, 'a'
    jl out
    cmp al, 'z'
    jg out
    inc ecx
    mov al, [esi+ecx]
    cmp al, 0x3a
    jne out
    inc ecx
    mov al, [esi+ecx]
    cmp al, 0x5c
    jne out

;tuong tu nhu root, cac ham duoi de convert path_sub va kiem tra hop le
convert_sub:
    mov bl, [edi + edx]
    cmp bl, 0
    je reset_index_sub
    cmp bl, 'A'
    jl next_char_sub
    cmp bl, 'Z'
    jg next_char_sub
    add byte [edi + edx], 0x20

next_char_sub:
    inc edx
    jmp convert_sub

reset_index_sub:
    xor edx, edx
    jmp check_valid_sub

check_valid_sub:
    mov bl, [edi+edx]
    cmp bl, 0
    je out
    cmp bl, 'a'
    jl out
    cmp bl, 'z'
    jg out
    inc edx
    mov bl, [edi+edx]
    cmp bl, 0x3a
    jne out
    inc edx
    mov bl, [edi+edx]
    cmp bl, 0x5c
    jne out

;ham kiem tra chinh
func:
    mov al, [esi+ecx]
    mov bl, [edi+edx]
    cmp al, 0
    je check_sub
    cmp al, bl
    jne out
    inc ecx
    inc edx
    jmp func

;kiem tra duong dan con 
check_sub:
    mov bl, [edi+ecx]
    cmp bl, 0x5c
    jne out
    jmp result
    

out:
    push msg
    call _printf
    add esp, 4
    ret
result:
    push msg1
    call _printf
    add esp, 4
    ret


section .data
tbao db 'Nhap path_root: ', 0
tbao1 db 'Nhap path_sub: ', 0

msg  db 'False', 0
msg1 db 'True', 0
format db "%s", 0
format1 db "%s", 0
section .bss
    path_root resb 260
    path_sub  resb 260