section .data
  pathname db "./ls", 0   ; filename (terminated with null character)

  error_msg db "Il y a un probleme", 0xA ; Message when e_entry matches
  error_msg_len equ $ - error_msg           ; Length of the match message

  match_msg db "Entry Point Match", 0xA ; Message when e_entry matches
  match_len equ $ - match_msg           ; Length of the match message

  matchPHNUM_msg db "PHNUM Match", 0xA ; Message when e_entry matches
  matchPHNUM_len equ $ - matchPHNUM_msg           ; Length of the match message

  note_msg db "PT_NOTE segment FOUND", 0xA ; Message to print
  note_len equ $ - note_msg         ; Message length

  headerMessage db "Im in a PH segment", 0xA ; Message to print
  headerMessagelen equ $ - headerMessage         ; Message length


section .bss
ELF_Header: resb 64                    ; ELF header buffer
ph_entry: resb 64                      ; Program header entry buffer
e_entry_point: resb 8                  ; Entry point field
e_phoff: resb 8                        ; Program header offset field
e_phentsize: resb 2                    ; Program header entry size field
e_phnum: resb 2                        ; Number of program headers field
fd resq 1                              ; File descriptor
statbuf resb 144                  ; reserve space for the stat struct

section .text
global _start

_start:
  call read_file
  call check_ELF_file
  call save_Important_field_ELF_Header
  call compare_entry_point
  ;call compare_e_phnum
  call find_PT_NOTE
  call write_output

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
  xor rsi, rsi          ; flags = 0 (O_RDONLY = 0) for read-only mode
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
; It uses the 'write' syscall to display the data on the terminal.
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


compare_entry_point:
  ; Compare the saved e_entry_point with a hardcoded value (e.g., 0x5130)
  mov rax, qword [e_entry_point] ; Load the saved e_entry_point
  cmp rax, 0x5130               ; Compare it with the expected value
  je entry_point_match          ; If equal, jump to match label

compare_e_phnum:
    movzx rax, word [e_phnum]   ; Load e_phnum (2 bytes) into RAX, zero-extend it
    cmp rax, 13                ; Compare with 13 (0x0D)
    ;je e_phnum_match            ; If equal, jump to match label

  ret

entry_point_match:
  ; Do something when entry point matches
  ; For example, print "Entry Point Match"
  mov rax, 1                    ; syscall: write
  mov rdi, 1                    ; stdout
  lea rsi, [match_msg]          ; Pointer to the "Match" message
  mov rdx, match_len            ; Length of the message
  syscall
  ret

e_phnum_match:
  ; Do something when entry point matches
  ; For example, print "Entry Point Match"
  mov rax, 1                    ; syscall: write
  mov rdi, 1                    ; stdout
  lea rsi, [matchPHNUM_msg]          ; Pointer to the "Match" message
  mov rdx, matchPHNUM_len            ; Length of the message
  syscall
  ret

; -----------------------------
; Function: find_PT_NOTE
; Loop through all program headers to find a PT_NOTE segment.
; -----------------------------
find_PT_NOTE:
  mov rbx, [e_phoff]                ; Start of program header table
  movzx rcx, word [e_phnum]         ; Number of program headers
  movzx rdx, word [e_phentsize]     ; Size of each program header

loop_ph:
  test rcx, rcx                     ; Check if we've processed all headers
  jz done_ph

  ; Save important registers before syscall
  push rdx
  push rcx

  ; Restore registers after syscall
  pop rcx

  ; Read the current program header
  mov rdi, rbx                      ; Offset to the current program header
  lea rsi, [ph_entry]               ; Buffer to store the program header
  mov rdx, 64                       ; Read 64 bytes (PH size)
  call read_at_offset

  pop rdx

  ; Check if the segment is PT_NOTE
  mov eax, dword [ph_entry]         ; Load Type field (first 4 bytes)
  cmp eax, 0x4                      ; Compare with PT_NOTE (0x4)
  jne next_ph

  ; PT_NOTE found: Print the message
  push rdx
  push rcx
  mov rax, 1                        ; syscall: write
  mov rdi, 1                        ; stdout
  lea rsi, [note_msg]               ; Message buffer
  mov rdx, note_len                 ; Message length
  syscall
  pop rcx
  pop rdx

next_ph:
  add rbx, rdx                      ; Move to the next program header
  dec rcx                           ; Decrement header count
  jmp loop_ph

done_ph:
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
; -----------------------------
; Function: write_output
; This function writes the content of the buffer to the standard output (stdout).
; It uses the 'write' syscall to display the data on the terminal.
; -----------------------------
write_output:
  ; Write the buffer content to stdout
  mov rax, 1            ; syscall number for 'write'
  mov rdi, 1            ; file descriptor for stdout (1)
  mov rsi, ELF_Header       ; buffer containing the data to write
  mov rdx, 4            ; number of bytes to write (4 bytes)
  syscall

  ; Write the saved entry point for debugging
  ;mov rax, 1              ; syscall: write
  ;mov rdi, 1              ; stdout
  ;lea rsi, [e_entry_point] ; Pointer to entry point
  ;mov rdx, 8              ; Write 8 bytes
  ;syscall

; Write the saved entry point for debugging
  ;mov rax, 1              ; syscall: write
  ;mov rdi, 1              ; stdout
  ;lea rsi, [e_phoff] ; Pointer to entry point
  ;mov rdx, 8              ; Write 8 bytes
  ;syscall

; Write the saved entry point for debugging
  mov rax, 1              ; syscall: write
  mov rdi, 1              ; stdout
  lea rsi, [e_phentsize] ; Pointer to entry point
  mov rdx, 2              ; Write 8 bytes
  syscall

; Write the saved entry point for debugging
  mov rax, 1              ; syscall: write
  mov rdi, 1              ; stdout
  lea rsi, [e_phnum] ; Pointer to entry point
  mov rdx, 2              ; Write 8 bytes
  syscall

  ret                   ; return to caller

