section .data
  pathname db "./Infector", 0   ; filename (terminated with null character)

section .bss
buffer: resb 4                    ; create a buffer and reserve 4 bytes

section .text
global _start

_start:
  call read_file
  call check_ELF_file
  call write_output

  ; Finish the execution successfully
  mov rax, 60           ; syscall number for 'exit'
  xor rdi, rdi          ; exit code 0 (success)
  syscall

error:
  ; Handle errors (exit with code 1 if something goes wrong)
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

  ; Read the content of the file
  mov rdi, rax          ; move file descriptor returned by 'open' to rdi
  mov rax, 0            ; syscall number for 'read'
  mov rsi, buffer       ; buffer to store the file content
  mov rdx, 4            ; number of bytes to read (4 bytes)
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
  mov al, byte [buffer]  ; load the first byte of the buffer into al
  cmp al, 0x7f           ; compare with 0x7f (ELF magic number prefix)
  jne error              ; if not equal, jump to error

  ; Check the second byte (should be 'E' = 0x45)
  mov al, byte [buffer + 1]  ; load the second byte of the buffer
  cmp al, 0x45           ; compare with 'E' (0x45 in hex)
  jne error              ; if not equal, jump to error

  ; Check the third byte (should be 'L' = 0x4C)
  mov al, byte [buffer + 2]  ; load the third byte of the buffer
  cmp al, 0x4C           ; compare with 'L' (0x4C in hex)
  jne error              ; if not equal, jump to error

  ; Check the fourth byte (should be 'F' = 0x46)
  mov al, byte [buffer + 3]  ; load the fourth byte of the buffer
  cmp al, 0x46           ; compare with 'F' (0x46 in hex)
  jne error              ; if not equal, jump to error

  ret                    ; return to caller if ELF file is valid

; -----------------------------
; Function: write_output
; This function writes the content of the buffer to the standard output (stdout).
; It uses the 'write' syscall to display the data on the terminal.
; -----------------------------
write_output:
  ; Write the buffer content to stdout
  mov rax, 1            ; syscall number for 'write'
  mov rdi, 1            ; file descriptor for stdout (1)
  mov rsi, buffer       ; buffer containing the data to write
  mov rdx, 4            ; number of bytes to write (4 bytes)
  syscall

  ret                   ; return to caller

