section .data
  pathname db "./openme.txt", 0   ; filename (terminated with null character)

section .bss
buffer: resb 4                    ; create a buffer and reserve 4 bytes

section .text
global _start

_start:
  call read_file
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

