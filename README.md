# **ELF Infector Project**

## **Project Description**  
This project is an ELF file infector written in x86_64 assembly. The goal is to manipulate and inject a payload into an ELF executable while maintaining its original functionality. Specifically, the project targets the executable `/usr/bin/ls` as the base file for testing.

## **Features**  
- Modifies the ELF program header to change the `PT_NOTE` segment into a `PT_LOAD` segment.  
- Injects custom shellcode at the end of the executable.  
- Adjusts critical ELF fields such as `p_filesz`, `p_memsz`, and `e_entry_point` to execute the payload while preserving the original functionality.  

## **Requirements**  
- **Architecture**: x86_64  
- **OS**: Linux (tested on distributions supporting the ELF format).  
- **Tools Needed**:  
   - `nasm` (Netwide Assembler) for compiling the assembly code.  
   - `ld` (GNU linker) for linking the object files.  
   - `gdb` with `pwndbg` plugin for debugging and inspecting ELF files.  
   - `readelf` for inspecting ELF headers and sections.  

## **How to Compile and Run**  

1. **Assemble the Code**  
   Use `nasm` to assemble the source code into an object file:  
   ```bash
   nasm -f elf64 -o infector.o infector.asm
   ```
2. **Link the Object File**
   Link the object file to create the final executable:
   ```bash
   ld -o infector infector.o
   ```
3. **Run the ELF Infector**
   Provide a copy of it as the target executable, execute the malware then execute the target executable:
   ```bash
   cp /usr/bin/ls && ./infector && ./ls
   ```
## **Notes**
- Always test this program in a controlled environment (e.g., a virtual machine or sandbox).
- Modify only copies of /usr/bin/ls to avoid corruption of system files.
- This project is strictly for educational purposes to understand ELF binaries and assembly programming
   
