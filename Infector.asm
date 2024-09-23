section .data
  pathname db ".", 0                   ; le répertoire actuel
  elf_magic db 0x7f, 0x45, 0x4c, 0x46  ; les numéros magiques ELF (0x7f 'E' 'L' 'F')
  is_elf_msg db " is an ELF file", 0xA, 0  ; message pour les fichiers ELF
  not_elf_msg db " is not an ELF file", 0xA, 0 ; message pour les fichiers non-ELF
  err db "erreur", 0xA, 0              ; message erreur

section .bss
  buffer resb 4096                     ; tampon pour les entrées de répertoire (non initialisé, donc dans .bss)
  temp_file resb 256                   ; tampon pour les noms de fichiers temporaires (non initialisé)

section .text
global _start

_start:
  ; Ouvre le répertoire actuel et liste son contenu
  call list_directory

  ; Quitte le programme avec succès
  mov rax, 60                          ; numéro de syscall pour 'exit'
  xor rdi, rdi                         ; code de sortie 0 (succès)
  syscall                              ; appel du kernel (exit)

error:
  ; Gère les erreurs (sortie avec le code 1 si quelque chose tourne mal)
  mov rdi, err
  mov rsi, 20
  call write_message

  mov rax, 60                          ; numéro de syscall pour 'exit'
  mov rdi, 1                           ; code de sortie 1 (erreur)
  syscall                              ; exécute le syscall (exit)

; -----------------------------
; Fonction: list_directory
; Cette fonction lit les entrées du répertoire et traite chaque fichier.
; -----------------------------
list_directory:
  ; Ouvre le répertoire courant
  mov rax, 2                           ; numéro de syscall pour 'open' (2 pour 'openat')
  mov rdi, pathname                    ; pointeur vers le nom du répertoire
  xor rsi, rsi                         ; flags = 0 (O_RDONLY)
  syscall                              ; exécute le syscall

  ; Vérifie si l'ouverture du répertoire a réussi
  cmp rax, 0
  jl error                             ; si rax < 0, une erreur s'est produite (saut vers error)
  mov rdi, rax                         ; descripteur de fichier du répertoire

  ; Lit les entrées du répertoire avec getdents
  mov rax, 0x4e                          ; numéro de syscall pour 'getdents' (78 en x86_64)
  mov rsi, buffer                      ; tampon pour stocker les entrées de répertoire
  mov rdx, 4096                        ; taille du tampon
  syscall                              ; exécute le syscall

  ; print output of getdents
  ;mov rdi, buffer
  ;mov rsi, 4096
  ;call write_message

  ; Vérifie si le syscall a réussi
  cmp rax, 0
  jl error                             ; si rax < 0, une erreur s'est produite (saut vers error)
  
  ; Traite chaque entrée
  mov rbx, buffer                      ; rbx pointe vers le début du tampon
  call process_entry                   ; appel de la fonction pour traiter les entrées
  ret                                  ; retour au programme principal

; -----------------------------
; Fonction: process_entry
; Cette fonction traite chaque entrée de répertoire lue dans le tampon.
; -----------------------------
process_entry:
  ; Obtenir le nom du fichier
  mov rdi, rbx                          ; rbx pointe vers l'entrée actuelle dans le tampon
  add rdi, 18                           ; décalage vers le nom de fichier dans la structure dirent
  ;call write_message

  mov rsi, temp_file                    ; déplacer vers le tampon temp_file
  call copy_filename                    ; copier le nom de fichier dans temp_file

  ; Imprimer le nom du fichier
  mov rdi, rsi
  mov rsi, 10
  call write_message                   ; imprimer le nom de fichier sur stdout
  ;call write_filename                   ; imprimer le nom de fichier sur stdout
  
  ; Ouvre et vérifie si le fichier est un fichier ELF
  call read_file
  ;call write_message_ELF
  call check_ELF_file

  ; Passe à l'entrée suivante du répertoire
  movzx eax, word [rbx + 4]             ; charge la valeur de d_reclen (2 octets) dans rax
  add rbx, rax                          ; ajoute d_reclen à rbx pour passer à l'entrée suivante

  ; Vérifie si nous avons atteint la fin du tampon
  lea rsi, [buffer + rdx]               ; charge l'adresse effective de buffer + rdx dans rsi
  cmp rbx, rsi                          ; compare rbx avec la fin du tampon
  jb process_entry                      ; si pas encore à la fin, continue de traiter

  ret                                   ; retourne au programme principal

; -----------------------------
; Fonction: copy_filename
; Cette fonction copie le nom du fichier de l'entrée du répertoire dans le tampon temp_file.
; Entrées:
;   rdi = source (nom du fichier dans le tampon)
;   rsi = destination (tampon temp_file)
; -----------------------------
copy_filename:
  mov rcx, 256                         ; limite à 256 caractères
copy_loop:
  lodsb                                ; charge le prochain octet de la source dans al
  stosb                                ; stocke al dans la destination
  cmp al, 0                            ; vérifie s'il s'agit du terminateur nul
  je done_copying
  loop copy_loop                       ; répète jusqu'à ce que tous les caractères soient copiés
done_copying:
  ret                                  ; retourne à l'appelant

; -----------------------------
; Fonction: read_file
; Cette fonction ouvre un fichier et lit ses 4 premiers octets dans le tampon.
; Entrées:
;   temp_file contient le nom du fichier à ouvrir
; -----------------------------
read_file:
  ; Ouvre le fichier
  mov rax, 2                           ; numéro de syscall pour 'open'
  mov rdi, temp_file                   ; pointeur vers le nom de fichier (1er argument de 'open')
  xor rsi, rsi                         ; flags = 0 (O_RDONLY = 0) pour mode lecture seule
  syscall                              ; exécute le syscall

  ; Vérifie si le fichier a été ouvert avec succès
  cmp rax, 0
  jl error                             ; si rax < 0, une erreur s'est produite (saut vers error)

  ; Lit les 4 premiers octets du fichier
  mov rdi, rax                         ; déplace le descripteur de fichier renvoyé par 'open' dans rdi
  mov rax, 0                           ; numéro de syscall pour 'read'
  mov rsi, buffer                      ; tampon pour stocker le contenu du fichier
  mov rdx, 4                           ; nombre d'octets à lire (4 octets)
  syscall                              ; exécute le syscall


  ; Vérifie si la lecture a réussi
  cmp rax, 0
  jl error                             ; si rax < 0, une erreur s'est produite (saut vers error)

  ret                                  ; retourne à l'appelant

; -----------------------------
; Fonction: check_ELF_file
; Cette fonction vérifie si le fichier commence par le numéro magique ELF (0x7f 45 4c 46).
; Si le fichier n'est pas un fichier ELF, il passe au suivant.
; -----------------------------
check_ELF_file:
  ; Compare les quatre premiers octets du tampon avec le numéro magique ELF
  mov eax, [buffer]                    ; charge les 4 premiers octets du fichier
  cmp eax, [elf_magic]                 ; compare avec le numéro magique ELF
  jne not_elf                          ; si différent, ce n'est pas un fichier ELF

  ; Le fichier est un fichier ELF, imprime un message
  mov rdi, temp_file                   ; pointeur vers le nom du fichier dans temp_file
  call write_filename                  ; écrit le nom du fichier
  mov rdi, is_elf_msg                  ; message "is an ELF file"
  call write_message                   ; écrit le message
  ret                                  ; retourne à l'appelant

not_elf:
  ; Le fichier n'est pas un fichier ELF, imprime un message
  mov rdi, temp_file                   ; pointeur vers le nom du fichier dans temp_file
  call write_filename                  ; écrit le nom du fichier
  mov rdi, not_elf_msg                 ; message "is not an ELF file"
  call write_message                   ; écrit le message
  ret                                  ; retourne à l'appelant

; -----------------------------
; Fonction: write_filename
; Cette fonction écrit le nom du fichier sur la sortie standard.
; -----------------------------
write_filename:
  ; Trouver la longueur réelle de la chaîne dans temp_file (jusqu'au null)
  mov rsi, temp_file                   ; pointer vers temp_file
  xor rcx, rcx                         ; compteur de longueur = 0

find_null:
  cmp byte [rsi + rcx], 0              ; comparer chaque octet avec 0 (null)
  je write_now                         ; si null trouvé, passer à l'écriture
  inc rcx                              ; sinon, incrémenter le compteur
  cmp rcx, 256                         ; limite à 256 caractères
  jb find_null                         ; continuer jusqu'à atteindre la fin ou 256 octets

write_now:
  ; Écrit le nom du fichier sur stdout
  mov rax, 1                           ; numéro de syscall pour 'write'
  mov rdi, 1                           ; descripteur de fichier pour stdout (1)
  mov rsi, temp_file                   ; pointer vers temp_file pour l'écriture
  mov rdx, rcx                         ; longueur réelle du fichier (jusqu'au null)
  syscall                              ; exécuter le syscall
  ret                                  ; retourner à l'appelant

; -----------------------------
; Fonction: write_message
; Cette fonction écrit un message (soit message ELF soit non-ELF) sur la sortie standard.
; -----------------------------
write_message:
  ; Écrit le message sur stdout
  mov rdx, rsi
  mov rsi, rdi
  mov rax, 1                           ; numéro de syscall pour 'write'
  mov rdi, 1                           ; descripteur de fichier pour stdout (1)
  ;mov rdx, 10                         ; imprime jusqu'à 256 octets (bien que le message soit plus court)
  syscall                              ; exécute le syscall
  ret
