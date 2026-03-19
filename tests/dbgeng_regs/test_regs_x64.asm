; x64 (64-bit) register test points - MASM syntax
; Assemble with: ml64 /c /Fo test_regs_x64.obj test_regs_x64.asm
;
; Each function loads known values into registers, then hits int3.
; The debugger can verify which register-reading API returns correct values.

.code

; ----------------------------------------------------------------------------
; Test point 1: small distinctive values
; Expected: rax=1 rbx=2 rcx=3 rdx=4 rsi=5 rdi=6 r8=7 r9=8
; ----------------------------------------------------------------------------
test_regs_small PROC
    push rbp
    mov  rbp, rsp
    push rbx
    push rsi
    push rdi

    mov  rax, 1
    mov  rbx, 2
    mov  rcx, 3
    mov  rdx, 4
    mov  rsi, 5
    mov  rdi, 6
    mov  r8,  7
    mov  r9,  8
    int  3

    pop  rdi
    pop  rsi
    pop  rbx
    pop  rbp
    ret
test_regs_small ENDP

; ----------------------------------------------------------------------------
; Test point 2: large distinctive values (32-bit, zero-extended)
; Expected: rax=AABBCCDD rbx=11223344 rcx=55667788 
;           rdx=99AABBCC rsi=DDEEFF00 rdi=12345678
;           r8=CAFEBABE r9=FEEDFACE
; ----------------------------------------------------------------------------
test_regs_large32 PROC
    push rbp
    mov  rbp, rsp
    push rbx
    push rsi
    push rdi

    mov  eax, 0AABBCCDDh
    mov  ebx, 011223344h
    mov  ecx, 055667788h
    mov  edx, 099AABBCCh
    mov  esi, 0DDEEFF00h
    mov  edi, 012345678h
    mov  r8d, 0CAFEBABEh
    mov  r9d, 0FEEDFACEh
    int  3

    pop  rdi
    pop  rsi
    pop  rbx
    pop  rbp
    ret
test_regs_large32 ENDP

; ----------------------------------------------------------------------------
; Test point 3: full 64-bit values
; Note: MASM doesn't support 64-bit immediate mov directly, use mov r64, imm64
; with explicit size or use two-instruction sequence.
; Actually ml64 DOES support mov reg, imm64 but the constant must be valid.
; The issue was hex constant starting with letter needs leading 0.
; ----------------------------------------------------------------------------
test_regs_large64 PROC
    push rbp
    mov  rbp, rsp
    push rbx
    push rsi
    push rdi

    ; Use mov with 64-bit immediate (ml64 supports this)
    mov  rax, 123456789ABCDEF0h
    mov  rbx, 0FEDCBA9876543210h
    mov  rcx, 0AAAABBBBCCCCDDDDh
    mov  rdx, 1111222233334444h
    mov  rsi, 5555666677778888h
    mov  rdi, 9999AAAABBBBCCCCh
    mov  r8,  0DDDDEEEEFFFF0000h
    mov  r9,  1000200030004h
    int  3

    pop  rdi
    pop  rsi
    pop  rbx
    pop  rbp
    ret
test_regs_large64 ENDP

; ----------------------------------------------------------------------------
; Test point 4: all 0xDEADBEEFDEADBEEF
; ----------------------------------------------------------------------------
test_regs_deadbeef PROC
    push rbp
    mov  rbp, rsp
    push rbx
    push rsi
    push rdi

    mov  rax, 0DEADBEEFDEADBEEFh
    mov  rbx, 0DEADBEEFDEADBEEFh
    mov  rcx, 0DEADBEEFDEADBEEFh
    mov  rdx, 0DEADBEEFDEADBEEFh
    mov  rsi, 0DEADBEEFDEADBEEFh
    mov  rdi, 0DEADBEEFDEADBEEFh
    mov  r8,  0DEADBEEFDEADBEEFh
    mov  r9,  0DEADBEEFDEADBEEFh
    int  3

    pop  rdi
    pop  rsi
    pop  rbx
    pop  rbp
    ret
test_regs_deadbeef ENDP

END
