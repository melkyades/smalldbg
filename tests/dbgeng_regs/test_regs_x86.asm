; x86 (32-bit) register test points - MASM syntax
; Assemble with: ml /c /Fo test_regs_x86.obj test_regs_x86.asm
;
; Each function loads known values into registers, then hits int3.
; The debugger can verify which register-reading API returns correct values.

.model flat, C
.code

; ----------------------------------------------------------------------------
; Test point 1: small distinctive values
; Expected: eax=1 ebx=2 ecx=3 edx=4 esi=5 edi=6
; ----------------------------------------------------------------------------
test_regs_small PROC
    push ebp
    mov  ebp, esp
    push ebx
    push esi
    push edi

    mov  eax, 1
    mov  ebx, 2
    mov  ecx, 3
    mov  edx, 4
    mov  esi, 5
    mov  edi, 6
    int  3

    pop  edi
    pop  esi
    pop  ebx
    pop  ebp
    ret
test_regs_small ENDP

; ----------------------------------------------------------------------------
; Test point 2: large distinctive values (32-bit)
; Expected: eax=AABBCCDD ebx=11223344 ecx=55667788 
;           edx=99AABBCC esi=DDEEFF00 edi=12345678
; ----------------------------------------------------------------------------
test_regs_large32 PROC
    push ebp
    mov  ebp, esp
    push ebx
    push esi
    push edi

    mov  eax, 0AABBCCDDh
    mov  ebx, 011223344h
    mov  ecx, 055667788h
    mov  edx, 099AABBCCh
    mov  esi, 0DDEEFF00h
    mov  edi, 012345678h
    int  3

    pop  edi
    pop  esi
    pop  ebx
    pop  ebp
    ret
test_regs_large32 ENDP

; ----------------------------------------------------------------------------
; Test point 3: all 0xDEADBEEF
; Expected: eax=DEADBEEF ebx=DEADBEEF ecx=DEADBEEF 
;           edx=DEADBEEF esi=DEADBEEF edi=DEADBEEF
; ----------------------------------------------------------------------------
test_regs_deadbeef PROC
    push ebp
    mov  ebp, esp
    push ebx
    push esi
    push edi

    mov  eax, 0DEADBEEFh
    mov  ebx, 0DEADBEEFh
    mov  ecx, 0DEADBEEFh
    mov  edx, 0DEADBEEFh
    mov  esi, 0DEADBEEFh
    mov  edi, 0DEADBEEFh
    int  3

    pop  edi
    pop  esi
    pop  ebx
    pop  ebp
    ret
test_regs_deadbeef ENDP

END
