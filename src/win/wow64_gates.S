/* wow64_gates.S — the WoW64 mode-switch trampolines.
 *
 * wow64_thunk_gate and wow64_exit_gate are COPIED into low (<4GB) memory at
 * init because 32-bit far-returns can only target 32-bit addresses; the
 * 64-bit dispatch function address is patched into an embedded slot
 * (wow64_thunk_gate_disp). Everything is RIP-independent: only the patched
 * slot and immediates are absolute.
 *
 * wow64_call12 and wow64_enter32_asm run in place (called from 64-bit C).
 *
 * Offsets mirror wn_wow64_thread (asserted in wow64.c at init):
 *   0 teb32, 8 scratch, 16 stack_low, 24 stack_size, 32 host_fsbase,
 *   40 exit_blk, 48 host_rsp[16], 176 depth, 180 start32, 184 param32
 * Scratch layout: 0x00 exit_blk[4], 0x20 exit_frame[8], 0x40 enter_frame.
 */
.intel_syntax noprefix

.set WT_TEB32,   0
.set WT_SCRATCH, 8
.set WT_HOSTFS,  32
.set WT_EXITBLK, 40
.set WT_HOSTRSP, 48
.set WT_DEPTH,   176
.set SCR_EXITFRAME, 0x20

.text

/* ---------------------------------------------------------------------------
 * thunk_gate: entered from 32-bit guest code via
 *   push funcid32; push 0x33; push thunk_gate; retf
 * Entry (64-bit mode): [rsp]=funcid32 [rsp+4]=ret32 [rsp+8]=args...
 */
.globl wow64_thunk_gate
wow64_thunk_gate:
    mov     r10, rsp                /* frame base: [r10]=funcid, +4=ret32, +8=args */
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    push    rsi
    push    rdi
    and     rsp, -16
    sub     rsp, 16
    mov     [rsp], r10              /* stash frame ptr */
    mov     rax, qword ptr gs:[0x30]
    mov     r11, qword ptr [rax + 0xE8]     /* wt */
    mov     [rsp+8], r11
    mov     rsi, qword ptr [r11 + WT_HOSTFS]
    mov     eax, 158                /* SYS_arch_prctl */
    mov     edi, 0x1002             /* ARCH_SET_FS  */
    syscall
    mov     rdi, qword ptr [rsp+8]  /* wt */
    mov     rsi, r10                /* frame */
    mov     rax, qword ptr [rip + wow64_thunk_gate_disp]
    call    rax
    /* rax = retval, rdx = retval_hi (pass through to the guest) */
    mov     rbx, qword ptr [rsp+8]  /* wt */
    mov     r11, qword ptr [rbx + WT_EXITBLK]
    mov     r9,  qword ptr [r11 + 8]    /* new_esp32 */
    mov     r11, qword ptr [r11 + 16]   /* ret32    */
    mov     ecx, 0x2b
    mov     fs, ecx                 /* guest FS: flat, base 0 (rax = retval!) */
    mov     r12, qword ptr [rsp]    /* frame (r10 stash, captured pre-pushes) */
    lea     rsp, [r12 - 64]         /* the 8 pushed regs live BELOW frame */
    pop     rdi
    pop     rsi
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    mov     rsp, r9                 /* new_esp32 */
    sub     rsp, 16
    mov     [rsp], r11              /* RIP slot */
    mov     dword ptr [rsp+8], 0x23 /* CS slot */
    .byte 0x48, 0xCB           /* retfq */
.globl wow64_thunk_gate_disp
wow64_thunk_gate_disp:
    .quad 0                            /* patched with wow64_dispatch_c */
.globl wow64_thunk_gate_end
wow64_thunk_gate_end:

/* ---------------------------------------------------------------------------
 * exit_gate: 32-bit code far-returns here (ret_thunk32 lands on it).
 * Entry (64-bit): RSP = guest esp32 at the moment of the return.
 */
.globl wow64_exit_gate
wow64_exit_gate:
    mov     r11d, eax                      /* guest eax FIRST (rax is clobbered) */
    mov     rax, qword ptr gs:[0x30]
    mov     r10, qword ptr [rax + 0xE8]     /* wt (r10 survives syscall) */
    mov     rax, qword ptr [r10 + WT_SCRATCH]
    add     rax, SCR_EXITFRAME
    mov     dword ptr [rax+0],  r11d       /* capture eax before syscalls */
    mov     dword ptr [rax+4],  ebx
    mov     dword ptr [rax+8],  ecx
    mov     dword ptr [rax+12], edx
    mov     dword ptr [rax+16], esi
    mov     dword ptr [rax+20], edi
    mov     dword ptr [rax+24], ebp
    mov     dword ptr [rax+28], esp
    mov     rsi, qword ptr [r10 + WT_HOSTFS]
    mov     eax, 158
    mov     edi, 0x1002
    syscall
    mov     ecx, dword ptr [r10 + WT_DEPTH]
    mov     rsp, qword ptr [r10 + WT_HOSTRSP + rcx*8]
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
.globl wow64_exit_gate_end
wow64_exit_gate_end:

/* ---------------------------------------------------------------------------
 * wow64_enter32_asm(wt in rdi, enter_frame in rsi)
 * 64->32 call. enter frame (low): target32@0, esp32@4,
 * regs[7]@8 (eax,ebx,ecx,edx,esi,edi,ebp).
 */
.globl wow64_enter32_asm
wow64_enter32_asm:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    mov     eax, dword ptr [rdi + WT_DEPTH]
    lea     rbx, [rdi + WT_HOSTRSP]
    mov     [rbx + rax*8], rsp
    mov     r8d, dword ptr [rsi+0]      /* target32 */
    mov     r9d, dword ptr [rsi+4]      /* esp32   */
    mov     r10d, dword ptr [rsi+28]    /* guest edi (stashed) */
    mov     r11d, dword ptr [rsi+32]    /* guest ebp (stashed) */
    mov     eax, dword ptr [rsi+8]
    mov     ebx, dword ptr [rsi+12]
    mov     ecx, dword ptr [rsi+16]
    mov     edx, dword ptr [rsi+20]
    mov     esi, dword ptr [rsi+24]
    mov     eax, 0x2b
    mov     ds, ax
    mov     es, ax
    mov     ss, ax
    mov     fs, ax
    mov     edi, r10d
    mov     ebp, r11d
    mov     rsp, r9
    sub     rsp, 16
    mov     [rsp], r8
    mov     dword ptr [rsp+8], 0x23
    .byte 0x48, 0xCB           /* retfq */

/* ---------------------------------------------------------------------------
 * void *wow64_call12(fn, a, d, nd) - SysV: rdi, rsi, rdx, ecx
 * Calls an ms_abi function with 12 GP register/stack args + up to 3 XMM
 * doubles. Extra args are ignored by the callee (registers/stack the callee
 * never reads), so one shim serves every builtin regardless of arity.
 */
.globl wow64_call12
wow64_call12:
    mov     r10, rdx                 /* d */
    mov     r11d, ecx                /* nd (save before rcx reuse) */
    mov     rcx, qword ptr [rsi]     /* a0 */
    mov     rdx, qword ptr [rsi+8]   /* a1 */
    mov     r8,  qword ptr [rsi+16]  /* a2 */
    mov     r9,  qword ptr [rsi+24]  /* a3 */
    sub     rsp, 0x68                /* 0x20 shadow + 8 stack args + align */
    mov     rax, qword ptr [rsi+32]
    mov     [rsp+0x20], rax
    mov     rax, qword ptr [rsi+40]
    mov     [rsp+0x28], rax
    mov     rax, qword ptr [rsi+48]
    mov     [rsp+0x30], rax
    mov     rax, qword ptr [rsi+56]
    mov     [rsp+0x38], rax
    mov     rax, qword ptr [rsi+64]
    mov     [rsp+0x40], rax
    mov     rax, qword ptr [rsi+72]
    mov     [rsp+0x48], rax
    mov     rax, qword ptr [rsi+80]
    mov     [rsp+0x50], rax
    mov     rax, qword ptr [rsi+88]
    mov     [rsp+0x58], rax
    test    r11d, r11d
    jz      1f
    movsd   xmm0, qword ptr [r10]
    cmp     r11d, 1
    jbe     1f
    movsd   xmm1, qword ptr [r10+8]
    cmp     r11d, 2
    jbe     1f
    movsd   xmm2, qword ptr [r10+16]
1:
    call    rdi
    add     rsp, 0x68
    ret


.section .note.GNU-stack, "", @progbits
