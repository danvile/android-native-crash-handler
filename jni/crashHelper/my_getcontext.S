#if defined(__arm__)
#define  MCONTEXT_GREGS_OFFSET     32
#define  UCONTEXT_SIGMASK_OFFSET   104
  .text
  .global my_getcontext
  .hidden my_getcontext
  .type my_getcontext, #function
  .align 0
  .fnstart
my_getcontext:
  // 取得 ucontext.uc_mcontext 寄存器区域
  add   r1, r0, #(MCONTEXT_GREGS_OFFSET + 4*4)
  stm   r1, {r4-r11}                              // 保存 r4-r11 寄存器
  str   sp, [r0, #(MCONTEXT_GREGS_OFFSET + 13*4)] // 保存堆栈指针寄存器
  str   lr, [r0, #(MCONTEXT_GREGS_OFFSET + 14*4)] // 保存指令指针寄存器
  str   lr, [r0, #(MCONTEXT_GREGS_OFFSET + 15*4)]
  
  // sigprocmask(r4, UCONTEXT_SIGMASK_OFFSET, 0);
  mov   r4, r0
  mov   r0, #0
  mov   r1, #0
  add   r2, r4, #UCONTEXT_SIGMASK_OFFSET
  bl    sigprocmask(PLT)
  
  mov   r0, r4
  ldr   lr, [r0, #(MCONTEXT_GREGS_OFFSET + 14*4)]
  ldr   r4, [r0, #(MCONTEXT_GREGS_OFFSET +  4*4)]

  mov   r0, #0
  bx    lr

  .fnend
  .size my_getcontext, . - my_getcontext

#elif defined(__aarch64__)
#define  UCONTEXT_SIGMASK_OFFSET     40
#define  MCONTEXT_GREGS_OFFSET       184
#define  MCONTEXT_SP_OFFSET          432
#define  MCONTEXT_PC_OFFSET          440
#define  MCONTEXT_PSTATE_OFFSET      448
#define  MCONTEXT_EXTENSION_OFFSET   464
#define  FPSIMD_MAGIC                0x46508001
#define  FPSIMD_CONTEXT_MAGIC_OFFSET 0
#define  FPSIMD_CONTEXT_SIZE_OFFSET  4
#define  FPSIMD_CONTEXT_FPSR_OFFSET  8
#define  FPSIMD_CONTEXT_FPCR_OFFSET  12
#define  FPSIMD_CONTEXT_VREGS_OFFSET 16
#define  FPSIMD_CONTEXT_SIZE         528
#define  REGISTER_SIZE               8
#define  SIMD_REGISTER_SIZE          16
#define  _NSIG                       64
#define  __NR_rt_sigprocmask         135

  .text
  .global my_getcontext
  .hidden my_getcontext
  .type my_getcontext, #function
  .align 4
  .cfi_startproc
my_getcontext:
  // 取得 ucontext.uc_mcontext 寄存器区域
  str     xzr,      [x0, MCONTEXT_GREGS_OFFSET +  0 * REGISTER_SIZE]
  stp     x18, x19, [x0, MCONTEXT_GREGS_OFFSET + 18 * REGISTER_SIZE]
  stp     x20, x21, [x0, MCONTEXT_GREGS_OFFSET + 20 * REGISTER_SIZE]
  stp     x22, x23, [x0, MCONTEXT_GREGS_OFFSET + 22 * REGISTER_SIZE]
  stp     x24, x25, [x0, MCONTEXT_GREGS_OFFSET + 24 * REGISTER_SIZE]
  stp     x26, x27, [x0, MCONTEXT_GREGS_OFFSET + 26 * REGISTER_SIZE]
  stp     x28, x29, [x0, MCONTEXT_GREGS_OFFSET + 28 * REGISTER_SIZE]
  str     x30,      [x0, MCONTEXT_GREGS_OFFSET + 30 * REGISTER_SIZE]
  // 获取 程序计数器和,fpsimd
  str     x30, [x0, MCONTEXT_PC_OFFSET]
  mov     x2, sp
  str     x2, [x0, MCONTEXT_SP_OFFSET]
  str     xzr, [x0, MCONTEXT_PSTATE_OFFSET]
  add     x2, x0, #MCONTEXT_EXTENSION_OFFSET
  mov     w3, #(FPSIMD_MAGIC & 0xffff)
  movk    w3, #(FPSIMD_MAGIC >> 16), lsl #16
  str     w3, [x2, #FPSIMD_CONTEXT_MAGIC_OFFSET]
  mov     w3, #FPSIMD_CONTEXT_SIZE
  str     w3, [x2, #FPSIMD_CONTEXT_SIZE_OFFSET]

  add     x3, x2, #(FPSIMD_CONTEXT_VREGS_OFFSET + 8 * SIMD_REGISTER_SIZE)
  stp     d8,  d9, [x3], #(2 * SIMD_REGISTER_SIZE)
  stp     d10, d11, [x3], #(2 * SIMD_REGISTER_SIZE)
  stp     d12, d13, [x3], #(2 * SIMD_REGISTER_SIZE)
  stp     d14, d15, [x3], #(2 * SIMD_REGISTER_SIZE)

  add     x3, x2, FPSIMD_CONTEXT_FPSR_OFFSET
  mrs     x4, fpsr
  str     w4, [x3]
  mrs     x4, fpcr
  str     w4, [x3, FPSIMD_CONTEXT_FPCR_OFFSET - FPSIMD_CONTEXT_FPSR_OFFSET]

  add     x2, x2, #FPSIMD_CONTEXT_SIZE

  str     xzr, [x2, #FPSIMD_CONTEXT_MAGIC_OFFSET]
  str     xzr, [x2, #FPSIMD_CONTEXT_SIZE_OFFSET]
  // __NR_rt_sigprocmask(x0, UCONTEXT_SIGMASK_OFFSET, 0);
  add     x2, x0, #UCONTEXT_SIGMASK_OFFSET
  mov     x0, #0
  mov     x1, #0
  mov     x3, #(_NSIG / 8)
  mov     x8, #__NR_rt_sigprocmask
  svc     0

  mov     x0, 0
  ret

  .cfi_endproc
  .size my_getcontext, . - my_getcontext

#elif defined(__i386__)
#define  MCONTEXT_GREGS_OFFSET     20
#define  MCONTEXT_GS_OFFSET        (MCONTEXT_GREGS_OFFSET + 0*4)
#define  MCONTEXT_FS_OFFSET        (MCONTEXT_GREGS_OFFSET + 1*4)
#define  MCONTEXT_ES_OFFSET        (MCONTEXT_GREGS_OFFSET + 2*4)
#define  MCONTEXT_DS_OFFSET        (MCONTEXT_GREGS_OFFSET + 3*4)
#define  MCONTEXT_EDI_OFFSET       (MCONTEXT_GREGS_OFFSET + 4*4)
#define  MCONTEXT_ESI_OFFSET       (MCONTEXT_GREGS_OFFSET + 5*4)
#define  MCONTEXT_EBP_OFFSET       (MCONTEXT_GREGS_OFFSET + 6*4)
#define  MCONTEXT_ESP_OFFSET       (MCONTEXT_GREGS_OFFSET + 7*4)
#define  MCONTEXT_EBX_OFFSET       (MCONTEXT_GREGS_OFFSET + 8*4)
#define  MCONTEXT_EDX_OFFSET       (MCONTEXT_GREGS_OFFSET + 9*4)
#define  MCONTEXT_ECX_OFFSET       (MCONTEXT_GREGS_OFFSET + 10*4)
#define  MCONTEXT_EAX_OFFSET       (MCONTEXT_GREGS_OFFSET + 11*4)
#define  MCONTEXT_TRAPNO_OFFSET    (MCONTEXT_GREGS_OFFSET + 12*4)
#define  MCONTEXT_ERR_OFFSET       (MCONTEXT_GREGS_OFFSET + 13*4)
#define  MCONTEXT_EIP_OFFSET       (MCONTEXT_GREGS_OFFSET + 14*4)
#define  MCONTEXT_CS_OFFSET        (MCONTEXT_GREGS_OFFSET + 15*4)
#define  MCONTEXT_EFL_OFFSET       (MCONTEXT_GREGS_OFFSET + 16*4)
#define  MCONTEXT_UESP_OFFSET      (MCONTEXT_GREGS_OFFSET + 17*4)
#define  MCONTEXT_SS_OFFSET        (MCONTEXT_GREGS_OFFSET + 18*4)
#define  UCONTEXT_SIGMASK_OFFSET   108
#define  UCONTEXT_FPREGS_OFFSET       96
#define  UCONTEXT_FPREGS_MEM_OFFSET   116
  .text
  .global my_getcontext
  .hidden my_getcontext
  .align 4
  .type my_getcontext, @function
my_getcontext:
  // eax = esp + 4, 跳过 eip
  movl 4(%esp), %eax
  // 取得 MCONTEXT_GREGS_OFFSET 寄存器区域
  movl %ecx, MCONTEXT_ECX_OFFSET(%eax)
  movl %edx, MCONTEXT_EDX_OFFSET(%eax)
  movl %ebx, MCONTEXT_EBX_OFFSET(%eax)
  movl %edi, MCONTEXT_EDI_OFFSET(%eax)
  movl %esi, MCONTEXT_ESI_OFFSET(%eax)
  movl %ebp, MCONTEXT_EBP_OFFSET(%eax)

  movl (%esp), %edx
  lea  4(%esp), %ecx
  mov  %edx, MCONTEXT_EIP_OFFSET(%eax)
  mov  %ecx, MCONTEXT_ESP_OFFSET(%eax)

  xorl %ecx, %ecx
  movw %fs, %cx
  mov  %ecx, MCONTEXT_FS_OFFSET(%eax)

  movl $0, MCONTEXT_EAX_OFFSET(%eax)

  // 获取浮点寄存器上下文
  leal UCONTEXT_FPREGS_MEM_OFFSET(%eax), %ecx
  fnstenv (%ecx)
  fldenv  (%ecx)
  mov %ecx, UCONTEXT_FPREGS_OFFSET(%eax)
  // sigprocmask(eax, UCONTEXT_SIGMASK_OFFSET, 0);
  leal UCONTEXT_SIGMASK_OFFSET(%eax), %edx
  xorl %ecx, %ecx
  push %edx
  push %ecx
  push %ecx
  call sigprocmask@PLT
  addl $12, %esp

  movl $0, %eax
  ret

  .size my_getcontext, . - my_getcontext

#elif defined(__x86_64__)
#define MCONTEXT_GREGS_OFFSET     40
#define UCONTEXT_SIGMASK_OFFSET   296
#define MCONTEXT_GREGS_R8    40
#define MCONTEXT_GREGS_R9    48
#define MCONTEXT_GREGS_R10   56
#define MCONTEXT_GREGS_R11   64
#define MCONTEXT_GREGS_R12   72
#define MCONTEXT_GREGS_R13   80
#define MCONTEXT_GREGS_R14   88
#define MCONTEXT_GREGS_R15   96
#define MCONTEXT_GREGS_RDI   104
#define MCONTEXT_GREGS_RSI   112
#define MCONTEXT_GREGS_RBP   120
#define MCONTEXT_GREGS_RBX   128
#define MCONTEXT_GREGS_RDX   136
#define MCONTEXT_GREGS_RAX   144
#define MCONTEXT_GREGS_RCX   152
#define MCONTEXT_GREGS_RSP   160
#define MCONTEXT_GREGS_RIP   168
#define MCONTEXT_FPREGS_PTR  224
#define MCONTEXT_FPREGS_MEM  304
#define FPREGS_OFFSET_MXCSR  24
  .text
  .global my_getcontext
  .hidden my_getcontext
  .align 4
  .type my_getcontext, @function
my_getcontext:
  .cfi_startproc
  // 获取寄存器区域
  movq %r12, MCONTEXT_GREGS_R12(%rdi)
  movq %r13, MCONTEXT_GREGS_R13(%rdi)
  movq %r14, MCONTEXT_GREGS_R14(%rdi)
  movq %r15, MCONTEXT_GREGS_R15(%rdi)
  movq %rbp, MCONTEXT_GREGS_RBP(%rdi)
  movq %rbx, MCONTEXT_GREGS_RBX(%rdi)

  movq %r8,  MCONTEXT_GREGS_R8(%rdi)
  movq %r9,  MCONTEXT_GREGS_R9(%rdi)
  movq %rdi, MCONTEXT_GREGS_RDI(%rdi)
  movq %rsi, MCONTEXT_GREGS_RSI(%rdi)
  movq %rdx, MCONTEXT_GREGS_RDX(%rdi)
  movq %rax, MCONTEXT_GREGS_RAX(%rdi)
  movq %rcx, MCONTEXT_GREGS_RCX(%rdi)

  leaq MCONTEXT_FPREGS_MEM(%rdi),%r8
  movq %r8, MCONTEXT_FPREGS_PTR(%rdi)
  fnstenv (%r8)
  stmxcsr FPREGS_OFFSET_MXCSR(%r8)

  leaq 8(%rsp), %rax
  movq %rax, MCONTEXT_GREGS_RSP(%rdi)

  movq 0(%rsp), %rax
  movq %rax, MCONTEXT_GREGS_RIP(%rdi)

  // sigprocmask(rax, UCONTEXT_SIGMASK_OFFSET, 0);
  leaq UCONTEXT_SIGMASK_OFFSET(%rdi), %rdx
  xorq %rsi, %rsi
  xorq %rdi, %rdi
  call sigprocmask@PLT

  xorl %eax, %eax
  ret
  .cfi_endproc
  .size my_getcontext, . - my_getcontext
#endif
