#include "com_iexin_common_CrashHelper.h"

const int exception_signals[] = { SIGSEGV, SIGABRT, SIGFPE, SIGILL, SIGBUS, SIGTRAP};
const int exception_numbers = sizeof(exception_signals) / sizeof(exception_signals[0]);
struct sigaction old_signals[exception_numbers];
struct cpu_register;
struct crash_context;

pthread_t         thread;
pthread_mutex_t   daemon_mtx;
pthread_cond_t    daemon_ctx;

JavaVM         *gvm;
jclass          crash_helper_clazz;
jmethodID       crash_helper_commit_method;
crash_context  *crash_ctx;

void signal_handler(int, siginfo_t*, void*);
void signal_simple_handler(int);
char* get_general_register(ucontext *uc);
char* get_general_info(uint64_t);

// 异常上下文
struct crash_context {
      siginfo_t    *sig_info;   // 异常信息
      ucontext     *sig_ctx;    // 异常上下文
      int           sig;        // 异常信号量
      int           tid;        // 线程 id
};

// intel i386 处理器现场
struct intel_32_register {
      uint32_t gs;
      uint32_t fs;
      uint32_t es;
      uint32_t ds;
      uint32_t ss;
      uint32_t cs;

      uint32_t ebp;
      uint32_t esp;
      uint32_t eip;
      uint32_t edi;
      uint32_t esi;

      uint32_t ebx;
      uint32_t edx;
      uint32_t ecx;
      uint32_t eax;

      uint32_t eflags;

      int control_word;
      int status_word;
      int tag_word;

      int error_offset;
      int data_offset;

      int error_selector;
      int data_selector;
};

// intel x86_64 处理器现场
struct intel_64_register {
      uint64_t cs;
      uint64_t fs;
      uint64_t gs;
      uint64_t rflags;

      uint64_t rax;
      uint64_t rcx;
      uint64_t rdx;
      uint64_t rbx;

      uint64_t rsi;
      uint64_t rdi;
      uint64_t rbp;
      uint64_t rsp;
      uint64_t rip;

      uint64_t r8;
      uint64_t r9;
      uint64_t r10;
      uint64_t r11;
      uint64_t r12;
      uint64_t r13;
      uint64_t r14;
      uint64_t r15;

      int control_word;
      int status_word;
      int tag_word;

      int error_offset;
      int data_offset;

      int error_opcode;
      int error_selector;
      int data_selector;
      int mx_csr;
      int mx_csr_mask;
};

// arm 32bit 处理器现场
struct arm_32_register {
      uint32_t fp;
      uint32_t ip;
      uint32_t sp;
      uint32_t lr;
      uint32_t pc;

      uint32_t r0;
      uint32_t r1;
      uint32_t r2;
      uint32_t r3;
      uint32_t r4;
      uint32_t r5;
      uint32_t r6;
      uint32_t r7;
      uint32_t r8;
      uint32_t r9;
      uint32_t r10;

      int cpsr;
      int fpscr;
};
// arm 64bit 处理器现场
struct arm_64_register {
      uint64_t pc;
      uint64_t sp;

      uint64_t x0;
      uint64_t x1;
      uint64_t x2;
      uint64_t x3;
      uint64_t x4;
      uint64_t x5;
      uint64_t x6;
      uint64_t x7;
      uint64_t x8;
      uint64_t x9;
      uint64_t x10;
      uint64_t x11;
      uint64_t x12;
      uint64_t x13;
      uint64_t x14;
      uint64_t x15;
      uint64_t x16;
      uint64_t x17;
      uint64_t x18;
      uint64_t x19;
      uint64_t x20;
      uint64_t x21;
      uint64_t x22;
      uint64_t x23;
      uint64_t x24;
      uint64_t x25;
      uint64_t x26;
      uint64_t x27;
      uint64_t x28;
      uint64_t x29;
      uint64_t x30;

      int fpsr;
      int fpcr;
};

// 处理器上下文
struct cpu_register {
#if defined(__aarch64__)
      arm_64_register arm64;
#elif defined(__ARM_ARCH_7A__)
      arm_32_register arm32;
#elif defined(__i386__)
      intel_32_register x86;
#elif defined(__x86_64)
      intel_64_register x86_64;
#endif
};

inline int split_data(char *str, char *valueTable[], const char *split) {
      char *data = strtok(str, split);
      int index = 0;
      while (data) {
            valueTable[index++] = data;
            data = strtok(NULL, split);
      }
      return index;
}

inline uint64_t convert_integer(char *c) {
      uint64_t result = 0;
      char ch;
      while ((ch = *c)) {
            result <<= 4;
            ch |= 0x20;
            if (ch >= 0x61 && ch <= 0x66) { // a-f
                  result |= (ch - 0x57);
            } else if (ch >= 0x30 && ch <= 0x39) { // 0-9
                  result |= (ch - 0x30);
            }
            c++;
      }
      return result;
}

int sigemptyset_compat(sigset_t* set) {
      if (set == NULL) {
            return -1;
      }
      memset(set, 0, sizeof(sigset_t));
      return 0;
}

int sigaddset_compat(sigset_t* set, int signum) {
      // Signal numbers start at 1, but bit positions start at 0.
      int bit = signum - 1;
      unsigned long* local_set = reinterpret_cast<unsigned long*>(set);
      if (set == NULL || bit < 0
                  || bit >= static_cast<int>(8 * sizeof(sigset_t))) {
            return -1;
      }
      local_set[bit / LONG_BIT] |= 1UL << (bit % LONG_BIT);
      return 0;
}

jclass find_class(JNIEnv *env, const char *name) {
      jclass local = env->FindClass(name);
      jclass global = (jclass) env->NewGlobalRef(local);
      env->DeleteLocalRef(local);
      return global;
}

jmethodID get_static_method(JNIEnv *env, jclass clazz, const char *name,
            const char*sig) {
      return env->GetStaticMethodID(clazz, name, sig);
}

void call_static_method(JNIEnv *env, jclass clazz, jmethodID method,
            jstring utf) {
      env->CallStaticVoidMethod(clazz, method, utf);
}

void del_local_ref(JNIEnv *env, jobject obj) {
      env->DeleteLocalRef(obj);
}

void del_glo_ref(JNIEnv *env, jobject obj) {
      env->DeleteGlobalRef(obj);
}

jstring new_utf_chars(JNIEnv *env, char *chars) {
      return env->NewStringUTF(chars);
}

/**
 * 异常处理
 */
void signal_handler(int sig, siginfo_t *info, void *uc) {
                    crash_ctx = (crash_context*) malloc(sizeof(struct crash_context));
      siginfo_t     *sig_info = (siginfo_t*)     malloc(sizeof(siginfo_t));
      ucontext      *sig_ctx  = (ucontext*)      malloc(sizeof(ucontext));
      memcpy(sig_info, info, sizeof(siginfo_t));
      memcpy(sig_ctx,  uc,   sizeof(ucontext));
      crash_ctx->sig_info   = sig_info;
      crash_ctx->sig_ctx    = sig_ctx;
      crash_ctx->sig        = sig;
      crash_ctx->tid        = gettid();
      // 发送信号给 daemon_thread
      pthread_mutex_lock(&daemon_mtx);
      pthread_cond_signal(&daemon_ctx);
      pthread_mutex_unlock(&daemon_mtx);
}
/**
 * 异常处理
 */
void signal_simple_handler(int sig) {
      siginfo_t siginfo = { };
      ucontext context = { };
      siginfo.si_code = SI_USER;
      siginfo.si_pid = getpid();
      my_getcontext(&context);

      signal_handler(sig, &siginfo, &context);
}

char* get_platform_string() {
      char* result = 0;
#if defined(__aarch64__)
      result = "aarch64";
#elif defined(__ARM_ARCH_7A__)
      result = "armeabi-v7a";
#elif defined(__i386__)
      result = "x86";
#elif defined(__x86_64)
      result = "x86_64";
#endif
      return result;
}

char* get_register_string(cpu_register *reg) {
      char *result = (char*) malloc(sizeof(char) * 2048);
#if defined(__aarch64__)
      sprintf(result,
                  "pc  = %016llx, sp  = %016llx, fpsr = %016llx, fpcr = %016llx\n"
                  "x0  = %016llx, x1  = %016llx, x2   = %016llx, x3   = %016llx\n"
                  "x4  = %016llx, x5  = %016llx, x6   = %016llx, x7   = %016llx\n"
                  "x8  = %016llx, x9  = %016llx, x10  = %016llx, x11  = %016llx\n"
                  "x12 = %016llx, x13 = %016llx, x14  = %016llx, x15  = %016llx\n"
                  "x16 = %016llx, x17 = %016llx, x18  = %016llx, x19  = %016llx\n"
                  "x20 = %016llx, x21 = %016llx, x22  = %016llx, x23  = %016llx\n"
                  "x24 = %016llx, x25 = %016llx, x26  = %016llx, x27  = %016llx\n"
                  "x28 = %016llx, x29 = %016llx, x30  = %016llx",
                  reg->arm64.pc,  reg->arm64.sp,  reg->arm64.fpsr, reg->arm64.fpcr,
                  reg->arm64.x0,  reg->arm64.x1,  reg->arm64.x2,   reg->arm64.x3,
                  reg->arm64.x4,  reg->arm64.x5,  reg->arm64.x6,   reg->arm64.x7,
                  reg->arm64.x8,  reg->arm64.x9,  reg->arm64.x10,  reg->arm64.x11,
                  reg->arm64.x12, reg->arm64.x13, reg->arm64.x14,  reg->arm64.x15,
                  reg->arm64.x16, reg->arm64.x17, reg->arm64.x18,  reg->arm64.x19,
                  reg->arm64.x20, reg->arm64.x21, reg->arm64.x22,  reg->arm64.x23,
                  reg->arm64.x24, reg->arm64.x25, reg->arm64.x26,  reg->arm64.x27,
                  reg->arm64.x28, reg->arm64.x29, reg->arm64.x30);
#elif defined(__ARM_ARCH_7A__)
      sprintf(result,
                  "pc = %08x, ip   = %08x, sp    = %08x, lr = %08x\n"
                  "fp = %08x, cpsr = %08x, fpscr = %08x\n"
                  "r0 = %08x, r1   = %08x, r2    = %08x, r3 = %08x\n"
                  "r4 = %08x, r5   = %08x, r6    = %08x, r7 = %08x\n"
                  "r8 = %08x, r9   = %08x, r10   = %08x",
                  reg->arm32.pc, reg->arm32.ip,   reg->arm32.sp,    reg->arm32.lr,
                  reg->arm32.fp, reg->arm32.cpsr, reg->arm32.fpscr,
                  reg->arm32.r0, reg->arm32.r1,   reg->arm32.r2,    reg->arm32.r3,
                  reg->arm32.r4, reg->arm32.r5,   reg->arm32.r6,    reg->arm32.r7,
                  reg->arm32.r8, reg->arm32.r9,   reg->arm32.r10);
#elif defined(__i386__)
      sprintf(result,
                  "cs  = %08x, ds = %08x, es = %08x, ss = %08x fs = %08x, gs = %08x\n"
                  "eip = %08x, eflags = %08x\n"
                  "eax = %08x, ebx = %08x, ecx = %08x, edx = %08x\n"
                  "ebp = %08x, esp = %08x, esi = %08x, edi = %08x\n"

                  "control_word = %08x, status_word    = %08x, tag_word = %08x\n"
                  "error_offset = %08x, error_selector = %08x\n"
                  "data_offset  = %08x, data_selector  = %08x",
                  reg->x86.cs,  reg->x86.ds,  reg->x86.es, reg->x86.ss,
                  reg->x86.fs,  reg->x86.gs,
                  reg->x86.eip, reg->x86.eflags,
                  reg->x86.eax, reg->x86.ebx, reg->x86.ecx, reg->x86.edx,
                  reg->x86.ebp, reg->x86.esp, reg->x86.esi, reg->x86.edi,

                  reg->x86.control_word, reg->x86.status_word,    reg->x86.tag_word,
                  reg->x86.error_offset, reg->x86.error_selector,
                  reg->x86.data_offset,  reg->x86.data_selector
      );
#elif defined(__x86_64)
      sprintf(result,
                  "cs  = %016llx, fs = %016llx, gs = %016llx\n"
                  "rip = %016llx, rflags = %016llx\n"
                  "rax = %016llx, rbx = %016llx, rcx = %016llx, rdx = %016llx\n"
                  "rsi = %016llx, rdi = %016llx, rbp = %016llx, rsp = %016llx\n"
                  "r8  = %016llx, r9  = %016llx, r10 = %016llx, r11 = %016llx\n"
                  "r12 = %016llx, r13 = %016llx, r14 = %016llx, r15 = %016llx\n"

                  "control_word = %016llx, status_word    = %016llx, tag_word     = %016llx\n"
                  "error_offset = %016llx, error_selector = %016llx, error_opcode = %016llx\n"
                  "data_offset  = %016llx, data_selector  = %016llx\n"
                  "mx_csr       = %016llx, mx_csr_mask    = %016llx",
                  reg->x86_64.cs, reg->x86_64.fs, reg->x86_64.gs,
                  reg->x86_64.rip,reg->x86_64.rflags,

                  reg->x86_64.rax, reg->x86_64.rbx, reg->x86_64.rcx, reg->x86_64.rdx,
                  reg->x86_64.rsi, reg->x86_64.rdi, reg->x86_64.rbp, reg->x86_64.rsp,
                  reg->x86_64.r8,  reg->x86_64.r9,  reg->x86_64.r10, reg->x86_64.r11,
                  reg->x86_64.r12, reg->x86_64.r13, reg->x86_64.r14, reg->x86_64.r15,

                  reg->x86_64.control_word, reg->x86_64.status_word,    reg->x86_64.tag_word,
                  reg->x86_64.error_offset, reg->x86_64.error_selector, reg->x86_64.error_opcode,
                  reg->x86_64.data_offset,  reg->x86_64.data_selector,
                  reg->x86_64.mx_csr,       reg->x86_64.mx_csr_mask);
#endif
      return result;
}

char* get_general_register(ucontext *uc) {
      cpu_register purpose;
#if defined(__aarch64__)
      struct ucontext *uc_ptr = (struct ucontext*)uc;
      struct fpsimd_context *fp_ptr = (struct fpsimd_context*)&uc_ptr->uc_mcontext.__reserved;
      /**
       * 初始化各寄存器
       */
      purpose.arm64.pc  = uc_ptr->uc_mcontext.pc;
      purpose.arm64.sp  = uc_ptr->uc_mcontext.sp;
      purpose.arm64.x0  = uc_ptr->uc_mcontext.regs[0];
      purpose.arm64.x1  = uc_ptr->uc_mcontext.regs[1];
      purpose.arm64.x2  = uc_ptr->uc_mcontext.regs[2];
      purpose.arm64.x3  = uc_ptr->uc_mcontext.regs[3];
      purpose.arm64.x4  = uc_ptr->uc_mcontext.regs[4];
      purpose.arm64.x5  = uc_ptr->uc_mcontext.regs[5];
      purpose.arm64.x6  = uc_ptr->uc_mcontext.regs[6];
      purpose.arm64.x7  = uc_ptr->uc_mcontext.regs[7];
      purpose.arm64.x8  = uc_ptr->uc_mcontext.regs[8];
      purpose.arm64.x9  = uc_ptr->uc_mcontext.regs[9];
      purpose.arm64.x10 = uc_ptr->uc_mcontext.regs[10];
      purpose.arm64.x11 = uc_ptr->uc_mcontext.regs[11];
      purpose.arm64.x12 = uc_ptr->uc_mcontext.regs[12];
      purpose.arm64.x13 = uc_ptr->uc_mcontext.regs[13];
      purpose.arm64.x14 = uc_ptr->uc_mcontext.regs[14];
      purpose.arm64.x15 = uc_ptr->uc_mcontext.regs[15];
      purpose.arm64.x16 = uc_ptr->uc_mcontext.regs[16];
      purpose.arm64.x17 = uc_ptr->uc_mcontext.regs[17];
      purpose.arm64.x18 = uc_ptr->uc_mcontext.regs[18];
      purpose.arm64.x19 = uc_ptr->uc_mcontext.regs[19];
      purpose.arm64.x20 = uc_ptr->uc_mcontext.regs[20];
      purpose.arm64.x21 = uc_ptr->uc_mcontext.regs[21];
      purpose.arm64.x22 = uc_ptr->uc_mcontext.regs[22];
      purpose.arm64.x23 = uc_ptr->uc_mcontext.regs[23];
      purpose.arm64.x24 = uc_ptr->uc_mcontext.regs[24];
      purpose.arm64.x25 = uc_ptr->uc_mcontext.regs[25];
      purpose.arm64.x26 = uc_ptr->uc_mcontext.regs[26];
      purpose.arm64.x27 = uc_ptr->uc_mcontext.regs[27];
      purpose.arm64.x28 = uc_ptr->uc_mcontext.regs[28];
      purpose.arm64.x29 = uc_ptr->uc_mcontext.regs[29];
      purpose.arm64.x30 = uc_ptr->uc_mcontext.regs[30];
      /**
       * 初始化 arm64 cpu 浮点寄存器
       */
      fpsimd_context float_state;
      if (fp_ptr->head.magic == FPSIMD_MAGIC) {
            memcpy(&float_state, fp_ptr, sizeof(fpsimd_context));

            purpose.arm64.fpsr = float_state.fpsr;
            purpose.arm64.fpcr = float_state.fpcr;
      }
#elif defined(__ARM_ARCH_7A__)
      struct ucontext *uc_ptr = (struct ucontext*)uc;
      /**
       * 初始化各寄存器
       */
      purpose.arm32.r0 = (uint32_t)uc_ptr->uc_mcontext.arm_r0;
      purpose.arm32.r1 = (uint32_t)uc_ptr->uc_mcontext.arm_r1;
      purpose.arm32.r2 = (uint32_t)uc_ptr->uc_mcontext.arm_r2;
      purpose.arm32.r3 = (uint32_t)uc_ptr->uc_mcontext.arm_r3;
      purpose.arm32.r4 = (uint32_t)uc_ptr->uc_mcontext.arm_r4;
      purpose.arm32.r5 = (uint32_t)uc_ptr->uc_mcontext.arm_r5;
      purpose.arm32.r6 = (uint32_t)uc_ptr->uc_mcontext.arm_r6;
      purpose.arm32.r7 = (uint32_t)uc_ptr->uc_mcontext.arm_r7;
      purpose.arm32.r8 = (uint32_t)uc_ptr->uc_mcontext.arm_r8;
      purpose.arm32.r9 = (uint32_t)uc_ptr->uc_mcontext.arm_r9;
      purpose.arm32.r10 = (uint32_t)uc_ptr->uc_mcontext.arm_r10;

      purpose.arm32.fp = (uint32_t)uc_ptr->uc_mcontext.arm_fp;
      purpose.arm32.ip = (uint32_t)uc_ptr->uc_mcontext.arm_ip;
      purpose.arm32.sp = (uint32_t)uc_ptr->uc_mcontext.arm_sp;
      purpose.arm32.lr = (uint32_t)uc_ptr->uc_mcontext.arm_lr;
      purpose.arm32.pc = (uint32_t)uc_ptr->uc_mcontext.arm_pc;

      purpose.arm32.cpsr = (int)uc_ptr->uc_mcontext.arm_cpsr;
      purpose.arm32.fpscr = (int)0;

#elif defined(__i386__)
      struct ucontext *uc_ptr = (struct ucontext*)uc;
      greg_t *regs = uc_ptr->uc_mcontext.gregs;
      fpregset_t fpregs = uc_ptr->uc_mcontext.fpregs;

      purpose.x86.gs = (uint32_t)regs[REG_GS];
      purpose.x86.fs = (uint32_t)regs[REG_FS];
      purpose.x86.es = (uint32_t)regs[REG_ES];
      purpose.x86.ds = (uint32_t)regs[REG_DS];
      purpose.x86.ss = (uint32_t)regs[REG_SS];
      purpose.x86.cs = (uint32_t)regs[REG_CS];

      purpose.x86.ebp = (uint32_t)regs[REG_EBP];
      purpose.x86.esp = (uint32_t)regs[REG_ESP];
      purpose.x86.eip = (uint32_t)regs[REG_EIP];
      purpose.x86.edi = (uint32_t)regs[REG_EDI];
      purpose.x86.esi = (uint32_t)regs[REG_ESI];

      purpose.x86.ebx = (uint32_t)regs[REG_EBX];
      purpose.x86.edx = (uint32_t)regs[REG_EDX];
      purpose.x86.ecx = (uint32_t)regs[REG_ECX];
      purpose.x86.eax = (uint32_t)regs[REG_EAX];
      purpose.x86.eflags = (uint32_t)regs[REG_EFL];
      if (fpregs) {
            purpose.x86.control_word = (int)fpregs->cw;
            purpose.x86.status_word = (int)fpregs->sw;
            purpose.x86.tag_word = (int)fpregs->tag;
            purpose.x86.error_offset = (int)fpregs->ipoff;
            purpose.x86.error_selector = (int)fpregs->cssel;
            purpose.x86.data_offset = (int)fpregs->dataoff;
            purpose.x86.data_selector = (int)fpregs->datasel;
      }
#elif defined(__x86_64)
      struct ucontext *uc_ptr = (struct ucontext*) uc;
      greg_t *regs = uc_ptr->uc_mcontext.gregs;
      fpregset_t fpregs = uc_ptr->uc_mcontext.fpregs;

      purpose.x86_64.cs = regs[REG_CSGSFS] & 0xFFFF;
      purpose.x86_64.fs = (regs[REG_CSGSFS] >> 32) & 0xFFFF;
      purpose.x86_64.gs = (regs[REG_CSGSFS] >> 16) & 0xFFFF;
      purpose.x86_64.rflags = regs[REG_EFL];

      purpose.x86_64.rax = regs[REG_RAX];
      purpose.x86_64.rcx = regs[REG_RCX];
      purpose.x86_64.rdx = regs[REG_RDX];
      purpose.x86_64.rbx = regs[REG_RBX];

      purpose.x86_64.rsi = regs[REG_RSI];
      purpose.x86_64.rdi = regs[REG_RDI];
      purpose.x86_64.rbp = regs[REG_RBP];
      purpose.x86_64.rsp = regs[REG_RSP];
      purpose.x86_64.rip = regs[REG_RIP];

      purpose.x86_64.r8 = regs[REG_R8];
      purpose.x86_64.r9 = regs[REG_R9];
      purpose.x86_64.r10 = regs[REG_R10];
      purpose.x86_64.r11 = regs[REG_R11];
      purpose.x86_64.r12 = regs[REG_R12];
      purpose.x86_64.r13 = regs[REG_R13];
      purpose.x86_64.r14 = regs[REG_R14];
      purpose.x86_64.r15 = regs[REG_R15];
      if (fpregs) {
            purpose.x86_64.control_word = fpregs->cwd;
            purpose.x86_64.status_word = fpregs->swd;
            purpose.x86_64.tag_word = fpregs->ftw;

            purpose.x86_64.error_opcode = fpregs->fop;
            purpose.x86_64.error_offset = fpregs->rip;
            purpose.x86_64.error_selector = 0;

            purpose.x86_64.data_offset = fpregs->rdp;
            purpose.x86_64.data_selector = 0;

            purpose.x86_64.mx_csr = fpregs->mxcsr;
            purpose.x86_64.mx_csr_mask = fpregs->mxcr_mask;
      }
#endif
      return get_register_string(&purpose);
}

char* get_thread_name(int tid) {
      if (tid <= 1) {
            return 0;
      }
      char *path = (char*)malloc(sizeof(char) * 255);
      char *line = (char*)malloc(sizeof(char) * 255);
      sprintf(path, "/proc/%d/comm", tid);

      FILE *f = fopen(path, "r");
      if (f) {
            fgets(line, 255, f);
            fclose(f);
            free(path);
            if (line) {
                  int length = strlen(line);
                  if (line[length - 1] == '\n') {
                        line[length - 1] = '\0';
                  }
            }
            return line;
      }
      else {
            free(path);
            free(line);
            return 0;
      }
}

char* get_general_info(uint64_t ip) {
      char *result = 0;

      char line[256];
      FILE *fd = fopen("/proc/self/maps", "r");
      char *table[10];
      char *addr[5];
      char *library = 0;
      char *space = 0;
      while (fgets(line, sizeof(line), fd)) {
            split_data((char*) line, table, " ");
            split_data(table[0], addr, "-");
            // 地址空间
            space = table[0];
            // 动态链接库
            if (table[5] && strlen(table[5]) > 0) {
                  library = table[5];
                  int length = strlen(library);
                  if (library[length - 1] == '\n') {
                	    library[length - 1] = '\0';
                  }
            }
            uint64_t start_space = convert_integer(addr[0]);
            uint64_t end_space   = convert_integer(addr[1]);
            if ((start_space <= ip) && (end_space >= ip) && library) {
                  char *crash_info = __rtl_search(library, ip);
                  result = (char*) malloc(sizeof(char) * 1024);
                  sprintf(result, "%s %s", library, crash_info);
                  free(crash_info);
                  break;
            }
      }
      fclose(fd);
      return result;
}

/**
 * 安装异常处理程序
 */
void init_signal_handler() {
      typedef int          (*my_sigaltstack_t)(const stack_t*, stack_t*);
      typedef int          (*my_sigaction_t)(int, const struct sigaction*, struct sigaction*);
      typedef int          (*my_sigemptyset_t)(sigset_t*);
      typedef int          (*my_sigaddset_t)(sigset_t*, int);
      typedef sighandler_t (*my_signal_t)(int, sighandler_t);
      my_sigaltstack_t my_sigaltstack;
      my_sigaction_t   my_sigaction;
      my_sigemptyset_t my_sigemptyset;
      my_sigaddset_t   my_sigaddset;
      my_signal_t      my_signal;
      /**
       * 获取 linux 信号相关符号
       */
      void* handle   = dlopen("libc.so", RTLD_LAZY);
      my_sigaltstack = (my_sigaltstack_t) dlsym(handle, "sigaltstack");
      my_sigaction   = (my_sigaction_t)   dlsym(handle, "sigaction");
      my_sigemptyset = (my_sigemptyset_t) dlsym(handle, "sigemptyset");
      my_sigaddset   = (my_sigaddset_t)   dlsym(handle, "sigaddset");
      my_signal      = (my_signal_t)      dlsym(handle, "signal");
      if (!my_signal) {
            my_signal = (my_signal_t) dlsym(handle, "bsd_signal");
      }
      if (!my_signal) {
            my_signal = (my_signal_t) dlsym(handle, "sysv_signal");
      }
      // 处理部分 linux 内核兼容性问题
      if (!my_sigemptyset) {
            my_sigemptyset = (my_sigemptyset_t) sigemptyset_compat;
      }
      if (!my_sigaddset) {
            my_sigaddset = (my_sigaddset_t) sigaddset_compat;
      }
      /**
       * 设置额外的栈空间，避免因 SIGSEGV 再次引起同样的信号
       */
      if (my_sigaltstack) {
            stack_t stack;
            memset(&stack, 0, sizeof(stack_t));
            stack.ss_size  = SIGSTKSZ;
            stack.ss_sp    = malloc(stack.ss_size);
            stack.ss_flags = 0;
            my_sigaltstack(&stack, 0);
      }
      /**
       * 安装信号处理回调
       */
      if (my_sigaction && my_sigemptyset && my_sigaddset) {
            // 获取老的异常处理
            for (int i = 0; i < exception_numbers; i++) {
                  my_sigaction(exception_signals[i], NULL, &old_signals[i]);
            }
            // 新增默认的异常处理
            struct sigaction sa;
            memset(&sa, 0, sizeof(struct sigaction));
            my_sigemptyset(&sa.sa_mask);
            sa.sa_flags = SA_ONSTACK | SA_SIGINFO;
            sa.sa_sigaction = signal_handler;
            // 安装新的异常
            for (int i = 0; i < exception_numbers; i++) {
                  my_sigaddset(&sa.sa_mask, exception_signals[i]);
            }
            for (int i = 0; i < exception_numbers; i++) {
                  my_sigaction(exception_signals[i], &sa, NULL);
            }
      } else if (my_signal) {
            for (int i = 0; i < exception_numbers; i++) {
                  my_signal(exception_signals[i], signal_simple_handler);
            }
      }
}

/**
 * 初始化 JNI
 */
void init_jni_method(JavaVM *vm) {
      JNIEnv *env = NULL;
      vm->GetEnv((void**)&env, JNI_VERSION_1_4);

      crash_helper_clazz = find_class(env, "com/iexin/common/CrashHelper");
      crash_helper_commit_method = get_static_method(env, crash_helper_clazz, "commitNativeCrash", "(Ljava/lang/String;Ljava/lang/String;)V");
}

void do_process_exception(JNIEnv *env, crash_context *ctx) {
      if (ctx) {
            char *crash    = (char*) malloc(sizeof(char) * 4096);
            char *thread   = get_thread_name(ctx->tid);
            char *platform = get_platform_string();
            char *regist   = get_general_register(ctx->sig_ctx);
            char *breakpad = (char*) malloc(sizeof(char) * 4096);

            unw_cursor_t cursor;
            unw_init_local(&cursor, (unw_context_t*) ctx->sig_ctx);
            do {
                  unw_word_t ip;
                  unw_get_reg(&cursor, UNW_REG_IP, &ip);
                  char *symbol = get_general_info(ip);
                  breakpad = strcat(breakpad, symbol);
                  breakpad = strcat(breakpad, "\n");
                  free(symbol);
            } while (unw_step(&cursor) > 0);
            sprintf(crash, "platform: %s\n\n"
                           "register: \n%s\n\n"
                           "breakpad: \n%s\n\n", platform, regist, breakpad);
            /**
             * 回调到 java
             */
            jstring jcrash  = env->NewStringUTF(crash);
            jstring jthread = env->NewStringUTF(thread);
            env->CallStaticVoidMethod(crash_helper_clazz, crash_helper_commit_method, jcrash, jthread);
            env->DeleteLocalRef(jcrash);
            env->DeleteLocalRef(jthread);
            /**
             * 调用老的异常处理
             */
            // 调用老的信号处理
            for (int i = 0; i < exception_numbers; i++) {
                  if (ctx->sig == exception_signals[i]) {
                        old_signals[i].sa_sigaction(ctx->sig, ctx->sig_info, ctx->sig_ctx);
                        break;
                  }
            }
            /**
             * 释放内存
             */
            free(crash);
            free(thread);
            free(regist);
            free(breakpad);
            free(ctx->sig_ctx);
            free(ctx->sig_info);
            free(ctx);
            jcrash   = 0;
            jthread  = 0;
            crash    = 0;
            thread   = 0;
            regist   = 0;
            breakpad = 0;
            ctx      = 0;
      }
}
/**
 * 守护线程
 */
void* daemon_thread(void *argv) {
      JavaVM *vm = (JavaVM*)argv;
      JNIEnv *env = NULL;
      if (vm->AttachCurrentThread(&env, 0) != JNI_OK) {
            return 0;
      }
      // 等待异常上下文
      while (true) {
            // 等待事件
            pthread_mutex_lock(&daemon_mtx);
            pthread_cond_wait(&daemon_ctx, &daemon_mtx);
            do_process_exception(env, crash_ctx);
            crash_ctx = 0;
            pthread_mutex_unlock(&daemon_mtx);
      }
      if (vm->DetachCurrentThread() != JNI_OK) {
            return 0;
      }
}

/**
 * 初始化守护线程
 */
void init_daemon_thread() {
      pthread_mutex_init(&daemon_mtx, 0);
      pthread_cond_init(&daemon_ctx, 0);
      pthread_create(&thread, 0, daemon_thread, gvm);
}

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
      gvm = vm;
      init_jni_method(vm);
      init_daemon_thread();
      init_signal_handler();

      return JNI_VERSION_1_4;
}

void JNI_OnUnload(JavaVM *vm, void *reserved) {
      JNIEnv *env = NULL;
      vm->GetEnv((void**)&env, JNI_VERSION_1_4);
      del_glo_ref(env, crash_helper_clazz);

      pthread_mutex_destroy(&daemon_mtx);
      pthread_cond_destroy(&daemon_ctx);

      crash_helper_clazz         = 0;
      crash_helper_commit_method = 0;
}
