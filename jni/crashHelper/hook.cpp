#include "hook.h"

int my_getpagesize(void);
// i386
#define R_386_32                   1       /* Direct 32 bit      */
#define R_386_GOT32                3       /* 32 bit GOT entry   */
#define R_386_PLT32                4       /* 32 bit PLT address */
// i686
#define R_X86_64_64                1       /* Direct 64 bit      */
#define R_X86_64_GOT32             3       /* 32 bit GOT entry   */
#define R_X86_64_PLT32             4       /* 32 bit PLT address */
// arm32
#define R_ARM_ABS32                2       /* Direct 32 bit      */
#define R_ARM_GLOB_DAT             21      /* Create GOT entry   */
#define R_ARM_JUMP_SLOT            22      /* Create PLT entry   */
// arm64
#define R_AARCH64_ABS64            257
#define R_AARCH64_GLOB_DAT         1025    /* Create GOT entry.  */
#define R_AARCH64_JUMP_SLOT        1026    /* Create PLT entry.  */

#if   defined(__aarch64__)
      #define Elf_Ehdr             Elf64_Ehdr
      #define Elf_Shdr             Elf64_Shdr
      #define Elf_Phdr             Elf64_Phdr
      #define Elf_Addr             Elf64_Addr
      #define Elf_Sym              Elf64_Sym
      #define Elf_Dyn              Elf64_Dyn
      #define Elf_Word             Elf64_Word
      #define Elf_Rel              Elf64_Rel
      #define Elf_Rela             Elf64_Rela
      #define CPU_BYTE_BIT         16
      #define uint                 uint64_t
      #define R_GENERIC_JUMP_SLOT  R_AARCH64_JUMP_SLOT
      #define R_GENERIC_GLOB_DAT   R_AARCH64_GLOB_DAT
      #define R_GENERIC_ABS        R_AARCH64_ABS64
      #define elf_r_sym            ELF64_R_SYM
      #define elf_r_type           ELF64_R_TYPE
#elif defined(__ARM_ARCH_7A__)
      #define Elf_Ehdr             Elf32_Ehdr
      #define Elf_Shdr             Elf32_Shdr
      #define Elf_Phdr             Elf32_Phdr
      #define Elf_Addr             Elf32_Addr
      #define Elf_Sym              Elf32_Sym
      #define Elf_Dyn              Elf32_Dyn
      #define Elf_Word             Elf32_Word
      #define Elf_Rel              Elf32_Rel
      #define Elf_Rela             Elf32_Rela
      #define CPU_BYTE_BIT         8
      #define uint                 uint32_t
      #define R_GENERIC_JUMP_SLOT  R_ARM_JUMP_SLOT
      #define R_GENERIC_GLOB_DAT   R_ARM_GLOB_DAT
      #define R_GENERIC_ABS        R_ARM_ABS32
      #define elf_r_sym            ELF32_R_SYM
      #define elf_r_type           ELF32_R_TYPE
#elif defined(__i386__)
      #define Elf_Ehdr             Elf32_Ehdr
      #define Elf_Shdr             Elf32_Shdr
      #define Elf_Phdr             Elf32_Phdr
      #define Elf_Addr             Elf32_Addr
      #define Elf_Sym              Elf32_Sym
      #define Elf_Dyn              Elf32_Dyn
      #define Elf_Word             Elf32_Word
      #define Elf_Rel              Elf32_Rel
      #define Elf_Rela             Elf32_Rela
      #define CPU_BYTE_BIT         8
      #define uint                 uint32_t
      #define R_GENERIC_JUMP_SLOT  R_386_PLT32
      #define R_GENERIC_GLOB_DAT   R_386_GOT32
      #define R_GENERIC_ABS        R_386_32
      #define elf_r_sym            ELF32_R_SYM
      #define elf_r_type           ELF32_R_TYPE
#endif

#define PAGE_START(addr)             (~(my_getpagesize() - 1) & (addr))
#define PAGE_END(addr)               PAGE_START((addr) + (PAGE_SIZE-1))
#define MAYBE_MAP_FLAG(x, from, to)  (((x) & (from)) ? (to) : 0)
#define PFLAGS_TO_PROT(x)            (MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC) | \
                                      MAYBE_MAP_FLAG((x), PF_R, PROT_READ) | \
                                      MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))

#define DT_GNU_HASH          ((int)0x6ffffef5)
#define DT_ANDROID_REL       ((int)0x60000006)
#define DT_ANDROID_RELSZ     ((int)0x60000010)

#define SAFE_SET_VALUE(t, v) if(t) *(t) = (v)
#define powerof2(x)          ((((x)-1)&(x))==0)
#define STT_GNU_IFUNC        10
/**
 * elf 可执行文件信息
 */
struct Elf_Info {
      void        *elf_base;
      Elf_Ehdr    *ehdr;
      Elf_Shdr    *shdr;
      Elf_Phdr    *phdr;

      Elf_Dyn     *dyn;
      Elf_Word     dynsz;

      Elf_Sym     *sym;
      Elf_Word     symsz;

      Elf_Addr     reldyn;
      Elf_Word     reldynsz;

      Elf_Addr     relplt;
      Elf_Word     relpltsz;

      // elf hash
      uint32_t    *bucket;
      uint32_t    *chain;
      uint32_t     nbucket;
      uint32_t     nchain;

      // gnu hash
      uint32_t    gnu_nbucket;
      uint32_t    gnu_symndx;
      uint32_t    gnu_maskwords;
      uint32_t    gnu_shift2;
      uint32_t   *gnu_bucket;
      uint32_t   *gnu_chain;
      Elf_Addr   *gnu_bloom_filter;

      const char  *shstr;
      const char  *symstr;
      bool        is_use_rela;
};
/**
 * 获取 android 系统版本
 */
int get_android_version() {
      char version[16];
      __system_property_get("ro.build.version.sdk", version);
      return atoi(version);
}
/**
 * 获取 elf 可执行文件基址
 */
void* get_elf_base(const char *soname) {
      void *base = 0;
      if (soname) {
            FILE *fd = fopen("/proc/self/maps", "r");
            char line[256];
            while (fgets(line, sizeof(line), fd)) {
                  if (strstr(line, soname)) {
                        line[CPU_BYTE_BIT] = 0x00;
                        base = (void*)strtoul(line, 0, 16);
                        break;
                  }
            }
            fclose(fd);
      }
      return base;
}
/**
 * 获取重定位的基址
 */
Elf_Addr get_load_base(Elf_Ehdr *ehdr) {
      Elf_Addr result = 0;
      Elf_Addr offset = ehdr->e_phoff;
      Elf_Phdr *p = (Elf_Phdr*)(((char*)ehdr) + offset);
      for (int i = 0; i < ehdr->e_phnum; i++, p++) {
            if (p->p_type == PT_LOAD) {
                  result = ((Elf_Addr)ehdr) + p->p_offset - p->p_vaddr;
                  break;
            }
      }
      return result;
}
/**
 * 获取 symbol 哈希 code
 */
unsigned elf_hash(const char *name) {
      const unsigned char *temp = (const unsigned char*)name;
      unsigned h = 0;
      unsigned g = 0;
      while (*temp) {
            h = (h << 4) + *temp++;
            g = h & 0xF0000000;
            h ^= g;
            h ^= g >> 24;
      }
      return h;
}

/**
 * 获取 symbol 哈希 code
 */
uint32_t gnu_hash(const char *name) {
      uint32_t h = 5381;
      const uint8_t *temp = (const uint8_t*)name;
      while (*temp) {
            // h*33 + c = h + h * 32 + c = h + h << 5 + c
            h += (h << 5) + *temp++;
      }
      return h;
}

/**
 * 获取段
 */
template<class T>
void get_segment_info(Elf_Info *info, const Elf_Word type, Elf_Phdr **ppPhdr, Elf_Word *pSize, T *pData) {
      Elf_Phdr *result = 0;
      Elf_Phdr *phdr   = info->phdr;
      for (int i = 0; i < info->ehdr->e_phnum; i++) {
            if (phdr[i].p_type == type) {
                  result = phdr + i;
                  break;
            }
      }
      if (result) {
            SAFE_SET_VALUE(pData, reinterpret_cast<T>((char*)info->elf_base + result->p_vaddr));
            SAFE_SET_VALUE(pSize, result->p_memsz);
      }
      SAFE_SET_VALUE(ppPhdr, result);
}
/**
 * 获取 elf 文件信息
 */
Elf_Info* get_elf_info(const char *soname) {
      Elf_Info *info    = (Elf_Info*)malloc(sizeof(Elf_Info));
      info->elf_base    = get_elf_base(soname);
      info->ehdr        = (Elf_Ehdr*)info->elf_base;
      info->phdr        = (Elf_Phdr*)((char*)info->elf_base + info->ehdr->e_phoff);
      info->shdr        = (Elf_Shdr*)((char*)info->elf_base + info->ehdr->e_shoff);
      info->dyn         = 0;
      info->sym         = 0;
      info->bucket      = 0;
      info->chain       = 0;
      info->gnu_bucket  = 0;
      info->gnu_chain   = 0;
      info->shstr       = 0;
      info->symstr      = 0;
      info->symsz       = 0;
      info->reldyn      = 0;
      info->reldynsz    = 0;
      info->relplt      = 0;
      info->relpltsz    = 0;
      info->is_use_rela = 0;

      info->elf_base   = (void*)get_load_base(info->ehdr);

      Elf_Phdr *dymanic = 0;
      Elf_Dyn  *dyn     = 0;
      Elf_Word  size    = 0;

      get_segment_info(info, PT_DYNAMIC, &dymanic, &size, &info->dyn);
      info->dynsz = size / sizeof(Elf_Dyn);
      dyn = info->dyn;
      for (int i = 0; i < info->dynsz; i++, dyn++) {
            switch (dyn->d_tag) {
            case DT_PLTREL:
                  if (dyn->d_un.d_ptr == DT_RELA) {
                        info->is_use_rela = true;
                  }
                  break;
            case DT_REL:
            case DT_ANDROID_REL:
                  info->reldyn = reinterpret_cast<Elf_Addr>((char*)info->elf_base + dyn->d_un.d_ptr);
                  break;
            case DT_RELSZ:
            case DT_ANDROID_RELSZ:
                  info->reldynsz = dyn->d_un.d_val;
                  break;
            case DT_JMPREL:
                  info->relplt = reinterpret_cast<Elf_Addr>((char*)info->elf_base + dyn->d_un.d_ptr);
                  break;
            case DT_PLTRELSZ:
                  info->relpltsz = dyn->d_un.d_val;
                  break;
            case DT_SYMTAB:
                  info->sym = reinterpret_cast<Elf_Sym*>((char*)info->elf_base + dyn->d_un.d_ptr);
                  break;
            case DT_STRTAB:
                  info->symstr = reinterpret_cast<const char*>((char*)info->elf_base + dyn->d_un.d_ptr);
                  break;
            case DT_HASH: {
                        uint32_t *elf_raw = reinterpret_cast<uint32_t*>((char*)info->elf_base + dyn->d_un.d_ptr);
                        info->nbucket = elf_raw[0];
                        info->nchain  = elf_raw[1];
                        info->bucket  = elf_raw + 2;
                        info->chain   = info->bucket + info->nbucket;
                        break;
                  }
            case DT_GNU_HASH: {
                        uint32_t *gnu_raw      = reinterpret_cast<uint32_t*>((char*)info->elf_base + dyn->d_un.d_ptr);
                        info->gnu_nbucket      = gnu_raw[0];
                        info->gnu_symndx       = gnu_raw[1];
                        info->gnu_maskwords    = gnu_raw[2];
                        info->gnu_shift2       = gnu_raw[3];
                        info->gnu_bloom_filter = reinterpret_cast<Elf_Addr*>((char*)info->elf_base + dyn->d_un.d_ptr + 16);
                        info->gnu_bucket       = reinterpret_cast<uint32_t*>(info->gnu_bloom_filter + info->gnu_maskwords);
                        info->gnu_chain        = info->gnu_bucket + info->gnu_nbucket - info->gnu_symndx;
                        if (!powerof2(info->gnu_maskwords)) {
                              return 0;
                        }
                        info->gnu_maskwords -= 1;
                        break;
                  }
            }
      }
      if (info->symstr && info->sym) {
            info->symsz = ((uint)info->symstr - (uint)info->sym)/sizeof(Elf_Sym);
      }
      return info;
}
/**
 * 根据 hash, 找到 symbol 的表项
 */
void elf_lookup(Elf_Info *info, const char *symbol, Elf_Sym** sym, int* symidx) {
      Elf_Sym *result = 0;
      unsigned hash   = elf_hash(symbol);
      uint32_t index  = info->bucket[hash % info->nbucket];
      if (strcmp(info->symstr + info->sym[index].st_name, symbol) == 0) {
            result = info->sym + index;
      }
      if (!result) {
            do {
                  index = info->chain[index];
                  if (strcmp(info->symstr + info->sym[index].st_name, symbol) == 0) {
                        result = info->sym + index;
                        break;
                  }
            } while (index != 0);
      }
      if (sym) {
            *sym  = result;
      }
      if (symidx) {
            *symidx = index;
      }
}
/**
 * 根据 gnu hash, 找到 symbol 的表项
 */
void gnu_lookup(Elf_Info *info, const char *symbol, Elf_Sym** sym, int* symidx) {
      Elf_Sym *result = 0;

      uint32_t hash  = gnu_hash(symbol);
      uint32_t h2    = hash >> info->gnu_shift2;
      uint32_t index = 0;
      if (info->gnu_bloom_filter && info->gnu_bucket && info->gnu_chain) {
            uint32_t bloom_mask_bits = sizeof(Elf_Addr) * 8;
            uint32_t word_num        = (hash / bloom_mask_bits) & info->gnu_maskwords;
            Elf_Addr bloom_word      = info->gnu_bloom_filter[word_num];
                     index           = info->gnu_bucket[hash % info->gnu_nbucket];

            if ((1 & (bloom_word >> (hash % bloom_mask_bits)) & (bloom_word >> (h2 % bloom_mask_bits))) == 0) {
                  // error
                  return;
            }
            if (index == 0) {
                  // error
                  return;
            }
            do {
                  Elf_Sym *s = info->sym + index;
                  if (((info->gnu_chain[index] ^ hash) >> 1) == 0 && strcmp(info->symstr + s->st_name, symbol) == 0) {
                        result = s;
                        break;
                  }
            } while ((info->gnu_chain[index++] & 1) == 0);
      }
      if (sym) {
            *sym = result;
      }
      if (symidx) {
            *symidx = index;
      }
}

void* call_ifunc_resolver(Elf_Addr addr) {
      typedef Elf_Addr (*ifunc_resolver_t)(void);
      ifunc_resolver_t resolver = (ifunc_resolver_t)(addr);
      Elf_Addr ifunc_addr = resolver();
      return (void*)ifunc_addr;
}
/**
 * 获取符号的真实地址
 */
void* resolve_symbol_address(Elf_Info *info, Elf_Sym *sym) {
      if (ELF_ST_TYPE(sym->st_info) == STT_GNU_IFUNC) {
            return call_ifunc_resolver((Elf_Addr)((char*)info->elf_base + sym->st_value));
      }
      else {
            return (void*)((char*)info->elf_base + sym->st_value);
      }
}
/**
 * 设置内存访问权限, 注意需要内存页对齐
 */
bool set_mem_access(Elf_Addr addr, int prots) {
      void *page_start = (void*)PAGE_START(addr);
      return mprotect(page_start, my_getpagesize(), prots) == 0;
}
/**
 * 获取访问权限
 */
bool get_mem_access(Elf_Info* info, Elf_Addr addr, uint32_t* prots) {
      bool res = false;
      Elf_Phdr result;
      Elf_Phdr *phdr   = info->phdr;
      for (int i = 0; i < info->ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_LOAD) {
                  result = phdr[i];
                  Elf_Addr seg_start      = reinterpret_cast<Elf_Addr>((char*)info->elf_base + result.p_vaddr);
                  Elf_Addr seg_end        = seg_start + result.p_memsz;
                  Elf_Addr seg_page_start = PAGE_START(seg_start);
                  Elf_Addr seg_page_end   = PAGE_END(seg_end);
                  if (addr >= seg_page_start && addr < seg_page_end) {
                        *prots = PFLAGS_TO_PROT(result.p_flags);
                        res = true;
                  }
            }
      }
      return res;
}

int my_getpagesize(void) {
      return PAGE_SIZE;
}
/**
 * 清除 cpu 片上缓存
 */
void clear_cache(void *addr, size_t len) {
      void *end = (uint8_t*)addr + len;
      syscall(0xf0002, addr, end);
}

bool replace_function(Elf_Info* info, void *addr, void *replaceFunc, void **originalFunc) {
      bool res = false;
      uint32_t old_prots = PROT_READ;
      uint32_t prots     = PROT_READ;

      if (*(void**)addr == replaceFunc) {
            // 如果目标已经等于 replaceFunc
            goto fail;
      }
      if (!get_mem_access(info, reinterpret_cast<Elf_Addr>(addr), &old_prots)) {
            goto fail;
      }
      // 这里需要添加写权限
      prots = old_prots |= PROT_WRITE;
      if ((prots & PROT_WRITE) != 0) {
            prots &= ~PROT_EXEC;
      }
      if (!set_mem_access(reinterpret_cast<Elf_Addr>(addr), prots)) {
            goto fail;
      }
      *originalFunc = *(void**)addr;
      *(void**)addr = replaceFunc;
      // android 7.1 以下才清除缓存
      if (get_android_version() < 25) {
            clear_cache(addr, my_getpagesize());
      }
      res = true;
fail:
      return res;
}

void* get_symbol_address(Elf_Info *info, const char *symbol) {
      void *address = 0;
      Elf_Sym *result = 0;
      // gnu
      if (!result) {
            if (info->gnu_bucket) {
                  gnu_lookup(info, symbol, &result, 0);
                  if (!result) {
                        for (int i = 0; i < (int)info->gnu_symndx; i++) {
                              const char *sname = reinterpret_cast<const char*>(info->symstr + info->sym[i].st_name);
                              if (strcmp(sname, symbol) == 0) {
                                    result = info->sym + i;
                                    break;
                              }
                        }
                  }
            }
      }
      // elf
      if (!result) {
            if (info->bucket) {
                  elf_lookup(info, symbol, &result, 0);
                  if (!result) {
                        for (int i = 0; i < info->symsz; i++) {
                              const char *sname = reinterpret_cast<const char*>(info->symstr + info->sym[i].st_name);
                              if (strcmp(sname, symbol) == 0) {
                                    result = info->sym + i;
                                    break;
                              }
                        }
                  }
            }
      }
      if (result) {
            address = resolve_symbol_address(info, result);
      }
      return address;
}

bool replace_symbol_address(Elf_Info *info, const char *symbol, void *replaceFunc, void** originalFunc) {
      void*     address = 0;
      Elf_Sym*  sym     = 0;
      int       symidx  = 0;
      /**
       * 先找到 symbol 符号
       */
      if (!sym) {
            if (info->gnu_bucket) {
                  gnu_lookup(info, symbol, &sym, &symidx);
                  if (!sym) {
                        for (int i = 0; i < (int) info->gnu_symndx; i++) {
                              const char *sname = reinterpret_cast<const char*>(info->symstr + info->sym[i].st_name);
                              if (strcmp(sname, symbol) == 0) {
                                    sym    = info->sym + i;
                                    symidx = i;
                                    break;
                              }
                        }
                  }
            }
      }
      if (!sym) {
            if (info->bucket) {
                  elf_lookup(info, symbol, &sym, &symidx);
                  if (!sym) {
                        for (int i = 0; i < info->symsz; i++) {
                              const char *sname = reinterpret_cast<const char*>(info->symstr + info->sym[i].st_name);
                              if (strcmp(sname, symbol) == 0) {
                                    sym    = info->sym + i;
                                    symidx = i;
                                    break;
                              }
                        }
                  }
            }
      }
      /**
       * 替换 symbol 的相对 plt
       */
      if (sym) {
            uint32_t relplt_size = info->is_use_rela ? info->relpltsz / sizeof(Elf_Rela) : info->relpltsz / sizeof(Elf_Rel);
            for (uint32_t i = 0; i < relplt_size; i++) {
                  unsigned long r_info   = 0;
                  Elf_Addr      r_offset = 0;
                  if (info->is_use_rela) {
                        Elf_Rela *rela = reinterpret_cast<Elf_Rela*>(info->relplt + (sizeof(Elf_Rela) * i));
                        r_info         = (unsigned long)rela->r_info;
                        r_offset       = rela->r_offset;
                  }
                  else {
                        Elf_Rel *rel = reinterpret_cast<Elf_Rel*>(info->relplt + (sizeof(Elf_Rel) * i));
                        r_info       = (unsigned long)rel->r_info;
                        r_offset     = rel->r_offset;
                  }
                  if (elf_r_sym(r_info) == symidx && elf_r_type(r_info) == R_GENERIC_JUMP_SLOT) {
                        void *addr = (void*)((char*)info->elf_base + r_offset);
                        if (!replace_function(info, addr, replaceFunc, originalFunc)) {
                              return false;
                        }
                        break;
                  }
            }

            uint32_t reldyn_size = info->is_use_rela ? info->reldynsz / sizeof(Elf_Rela) : info->reldynsz / sizeof(Elf_Rel);
            for (uint32_t i = 0; i < reldyn_size; i++) {
                  unsigned long r_info   = 0;
                  Elf_Addr      r_offset = 0;
                  if (info->is_use_rela) {
                        Elf_Rela *rela = reinterpret_cast<Elf_Rela*>(info->reldyn + (sizeof(Elf_Rela) * i));
                        r_info = (unsigned long)rela->r_info;
                        r_offset = rela->r_offset;
                  }
                  else {
                        Elf_Rel *rel = reinterpret_cast<Elf_Rel*>(info->reldyn + (sizeof(Elf_Rel) * i));
                        r_info = (unsigned long)rel->r_info;
                        r_offset = rel->r_offset;
                  }
                  if (elf_r_sym(r_info) == symidx && (elf_r_type(r_info) == R_GENERIC_ABS || elf_r_type(r_info) == R_GENERIC_GLOB_DAT)) {
                        void *addr = (void*)((char*)info->elf_base + r_offset);
                        if (!replace_function(info, addr, replaceFunc, originalFunc)) {
                              return false;
                        }
                        break;
                  }
            }
      }
      return true;
}

char* search_symbol_address(Elf_Info *info, uint64_t pc) {
      char *result = 0;
      if (info->sym) {
            for (int i = 0; i < info->symsz; i++) {
                  Elf_Sym *symbol = info->sym + i;
                  uint64_t func_base = (uint64_t) resolve_symbol_address(info, symbol);
                  uint64_t func_end  = func_base + symbol->st_size;
                  // __LP64__
                  #if defined(__ARM_ARCH_7A__) | defined(__i386__)
                        func_base &= 0xFFFFFFFF;
                        func_end  &= 0xFFFFFFFF;
                  #endif

                  if (func_base <= pc && func_end >= pc) {
                	    const char *sname = reinterpret_cast<const char*>(info->symstr + symbol->st_name);
                	    uint64_t offset = pc - func_base;
                	    result = (char*)malloc(sizeof(char) * 1024);
                        #if defined(__ARM_ARCH_7A__) | defined(__i386)
                	          sprintf(result, "(%08x)%s + %d", (uint32_t)symbol->st_value + (uint32_t)offset, sname, (uint32_t)offset);
                        #elif defined(__aarch64__) | defined(__x86_64)
                	          sprintf(result, "(%016llx)%s + %d", symbol->st_value + offset, sname, offset);
                        #endif
                	    break;
                  }
            }
      }
      return result;
}

__attribute__((visibility ("default")))
char* __rtl_search(const char* soname, uint64_t pc) {
      Elf_Info *info = get_elf_info(soname);
      char     *crash = search_symbol_address(info, pc);
      free(info);
      return crash;
}

__attribute__((visibility ("default")))
void* __rtl_entry(const char* soname, const char* symbol) {
      Elf_Info *info = get_elf_info(soname);
      void     *base = get_symbol_address(info, symbol);
      free(info);
      return base;
}

__attribute__((visibility ("default")))
bool  __rtl_replace(const char* soname, const char* symbol, void* replaceFunc, void** originalFunc) {
      Elf_Info *info   = get_elf_info(soname);
      bool      result = replace_symbol_address(info, symbol, replaceFunc, originalFunc);
      free(info);
      return result;
}
