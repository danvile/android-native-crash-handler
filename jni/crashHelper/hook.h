#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/elf.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <android/log.h>

#ifndef __HOOK__H__
#define __HOOK__H__

extern "C" void* __rtl_entry  (const char*, const char*);
extern "C" bool  __rtl_replace(const char*, const char*, void*, void**);
extern "C" char* __rtl_search(const char* soname, uint64_t pc);
#endif
