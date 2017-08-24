LOCAL_PATH := $(call my-dir)
###############################################################################
#       crashHelper
#       author:zd
###############################################################################
include $(CLEAR_VARS)
LOCAL_MODULE             :=  crashHelper
LOCAL_SRC_FILES          :=  crashHelper/com_iexin_common_CrashHelper.cpp  \
                             crashHelper/hook.cpp                          \
                             crashHelper/my_getcontext.S
LOCAL_LDLIBS             +=  -L$(SYSROOT)/usr/lib -llog
LOCAL_C_INCLUDES         :=  $(LOCAL_PATH)/unwind/include
LOCAL_ARM_MODE           :=  arm
LOCAL_CFLAGS             +=  -fvisibility=hidden -Wno-pointer-arith -Wno-deprecated-declarations
LOCAL_STATIC_LIBRARIES   :=  unwind               \
                             unwind-arch          \
                             unwind-dwarf-common  \
                             unwind-dwarf-generic \
                             unwind-dwarf-local   \
                             unwind-elf           \
                             unwind-ptrace        \
                             unwind-setjmp
include $(BUILD_SHARED_LIBRARY)
###############################################################################
#       unwind
#       author:zd
###############################################################################
include $(CLEAR_VARS)
LOCAL_MODULE             :=  unwind
LOCAL_LDLIBS             +=  -L$(SYSROOT)/usr/lib -llog
LOCAL_SRC_FILES          :=  unwind/android/$(TARGET_ARCH_ABI)/libunwind.a
include $(PREBUILT_STATIC_LIBRARY)
###############################################################################
#       unwind-arch
#       author:zd
###############################################################################
include $(CLEAR_VARS)
LOCAL_MODULE             :=  unwind-arch
LOCAL_LDLIBS             +=  -L$(SYSROOT)/usr/lib -llog

ifeq ($(TARGET_ARCH_ABI),armeabi-v7a)
LOCAL_SRC_FILES          :=  unwind/android/$(TARGET_ARCH_ABI)/libunwind-arm.a
endif
ifeq ($(TARGET_ARCH_ABI),arm64-v8a)
LOCAL_SRC_FILES          :=  unwind/android/$(TARGET_ARCH_ABI)/libunwind-aarch64.a
endif
ifeq ($(TARGET_ARCH_ABI),x86)
LOCAL_SRC_FILES          :=  unwind/android/$(TARGET_ARCH_ABI)/libunwind-x86.a
endif
ifeq ($(TARGET_ARCH_ABI),x86_64)
LOCAL_SRC_FILES          :=  unwind/android/$(TARGET_ARCH_ABI)/libunwind-x86_64.a
endif
include $(PREBUILT_STATIC_LIBRARY)
###############################################################################
#       unwind-dwarf-common
#       author:zd
###############################################################################
include $(CLEAR_VARS)
LOCAL_MODULE             :=  unwind-dwarf-common
LOCAL_SRC_FILES          :=  unwind/android/$(TARGET_ARCH_ABI)/libunwind-dwarf-common.a
LOCAL_LDLIBS             +=  -L$(SYSROOT)/usr/lib -llog
include $(PREBUILT_STATIC_LIBRARY)
###############################################################################
#       unwind-dwarf-generic
#       author:zd
###############################################################################
include $(CLEAR_VARS)
LOCAL_MODULE             :=  unwind-dwarf-generic
LOCAL_SRC_FILES          :=  unwind/android/$(TARGET_ARCH_ABI)/libunwind-dwarf-generic.a
LOCAL_LDLIBS             +=  -L$(SYSROOT)/usr/lib -llog
include $(PREBUILT_STATIC_LIBRARY)
###############################################################################
#       unwind-dwarf-local
#       author:zd
###############################################################################
include $(CLEAR_VARS)
LOCAL_MODULE             :=  unwind-dwarf-local
LOCAL_SRC_FILES          :=  unwind/android/$(TARGET_ARCH_ABI)/libunwind-dwarf-local.a
LOCAL_LDLIBS             +=  -L$(SYSROOT)/usr/lib -llog
include $(PREBUILT_STATIC_LIBRARY)
###############################################################################
#       unwind-elf
#       author:zd
###############################################################################
include $(CLEAR_VARS)
LOCAL_MODULE             :=  unwind-elf
LOCAL_LDLIBS             +=  -L$(SYSROOT)/usr/lib -llog

ifeq ($(TARGET_ARCH_ABI),armeabi-v7a)
LOCAL_SRC_FILES          :=  unwind/android/$(TARGET_ARCH_ABI)/libunwind-elf32.a
endif
ifeq ($(TARGET_ARCH_ABI),arm64-v8a)
LOCAL_SRC_FILES          :=  unwind/android/$(TARGET_ARCH_ABI)/libunwind-elf64.a
endif
ifeq ($(TARGET_ARCH_ABI),x86)
LOCAL_SRC_FILES          :=  unwind/android/$(TARGET_ARCH_ABI)/libunwind-elf32.a
endif
ifeq ($(TARGET_ARCH_ABI),x86_64)
LOCAL_SRC_FILES          :=  unwind/android/$(TARGET_ARCH_ABI)/libunwind-elf64.a
endif

include $(PREBUILT_STATIC_LIBRARY)
###############################################################################
#       unwind-ptrace
#       author:zd
###############################################################################
include $(CLEAR_VARS)
LOCAL_MODULE             :=  unwind-ptrace
LOCAL_SRC_FILES          :=  unwind/android/$(TARGET_ARCH_ABI)/libunwind-ptrace.a
LOCAL_LDLIBS             +=  -L$(SYSROOT)/usr/lib -llog
include $(PREBUILT_STATIC_LIBRARY)
###############################################################################
#       unwind-setjmp
#       author:zd
###############################################################################
include $(CLEAR_VARS)
LOCAL_MODULE             :=  unwind-setjmp
LOCAL_SRC_FILES          :=  unwind/android/$(TARGET_ARCH_ABI)/libunwind-setjmp.a
LOCAL_LDLIBS             +=  -L$(SYSROOT)/usr/lib -llog
include $(PREBUILT_STATIC_LIBRARY)