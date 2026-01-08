obj-m := android-wuwa.o

android-wuwa-y := \
    src/core/wuwa.o \
    src/net/wuwa_sock.o \
    src/net/wuwa_protocol.o \
    src/utils/wuwa_utils.o \
    src/ioctl/wuwa_ioctl.o \
    src/mm/wuwa_page_walk.o \
    src/hook/wuwa_safe_signal.o \
    src/proc/wuwa_proc.o \
    src/inlinehook/hijack_arm64.o \
    src/utils/karray_list.o \
    src/mm/wuwa_bindproc.o

src := $(if $(filter /%,$(src)),$(src),$(srctree)/$(src))

KDIR := $(KDIR)
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

$(info -- KDIR: $(KDIR))
$(info -- MDIR: $(MDIR))
$(info -- WUWA_SRC_DIR: $(src))
$(info -- WUWA_OBJ_DIR: $(obj))

ccflags-y += -I$(src)/src/core -I$(src)/src/net -I$(src)/src/ioctl -I$(src)/src/mm
ccflags-y += -I$(src)/src/inlinehook -I$(src)/src/hook -I$(src)/src/proc -I$(src)/src/utils

ccflags-y += -Wno-implicit-function-declaration -Wno-strict-prototypes -Wno-int-conversion -Wno-gcc-compat
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function -Wno-unused-variable
ccflags-y += -Wno-unused-label  # ADDED THIS LINE TO FIX THE ERROR

# ========== DECLANG COMPATIBILITY FIXES ==========
# Check if we're using DeClang and fix incompatible flags
ifneq ($(CC),clang)
  ifeq ($(shell $(CC) --version 2>/dev/null | grep -i declang),)
    # Not DeClang, use normal flags
    DECLANG_FIXES :=
  else
    # Using DeClang - apply fixes
    $(info -- Using DeClang compiler, applying compatibility fixes)
    
    # Remove deprecated auto-init flags that DeClang doesn't like
    KBUILD_CFLAGS := $(filter-out -enable-trivial-auto-var-init-zero-knowing-it-will-be-removed-from-clang,$(KBUILD_CFLAGS))
    KBUILD_CFLAGS := $(filter-out -enable-trivial-auto-var-init-zero-knowing-it-will-be-removed-from-clang%,$(KBUILD_CFLAGS))
    KBUILD_CFLAGS := $(filter-out -ftrivial-auto-var-init=zero%,$(KBUILD_CFLAGS))
    
    # Suppress unused command line argument warnings
    KBUILD_CFLAGS += -Wno-unused-command-line-argument
    
    # DeClang-specific optimizations can go here
    DECLANG_FIXES := -Wno-unused-command-line-argument
  endif
endif

# Add DeClang fixes to ccflags
ccflags-y += $(DECLANG_FIXES)

# 编译时启用 隐藏模块功能
ccflags-y += -DHIDE_SELF_MODULE
# 编译时启用 PTE_MAPPING 功能
#ccflags-y += -DBUILD_PTE_MAPPING
# 编译时启用 HIDE_SIGNAL 功能
ccflags-y += -DBUILD_HIDE_SIGNAL
#ccflags-y += -DPTE_WALK
ccflags-y += -DBUILD_NO_CFI
# LOG CONTROL - Add this line to ENABLE logs, comment to DISABLE logs
ccflags-y += -DENABLE_WUWA_LOGS

all:
	make -C $(KDIR) M=$(MDIR) modules

clean:
	make -C $(KDIR) M=$(MDIR) clean
    
compdb:
	python3 $(MDIR)/.vscode/generate_compdb.py -O $(KDIR) $(MDIR)

.PHONY: all clean
