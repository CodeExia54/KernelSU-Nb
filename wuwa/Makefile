# ===============================
# Kernel Module
# ===============================
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

# ===============================
# Paths
# ===============================
src := $(if $(filter /%,$(src)),$(src),$(srctree)/$(src))
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

# ===============================
# Toolchain Configuration
# ===============================
# OLLVM Clang (for specific objects)
ifdef OLLVM_CLANG_PATH
    OLLVM_CC := $(OLLVM_CLANG_PATH)
else
    OLLVM_DIR := $(MDIR)/android-ollvm
    OLLVM_CC  := $(OLLVM_DIR)/bin/clang
endif

# Container Clang (for linking and non-obfuscated objects)
ifdef CONTAINER_CLANG_PATH
    CONTAINER_CC := $(CONTAINER_CLANG_PATH)
else
    # Default to kernel's default clang
    CONTAINER_CC := $(CC)
endif

# ===============================
# Debug Info
# ===============================
$(info )
$(info === TOOLCHAIN CONFIGURATION ===)
$(info OLLVM Clang: $(OLLVM_CC))
$(info Container Clang: $(CONTAINER_CC))
$(info OLLVM Enabled: $(OLLVM))
$(info )

# ===============================
# Include paths
# ===============================
ccflags-y += \
    -I$(src)/src/core \
    -I$(src)/src/net \
    -I$(src)/src/ioctl \
    -I$(src)/src/mm \
    -I$(src)/src/inlinehook \
    -I$(src)/src/hook \
    -I$(src)/src/proc \
    -I$(src)/src/utils

# ===============================
# Warnings / Defines
# ===============================
ccflags-y += \
    -Wno-implicit-function-declaration \
    -Wno-strict-prototypes \
    -Wno-int-conversion \
    -Wno-gcc-compat \
    -Wno-declaration-after-statement \
    -Wno-unused-function \
    -Wno-unused-variable \
    -Wno-unused-label

ccflags-y += -DHIDE_SELF_MODULE
ccflags-y += -DBUILD_HIDE_SIGNAL
ccflags-y += -DBUILD_NO_CFI
ccflags-y += -DENABLE_WUWA_LOGS

# ===============================
# OLLVM Common Flags
# ===============================
OLLVM_COMMON_FLAGS := \
    -fno-lto \
    -fno-sanitize=cfi \
    -fno-sanitize=shadow-call-stack

# ===============================
# Objects to obfuscate with OLLVM
# ===============================
OLLVM_OBJS := \
    src/core/wuwa.o \
    src/utils/wuwa_utils.o \
    src/mm/wuwa_page_walk.o \
    src/mm/wuwa_bindproc.o

# ===============================
# Objects to compile with container clang
# ===============================
CONTAINER_OBJS := \
    src/net/wuwa_sock.o \
    src/net/wuwa_protocol.o \
    src/ioctl/wuwa_ioctl.o \
    src/hook/wuwa_safe_signal.o \
    src/proc/wuwa_proc.o \
    src/inlinehook/hijack_arm64.o \
    src/utils/karray_list.o

# ===============================
# Obfuscation Levels
# ===============================
OLLVM_LEVEL ?= easy

ifeq ($(OLLVM_LEVEL),easy)
    OLLVM_FLAGS := -mllvm -fla
endif

ifeq ($(OLLVM_LEVEL),medium)
    OLLVM_FLAGS := -mllvm -fla -mllvm -sub
endif

ifeq ($(OLLVM_LEVEL),hard)
    OLLVM_FLAGS := -mllvm -fla -mllvm -split -mllvm -sub
endif

ifeq ($(OLLVM_LEVEL),extreme)
    OLLVM_FLAGS := -mllvm -fla -mllvm -split -mllvm -sub -mllvm -bcf -mllvm -sobf
endif

# ===============================
# CUSTOM OLLVM FLAGS from workflow
# ===============================
ifdef OLLVM_CUSTOM_FLAGS
    # Override with custom flags from workflow
    OLLVM_FLAGS := $(OLLVM_CUSTOM_FLAGS)
    $(info Using custom OLLVM flags: $(OLLVM_FLAGS))
endif

# ===============================
# MIXED TOOLCHAIN: Enable OLLVM for specific objects only
# ===============================
ifeq ($(OLLVM),1)
    # ============================================
    # 1. OLLVM OBJECTS: Compile with OLLVM clang
    # ============================================
    $(foreach obj,$(OLLVM_OBJS), \
        $(eval CFLAGS_$(basename $(obj)).o := $(OLLVM_COMMON_FLAGS) $(OLLVM_FLAGS)) \
        $(eval $(obj): CC := $(OLLVM_CC)) \
    )
    
    # ============================================
    # 2. CONTAINER OBJECTS: Compile with container clang
    # ============================================
    $(foreach obj,$(CONTAINER_OBJS), \
        $(eval $(obj): CC := $(CONTAINER_CC)) \
    )
    
    # ============================================
    # 3. LINKING: Use container clang for linking
    # ============================================
    # The final module object and linking should use container clang
    android-wuwa.o: CC := $(CONTAINER_CC)
    LD := $(CONTAINER_CC)
    
    # ============================================
    # 4. Debug output
    # ============================================
    $(info ==============================================)
    $(info MIXED TOOLCHAIN CONFIGURATION)
    $(info OLLVM Level: $(OLLVM_LEVEL))
    $(info OLLVM Objects (4): $(OLLVM_OBJS))
    $(info Container Objects (7): $(CONTAINER_OBJS))
    $(info Linking with: $(CONTAINER_CC))
    $(info ==============================================)
    $(info )
endif

# ===============================
# Targets
# ===============================
all:
	make -C $(KDIR) M=$(MDIR) modules

clean:
	make -C $(KDIR) M=$(MDIR) clean

.PHONY: all clean
