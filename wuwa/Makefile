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
# OLLVM CONFIG
# ===============================
OLLVM_DIR := $(MDIR)/.ollvm/android-ollvm
OLLVM_CC  := $(OLLVM_DIR)/bin/clang

OLLVM_COMMON_FLAGS := \
    -fno-lto \
    -fno-sanitize=cfi \
    -fno-sanitize=shadow-call-stack

# ===============================
# Objects SAFE to obfuscate
# ===============================
OLLVM_OBJS := \
    src/core/wuwa.o \
    src/utils/wuwa_utils.o \
    src/mm/wuwa_page_walk.o \
    src/mm/wuwa_bindproc.o

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
    OLLVM_FLAGS := \
        -mllvm -fla \
        -mllvm -split -mllvm -split_num=2 \
        -mllvm -sub  -mllvm -sub_loop=2
endif

# ===============================
# Enable OLLVM
# ===============================
ifeq ($(OLLVM),1)
    $(OLLVM_OBJS): ccflags-y += $(OLLVM_COMMON_FLAGS) $(OLLVM_FLAGS)
    $(OLLVM_OBJS): CC := $(OLLVM_CC)
endif

# ===============================
# Targets
# ===============================
all:
	make -C $(KDIR) M=$(MDIR) modules

clean:
	make -C $(KDIR) M=$(MDIR) clean

.PHONY: all clean
