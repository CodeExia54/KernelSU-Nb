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
# Targets
# ===============================
all:
	make -C $(KDIR) M=$(MDIR) modules

clean:
	make -C $(KDIR) M=$(MDIR) clean

.PHONY: all clean
