obj-y += hello.o

hello-y := \
    src/core/wuwa.o \
    src/net/wuwa_sock.o \
    src/net/wuwa_protocol.o \
    src/utils/wuwa_utils.o \
    src/ioctl/wuwa_ioctl.o \
    src/mm/wuwa_page_walk.o \
    src/mm/wuwa_proc_dmabuf.o \
    src/hook/wuwa_safe_signal.o \
    src/hook/wuwa_d0_mm_fault.o \
    src/proc/wuwa_proc.o \
    src/inlinehook/hijack_arm64.o \
    src/utils/karray_list.o
    
# ccflags-y += -I$(src)/src/core -I$(src)/src/net -I$(src)/src/ioctl -I$(src)/src/mm
# ccflags-y += -I$(src)/src/inlinehook -I$(src)/src/hook -I$(src)/src/proc -I$(src)/src/utils

ccflags-y += -Wno-implicit-function-declaration -Wno-strict-prototypes -Wno-int-conversion -Wno-gcc-compat
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function

# Keep a new line here!! Because someone may append config
