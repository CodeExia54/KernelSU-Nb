MODULE_NAME := panic_store
RESMAN_CORE_OBJS:=main.o

CFLAGS += -std=c99

RESMAN_GLUE_OBJS:=
ifneq ($(KERNELRELEASE),)
	
	obj-m := $(MODULE_NAME).o
	
	$(MODULE_NAME)-objs:=$(RESMAN_GLUE_OBJS) $(RESMAN_CORE_OBJS)
else
	KDIR := /root/android-kernel/mi8/out
all:
	make -C $(KDIR) ARCH=arm64 CROSS_COMPILE=aarch64-linux-android- M=$(PWD) modules
clean:
	@find . -name "*.o" -type f -delete
	@find . -name "*.o.cmd" -type f -delete
	rm -rf *.o *.mod .*.*.cmd *.mod.o *.mod.c *.symvers *.order .tmp_versions
endif