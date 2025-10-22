# Simple Kernel Module Makefile
obj-m += $(MODULE_NAME).o

MODULE_NAME ?= $(notdir $(CURDIR))

# Compiler flags
ccflags-y += -Wno-implicit-function-declaration -Wno-strict-prototypes
ccflags-y += -Wno-int-conversion -Wno-gcc-compat
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function
ccflags-y += -Wno-unused-variable

# Include path
ccflags-y += -I$(src)

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

.PHONY: all clean
