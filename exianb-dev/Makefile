# Simple Makefile for DDK builds
obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-y := $(MODULE_NAME).o

MODULE_NAME ?= $(notdir $(CURDIR))
KDIR ?= /lib/modules/$(shell uname -r)/build

# Common compiler flags
ccflags-y += -Wno-implicit-function-declaration -Wno-strict-prototypes
ccflags-y += -Wno-int-conversion -Wno-gcc-compat
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function
ccflags-y += -Wno-unused-variable

# Include current directory for header files
ccflags-y += -I$(CURDIR)

all:
	make -C $(KDIR) M=$(CURDIR) modules

clean:
	make -C $(KDIR) M=$(CURDIR) clean

.PHONY: all clean
