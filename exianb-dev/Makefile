# Unified Makefile for Single-File Module Structure
# Supports both Traditional and DDK builds

# Detect build mode
ifdef DDK_BUILD
    # DDK Fast Build Mode - Direct module compilation
    obj-m := $(MODULE_NAME).o
    $(MODULE_NAME)-y := $(MODULE_NAME).o
    
    # Common compiler flags for DDK
    ccflags-y += -Wno-implicit-function-declaration -Wno-strict-prototypes
    ccflags-y += -Wno-int-conversion -Wno-gcc-compat
    ccflags-y += -Wno-declaration-after-statement -Wno-unused-function
    ccflags-y += -Wno-unused-variable
    
    # DDK-specific flags
    ccflags-y += -DDDK_BUILD
    
else
    # Traditional Slow Build Mode - Kernel integration
    obj-$(CONFIG_PVM_MOD) += $(MODULE_NAME).o
    
    # Same compiler flags for compatibility
    ccflags-y += -Wno-implicit-function-declaration -Wno-strict-prototypes
    ccflags-y += -Wno-int-conversion -Wno-gcc-compat
    ccflags-y += -Wno-declaration-after-statement -Wno-unused-function
    ccflags-y += -Wno-unused-variable
endif

# Common variables
MODULE_NAME ?= $(notdir $(CURDIR))
KDIR ?= /lib/modules/$(shell uname -r)/build
MDIR := $(CURDIR)

$(info -- Build Mode: $(if $(DDK_BUILD),DDK Fast Build,Traditional Slow Build))
$(info -- Module: $(MODULE_NAME))
$(info -- KDIR: $(KDIR))
$(info -- MDIR: $(MDIR))

# Include current directory for header files
ccflags-y += -I$(MDIR)

# Common build targets
all:
	$(if $(DDK_BUILD), \
		@echo "Building $(MODULE_NAME) in DDK mode..." && \
		make -C $(KDIR) M=$(MDIR) modules, \
		@echo "Building $(MODULE_NAME) in traditional mode..." && \
		$(MAKE) KDIR=$(KDIR) M=$(MDIR) modules \
	)

clean:
	make -C $(KDIR) M=$(MDIR) clean

.PHONY: all clean
