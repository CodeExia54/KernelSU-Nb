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
# OLLVM Configuration
# ===============================
OLLVM_DIR := $(MDIR)/android-ollvm
OLLVM_CC  := $(OLLVM_DIR)/bin/clang

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
# Enhanced Obfuscation Levels
# ===============================
OLLVM_LEVEL ?= easy

# Level 1: Basic - just control flow flattening
ifeq ($(OLLVM_LEVEL),easy)
    OLLVM_FLAGS := \
        -mllvm -fla
    OLLVM_DESC := "Control Flow Flattening only"
endif

# Level 2: Medium - flattening + substitution
ifeq ($(OLLVM_LEVEL),medium)
    OLLVM_FLAGS := \
        -mllvm -fla \
        -mllvm -sub \
        -mllvm -sub_loop=2
    OLLVM_DESC := "FLA + SUB (2 loops)"
endif

# Level 3: Hard - all transformations
ifeq ($(OLLVM_LEVEL),hard)
    OLLVM_FLAGS := \
        -mllvm -fla \
        -mllvm -split \
        -mllvm -split_num=3 \
        -mllvm -sub \
        -mllvm -sub_loop=3 \
        -mllvm -bcf \
        -mllvm -bcf_loop=2 \
        -mllvm -bcf_prob=40 \
        -mllvm -sobf
    OLLVM_DESC := "FLA + SPLIT(3) + SUB(3 loops) + BCF(2 loops, 40%) + String Obfuscation"
endif

# Level 4: Extreme - maximum obfuscation
ifeq ($(OLLVM_LEVEL),extreme)
    OLLVM_FLAGS := \
        -mllvm -fla \
        -mllvm -split \
        -mllvm -split_num=5 \
        -mllvm -sub \
        -mllvm -sub_loop=5 \
        -mllvm -bcf \
        -mllvm -bcf_loop=3 \
        -mllvm -bcf_prob=60 \
        -mllvm -sobf
    OLLVM_DESC := "Maximum obfuscation (may impact performance)"
endif

# ===============================
# Enable OLLVM for specific objects
# ===============================
ifeq ($(OLLVM),1)
    # Print OLLVM configuration
    $(info )
    $(info ==============================================)
    $(info OLLVM OBFUSCATION CONFIGURATION)
    $(info Level: $(OLLVM_LEVEL))
    $(info Description: $(OLLVM_DESC))
    $(info Flags: $(OLLVM_FLAGS))
    $(info Objects: $(OLLVM_OBJS))
    $(info Compiler: $(OLLVM_CC))
    $(info ==============================================)
    $(info )
    
    # Add OLLVM debug markers
    ccflags-y += -DOLLVM_ENABLED=1
    ccflags-y += -DOLLVM_LEVEL_$(shell echo $(OLLVM_LEVEL) | tr 'a-z' 'A-Z')
    
    # Only compile specific objects with OLLVM
    $(foreach obj,$(OLLVM_OBJS),$(eval $(obj:.o=).o: ccflags-y += $(OLLVM_COMMON_FLAGS) $(OLLVM_FLAGS) -DOLLVM_COMPILED_$(shell echo $(OLLVM_LEVEL) | tr 'a-z' 'A-Z')))
    $(foreach obj,$(OLLVM_OBJS),$(eval $(obj:.o=).o: CC := $(OLLVM_CC)))
endif

# ===============================
# OLLVM Verification Helper
# ===============================
define verify_ollvm
    @echo "=== OLLVM Verification for $(1) ==="
    @if [ -f "$(1)" ]; then \
        echo "File: $(1)"; \
        echo "Size: $$(du -h "$(1)" | cut -f1)"; \
        echo "Checking for OLLVM patterns..."; \
        strings -n 8 "$(1)" | grep -i "fla\|bcf\|sub\|split" | head -5 || echo "  No patterns found"; \
        echo "Compiler signatures:"; \
        strings "$(1)" | grep -i "clang.*14\|llvm.*14" | head -3 || echo "  None found"; \
    else \
        echo "File not found: $(1)"; \
    fi
    @echo ""
endef

# ===============================
# Targets
# ===============================
all:
	make -C $(KDIR) M=$(MDIR) modules

clean:
	make -C $(KDIR) M=$(MDIR) clean

verify:
	@echo "=== OLLVM BUILD VERIFICATION ==="
	@echo "Configuration:"
	@echo "  OLLVM Enabled: $(if $(OLLVM),YES,NO)"
	@echo "  OLLVM Level: $(OLLVM_LEVEL)"
	@echo "  OLLVM Description: $(OLLVM_DESC)"
	@echo ""
	@echo "Checking OLLVM objects:"
	$(foreach obj,$(OLLVM_OBJS),$(call verify_ollvm,$(obj)))
	@echo "Checking non-OLLVM objects (for comparison):"
	$(call verify_ollvm,src/net/wuwa_sock.o)
	$(call verify_ollvm,src/ioctl/wuwa_ioctl.o)

.PHONY: all clean verify
