# Simple Kernel Module Makefile
obj-m := offset.o

# Compiler flags
ccflags-y += -Wno-implicit-function-declaration -Wno-strict-prototypes
ccflags-y += -Wno-int-conversion -Wno-gcc-compat
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function
ccflags-y += -Wno-unused-variable

# Remove ALL other targets - let kernel build system handle everything
