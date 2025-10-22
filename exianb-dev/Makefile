# Simple Kernel Module Makefile - Works with DDK
obj-m := exianb-dev.o

# Add all your source files here if you have multiple
# exianb-dev-y := file1.o file2.o

# Compiler flags
ccflags-y += -Wno-implicit-function-declaration -Wno-strict-prototypes
ccflags-y += -Wno-int-conversion -Wno-gcc-compat
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function
ccflags-y += -Wno-unused-variable

# Include current directory for headers
ccflags-y += -I$(PWD)
