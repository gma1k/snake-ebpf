CLANG ?= clang
LLVM_STRIP ?= llvm-strip
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
ARCH_TRIPLET := $(shell gcc -dumpmachine 2>/dev/null || echo "x86_64-linux-gnu")
BPFTOOL ?= bpftool

KERNEL_HEADERS ?= /usr/src/linux-headers-$(shell uname -r)

BPF_C := snake.bpf.c
BPF_OBJ := snake.bpf.o

CLANG_FLAGS := \
	-target bpf \
	-D__TARGET_ARCH_$(ARCH) \
	-Wall \
	-Wno-unused-value \
	-Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Werror \
	-O2 -g \
	-mcpu=v3 \
	-fno-stack-protector \
	-fno-jump-tables \
	-fno-unwind-tables \
	-fno-asynchronous-unwind-tables \
	-fno-omit-frame-pointer

INCLUDES := -I/usr/include

ifneq ($(ARCH_TRIPLET),)
	ARCH_INCLUDE := /usr/include/$(ARCH_TRIPLET)
	ifneq ($(wildcard $(ARCH_INCLUDE)),)
		INCLUDES += -I$(ARCH_INCLUDE)
	endif
endif

ifneq ($(wildcard $(KERNEL_HEADERS)),)
	# Use kernel headers for types, but let system headers resolve asm-generic
	INCLUDES += \
		-I$(KERNEL_HEADERS)/arch/$(ARCH)/include/uapi \
		-I$(KERNEL_HEADERS)/arch/$(ARCH)/include/generated/uapi \
		-I$(KERNEL_HEADERS)/include/uapi \
		-I$(KERNEL_HEADERS)/include/generated/uapi
endif

ifneq ($(wildcard /usr/local/include/bpf),)
	INCLUDES += -I/usr/local/include
endif

.PHONY: all clean

all: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_C)
	@echo "Compiling $(BPF_C) -> $(BPF_OBJ)"
	$(CLANG) $(CLANG_FLAGS) $(INCLUDES) -c $< -o $@
	$(LLVM_STRIP) -g $@

clean:
	rm -f $(BPF_OBJ)
