BPFTOOL ?= bpftool
CLANG ?= clang -g
LLVM_STRIP ?= llvm-strip

# Specify the default network interface, can be overridden by the command line
INTERFACE ?= eth0

# Add your source files here
SOURCES = ./modules/tcp.c
OBJECTS = $(SOURCES:.c=.o)

# Kernel headers directory, adjust this if needed
#KERNEL_HEADERS = /usr/src/linux-headers-$(shell uname -r)

# BPF headers directory
BPF_HEADERS = ./libbpf/src

#CFLAGS = -O2 -Wall -Werror -Wno-address-of-packed-member -I$(KERNEL_HEADERS)/include -I$(KERNEL_HEADERS)/arch/x86/include -I$(BPF_HEADERS)
CFLAGS = -O2 -Wall -Werror -Wno-address-of-packed-member -I$(BPF_HEADERS)

.PHONY: all clean load unload

all: $(OBJECTS)

%.o: %.c
	$(CLANG) -target bpf -c $(CFLAGS) $< -o $@
	$(LLVM_STRIP) -g $@

clean:
	rm -f $(OBJECTS)

load: $(OBJECTS)
	$(foreach obj, $(OBJECTS), \
		sudo $(BPFTOOL) prog load $(obj) /sys/fs/bpf/$(basename $(notdir $(obj))); \
	)

unload: $(OBJECTS)
	$(foreach obj, $(OBJECTS), \
		sudo rm -rf /sys/fs/bpf/$(basename $(notdir $(obj))); \
	)

attach: $(OBJECTS)
	$(foreach obj, $(OBJECTS), \
		sudo $(BPFTOOL) net attach xdp name tinyxdp_base dev $(INTERFACE); \
	)

detach:
	$(foreach obj, $(OBJECTS), \
		sudo $(BPFTOOL) net detach xdp dev $(INTERFACE); \
	)
