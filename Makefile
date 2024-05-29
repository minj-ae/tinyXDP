BPFTOOL ?= bpftool
CLANG ?= clang -g
LLVM_STRIP ?= llvm-strip

INTERFACE ?= eth0

SOURCES = ./modules/tcp.c
OBJECTS = $(SOURCES:.c=.o)

#KERNEL_HEADERS = /usr/src/linux-headers-$(shell uname -r)

BPF_HEADERS = ./libbpf/src

#CFLAGS = -O2 -Wall -Werror -Wno-address-of-packed-member -I$(KERNEL_HEADERS)/include -I$(KERNEL_HEADERS)/arch/x86/include -I$(BPF_HEADERS)
CFLAGS = -O2 -Wall -Werror -Wno-address-of-packed-member -I$(BPF_HEADERS)

.PHONY: all clean load unload attach detach ip

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

ip:
	@/bin/bash -c ' \
	if [ -z "$(ACTION)" ] || [ -z "$(IP)" ]; then \
		echo "Usage: make ip ACTION=<add|remove> IP=<IP_ADDRESS>"; \
		exit 1; \
	fi; \
	map_id=$$(sudo $(BPFTOOL) map show | grep -w whitelist_map | awk "{print \$$1}" | cut -d: -f1); \
	if [ -z "$$map_id" ]; then \
		echo "whitelist_map not found"; \
		exit 1; \
	fi; \
	if [ "$(ACTION)" = "add" ]; then \
		ip=$(IP); \
		key=$$(printf "%02X %02X %02X %02X" $${ip//./ }); \
		sudo $(BPFTOOL) map update id $$map_id key hex $$key value hex 01; \
	elif [ "$(ACTION)" = "remove" ]; then \
		ip=$(IP); \
		key=$$(printf "%02X %02X %02X %02X" $${ip//./ }); \
		sudo $(BPFTOOL) map delete id $$map_id key hex $$key; \
	else \
		echo "Invalid action: $(ACTION). Use 'add' or 'remove'."; \
	fi'
