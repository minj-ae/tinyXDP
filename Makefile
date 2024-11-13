BPFTOOL ?= bpftool
CLANG ?= clang -g
LLVM_STRIP ?= llvm-strip

INTERFACE ?= eth0

SOURCES = ./modules/base.c
OBJECTS = $(SOURCES:.c=.o)

#KERNEL_HEADERS = /usr/src/linux-headers-$(shell uname -r)

BPF_HEADERS = ./libbpf/src

#CFLAGS = -O2 -Wall -Werror -Wno-address-of-packed-member -I$(KERNEL_HEADERS)/include -I$(KERNEL_HEADERS)/arch/x86/include -I$(BPF_HEADERS)
CFLAGS = -O2 -Wall -Werror -Wno-address-of-packed-member -Wno-unused-variable -I$(BPF_HEADERS)

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
		sudo $(BPFTOOL) net attach xdp name tinyxdp_$(basename $(notdir $(obj))) dev $(INTERFACE); \
	)

detach:
	$(foreach obj, $(OBJECTS), \
		sudo $(BPFTOOL) net detach xdp dev $(INTERFACE); \
	)


ip:
	@/bin/bash -c ' \
	source ./ip_utils.sh; \
	if [ -z "$(ACTION)" ] || [ -z "$(NETWORK)" ] || [ -z "$(MASK)" ]; then \
		echo "Usage: make ip ACTION=<add|remove> NETWORK=<NETWORK_ADDRESS> MASK=<SUBNET_MASK>"; \
		exit 1; \
	fi; \
	map_id=$$(sudo bpftool map show | grep -w whitelist_map | awk "{print \$$1}" | cut -d: -f1); \
	if [ -z "$$map_id" ]; then \
		echo "whitelist_map not found"; \
		exit 1; \
	fi; \
	network=$$(ip_to_hex $(NETWORK)); \
	prefix_len=$$(mask_to_prefix $(MASK)); \
	key="0x$$(printf "%02x" $$prefix_len) 0x00 0x00 0x00 0x$${network:0:2} 0x$${network:2:2} 0x$${network:4:2} 0x$${network:6:2}"; \
	echo "Debug: map_id=$$map_id"; \
	echo "Debug: key=$$key"; \
	if [ "$(ACTION)" = "add" ]; then \
		echo "Debug: Executing command:"; \
		echo "sudo bpftool map update id $$map_id key $$key value 0x01 0x00 0x00 0x00"; \
		sudo bpftool map update id $$map_id key $$key value 0x01 0x00 0x00 0x00; \
		echo "Added network $(NETWORK)/$$prefix_len to whitelist"; \
	elif [ "$(ACTION)" = "remove" ]; then \
		echo "Debug: Executing command:"; \
		echo "sudo bpftool map delete id $$map_id key $$key"; \
		sudo bpftool map delete id $$map_id key $$key; \
		echo "Removed network $(NETWORK)/$$prefix_len from whitelist"; \
	else \
		echo "Invalid action: $(ACTION). Use '\''add'\'' or '\''remove'\''."; \
	fi'
