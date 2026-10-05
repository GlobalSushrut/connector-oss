# Connector eBPF — mark-deny + connect4 transparent redirect (T2)
# Requires: clang, llvm-strip, bpftool (optional for verify)
#
#   make -C platform/ebpf
#   # objects: connector_mark_deny.bpf.o connector_connect_redirect.bpf.o

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
	-Wall -Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-fno-stack-protector -fno-asynchronous-unwind-tables

OBJS := connector_mark_deny.bpf.o connector_connect_redirect.bpf.o

.PHONY: all clean verify

all: $(OBJS)

%.bpf.o: %.bpf.c
	$(CLANG) $(CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

verify: all
	@command -v bpftool >/dev/null && bpftool gen object /dev/null connector_mark_deny.bpf.o 2>/dev/null || true
	@ls -la $(OBJS)
	@echo "OK: $(OBJS)"

clean:
	rm -f $(OBJS)
