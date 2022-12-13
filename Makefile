TARGET := $(shell $(CC) -dumpmachine)
# Get 'uname -m'-like architecture description for target
TARGET_ARCH := $(shell echo $(TARGET) | cut -f1 -d- | tr [A-Z] [a-z])
TARGET_ARCH := $(shell echo $(TARGET_ARCH) | sed 's/powerpc/ppc/')

AUDIT_ARCH := $(shell echo $(TARGET_ARCH) | tr [a-z] [A-Z] | sed 's/^ARM.*/ARM/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/I[456]86/I386/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/PPC64/PPC/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/PPCLE/PPC64LE/')

CFLAGS += -DBUILD_TRANSFORM_OUT=\"t.out\"
CFLAGS += -DSEITAN_AUDIT_ARCH=AUDIT_ARCH_$(AUDIT_ARCH)
CFLAGS += -Wall -Wextra -pedantic

REGISTRY ?= "quay.io/"

all: bpf.out t.out seitan-loader seitan

bpf.out: qemu_filter build
	./build

t.out: qemu_filter build
	./build

build: tree.c build.c filter.h numbers.h transform.h tree.h
	$(CC) $(CFLAGS) -o build build.c tree.c

test-filter:
	$(CC) $(CFLAGS) -o tfilter test-filter.c

bpf_dbg: disasm.c
	$(CC) $(CFLAGS) -o bpf_dbg disasm.c

seitan-loader: loader.c
	$(CC) $(CFLAGS) -o seitan-loader loader.c

seitan: seitan.c transform.h
	$(CC) $(CFLAGS) -o seitan seitan.c

test:
	$(MAKE) -C tests-utils

filter.h: qemu_filter
	./filter.sh qemu_filter

numbers.h:
	./filter.sh

transform.h: qemu_filter
	./transform.sh qemu_filter

clean:
	rm -f filter.h numbers.h transform.h t.out bpf.out build seitan-loader seitan

test-images:
	podman build -t $(REGISTRY)seitan/test-seitan -f containerfiles/tests/seitan/Containerfile .
	podman build -t $(REGISTRY)seitan/test-eater -f containerfiles/tests/eater/Containerfile .
	podman build -t $(REGISTRY)seitan/benchmark -f containerfiles/tests/benchmark/Containerfile .
