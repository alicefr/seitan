TARGET := $(shell $(CC) -dumpmachine)
# Get 'uname -m'-like architecture description for target
TARGET_ARCH := $(shell echo $(TARGET) | cut -f1 -d- | tr [A-Z] [a-z])
TARGET_ARCH := $(shell echo $(TARGET_ARCH) | sed 's/powerpc/ppc/')

AUDIT_ARCH := $(shell echo $(TARGET_ARCH) | tr [a-z] [A-Z] | sed 's/^ARM.*/ARM/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/I[456]86/I386/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/PPC64/PPC/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/PPCLE/PPC64LE/')

CFLAGS += -DSEITAN_AUDIT_ARCH=AUDIT_ARCH_$(AUDIT_ARCH)
CFLAGS += -DTMP_DATA_SIZE=1000
CFLAGS += -Wall -Wextra -pedantic

export CFLAGS

all: seitan-eater seitan

build: build.c filter.c filter.h numbers.h
	$(CC) $(CFLAGS) -o build filter.c build.c

bpf_dbg: disasm.c disasm.h bpf_dbg.c
	$(CC) $(CFLAGS) -o bpf_dbg bpf_dbg.c disasm.c

seitan-eater: eater.c common.h common.c
	$(CC) $(CFLAGS) -o seitan-eater eater.c common.c

seitan: seitan.c transform.h common.h common.c
	$(CC) $(CFLAGS) -o seitan seitan.c common.c

numbers.h:
	./nr_syscalls.sh

test-unit:
	$(MAKE) -C tests/unit

build-test-images: build seitan seitan-eater
	$(MAKE) -C tests-utils
	./build test.bpf
	sudo podman build -t test-seitan -f containerfiles/tests/seitan/Containerfile .
	sudo podman build -t test-eater -f containerfiles/tests/eater/Containerfile .

test-integration:
	python -m pytest tests/integration/seitan_containers.py

transform.h: qemu_filter
	./transform.sh qemu_filter

clean:
	rm -f filter.h numbers.h transform.h bpf.out build seitan-eater seitan
