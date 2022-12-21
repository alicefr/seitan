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

export CFLAGS

all: t.out seitan-loader seitan

build: build.c filter.c filter.h numbers.h
	$(CC) $(CFLAGS) -o build filter.c build.c

bpf_dbg: disasm.c disasm.h bpf_dbg.c
	$(CC) $(CFLAGS) -o bpf_dbg bpf_dbg.c disasm.c

seitan-loader: loader.c
	$(CC) $(CFLAGS) -o seitan-loader loader.c

seitan: seitan.c transform.h
	$(CC) $(CFLAGS) -o seitan seitan.c

numbers.h:
	./nr_syscalls.sh

test-unit:
	$(MAKE) -C tests/unit

transform.h: qemu_filter
	./transform.sh qemu_filter

clean:
	rm -f filter.h numbers.h transform.h t.out bpf.out build seitan-loader seitan
