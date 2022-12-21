TARGET := $(shell $(CC) -dumpmachine)
# Get 'uname -m'-like architecture description for target
TARGET_ARCH := $(shell echo $(TARGET) | cut -f1 -d- | tr [A-Z] [a-z])
TARGET_ARCH := $(shell echo $(TARGET_ARCH) | sed 's/powerpc/ppc/')

AUDIT_ARCH := $(shell echo $(TARGET_ARCH) | tr [a-z] [A-Z] | sed 's/^ARM.*/ARM/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/I[456]86/I386/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/PPC64/PPC/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/PPCLE/PPC64LE/')

CFLAGS += -DBUILD_TRANSFORM_OUT=\"t.out\" -DBUILD_BPF_OUT=\"bpf.out\"
CFLAGS += -DBUILD_IN=\"qemu_filter\"
CFLAGS += -DSEITAN_AUDIT_ARCH=AUDIT_ARCH_$(AUDIT_ARCH)
CFLAGS += -DBUILD_PROFILE=qemu_filter
CFLAGS += -Wall -Wextra -pedantic

all: bpf.out t.out seitan-loader seitan

bpf.out: qemu_filter build
	./build

t.out: qemu_filter build
	./build

build: build.c filter.h numbers.h transform.h
	$(CC) $(CFLAGS) -o build build.c

seitan-loader: loader.c
	$(CC) $(CFLAGS) -o seitan-loader loader.c

seitan: seitan.c transform.h
	$(CC) $(CFLAGS) -o seitan seitan.c

filter.h: qemu_filter
	./filter.sh qemu_filter

numbers.h:
	./nr_syscalls.sh

transform.h: qemu_filter
	./transform.sh qemu_filter

clean:
	rm -f filter.h numbers.h transform.h t.out bpf.out build seitan-loader seitan
