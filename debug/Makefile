# SPDX-License-Identifier: GPL-3.0-or-later
#
# seitan - Syscall Expressive Interpreter, Transformer and Notifier
#
# debug/Makefile - Makefile for debug utilities: bpf_dbg
#
# Copyright 2023 Red Hat GmbH
# Author: Alice Frosi <afrosi@redhat.com>

SRCS := bpf_dbg.c  disasm.c
HEADERS := disasm.h
BIN := $(OUTDIR)bpf_dbg
CFLAGS += -Wall -Wextra -pedantic

# TODO: remove this part together with the build binary
# when cooker is ready
TARGET := $(shell $(CC) -dumpmachine)
TARGET_ARCH := $(shell echo $(TARGET) | cut -f1 -d- | tr [A-Z] [a-z])
TARGET_ARCH := $(shell echo $(TARGET_ARCH) | sed 's/powerpc/ppc/')

AUDIT_ARCH := $(shell echo $(TARGET_ARCH) | tr [a-z] [A-Z] | sed 's/^ARM.*/ARM/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/I[456]86/I386/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/PPC64/PPC/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/PPCLE/PPC64LE/')

bpf_dbg: $(SRCS) $(HEADERS)
	$(CC) $(CFLAGS) -o $(BIN) $(SRCS)

# TODO: remove when cooker is ready
build: build.c ../cooker/filter.c ../cooker/filter.h ../common/numbers.h
	$(CC) $(CFLAGS) -I../common -I../cooker -DSEITAN_AUDIT_ARCH=AUDIT_ARCH_$(AUDIT_ARCH)\
	       	-o $(OUTDIR)build ../cooker/filter.c build.c

all: $(BIN)

clean:
	rm -f $(BIN) build
