# SPDX-License-Identifier: GPL-2.0-or-later
#
# seitan - Syscall Expressive Interpreter, Transformer and Notifier
#
# debug/Makefile - Makefile for debug utilities: bpf_dbg
#
# Copyright 2023 Red Hat GmbH
# Author: Alice Frosi <afrosi@redhat.com>

SRCS := bpf_dbg.c  disasm.c
HEADERS := disasm.h
BIN := $(OUTDIR)/bpf_dbg
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

all: $(BIN)

clean:
	rm -f $(BIN) build
