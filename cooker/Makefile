# SPDX-License-Identifier: GPL-2.0-or-later
#
# seitan - Syscall Expressive Interpreter, Transformer and Notifier
#
# cooker/Makefile - Makefile for seitan-cooker
#
# Copyright 2023 Red Hat GmbH
# Authors: Alice Frosi <afrosi@redhat.com>
#	   Stefano Brivio <sbrivio@redhat.com>

OUTDIR	?= ..
COMMON	:= ../common
BIN	:= $(OUTDIR)/seitan-cooker
CFLAGS	:= -O0 -g -Wall -Wextra -pedantic -std=c99 -I$(COMMON)

TARGET ?= $(shell $(CC) -dumpmachine)
# Get 'uname -m'-like architecture description for target
TARGET_ARCH := $(shell echo $(TARGET) | cut -f1 -d- | tr [A-Z] [a-z])
TARGET_ARCH := $(shell echo $(TARGET_ARCH) | sed 's/powerpc/ppc/')

AUDIT_ARCH := $(shell echo $(TARGET_ARCH) | tr [a-z] [A-Z] | sed 's/^ARM.*/ARM/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/I[456]86/I386/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/PPC64/PPC/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/PPCLE/PPC64LE/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/MIPS64EL/MIPSEL64/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/HPPA/PARISC/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/SH4/SH/')

CFLAGS += -DSEITAN_AUDIT_ARCH=AUDIT_ARCH_$(AUDIT_ARCH)


SRCS := call.c calls.c emit.c gluten.c filter.c main.c match.c		\
	parse.c parson.c						\
        $(COMMON)/util.c						\
        calls/net.c calls/ioctl.c calls/process.c calls/fs.c
HEADERS := call.h calls.h cooker.h emit.h filter.h gluten.h match.h	\
        parse.h parson.h						\
        $(COMMON)/gluten.h $(COMMON)/util.h				\
        calls/net.h calls/ioctl.h calls/process.h calls/fs.h

$(BIN): $(SRCS) $(HEADERS)
	$(CC) $(CFLAGS) -o $(BIN) $(SRCS)

all: $(BIN)

clean:
	rm -f $(BIN)
