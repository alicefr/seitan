# SPDX-License-Identifier: GPL-3.0-or-later
#
# seitan - Syscall Expressive Interpreter, Transformer and Notifier
#
# cooker/Makefile - Makefile for seitan-cooker
#
# Copyright 2023 Red Hat GmbH
# Author: Stefano Brivio <sbrivio@redhat.com>

COMMON_DIR := ../common
SRCS := calls.c emit.c filter.c gluten.c main.c parse.c parson.c \
	$(COMMON_DIR)/util.c calls/net.c
HEADERS := calls.h cooker.h emit.h filter.h \
	   gluten.h parse.h parson.h calls/net.h \
	   $(COMMON_DIR)/util.h
BIN := $(OUTDIR)seitan-cooker

TARGET := $(shell $(CC) -dumpmachine)
TARGET_ARCH := $(shell echo $(TARGET) | cut -f1 -d- | tr [A-Z] [a-z])
TARGET_ARCH := $(shell echo $(TARGET_ARCH) | sed 's/powerpc/ppc/')

AUDIT_ARCH := $(shell echo $(TARGET_ARCH) | tr [a-z] [A-Z] | sed 's/^ARM.*/ARM/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/I[456]86/I386/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/PPC64/PPC/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/PPCLE/PPC64LE/')

CFLAGS += -DSEITAN_AUDIT_ARCH=AUDIT_ARCH_$(AUDIT_ARCH)
CFLAGS += -O0 -g -Wall -Wextra -pedantic -std=c99 -I$(COMMON_DIR)
cooker: $(SRCS) $(HEADERS)
	$(CC) $(CFLAGS) -o $(BIN) $(SRCS)

all: cooker

clean:
	rm -f cooker
