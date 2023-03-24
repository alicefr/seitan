# SPDX-License-Identifier: GPL-3.0-or-later
#
# seitan - Syscall Expressive Interpreter, Transformer and Notifier
#
# seitan/Makefile - Makefile for seitan
#
# Copyright 2023 Red Hat GmbH
# Author: Alice Frosi <afrosi@redhat.com>
# Author: Stefano Brivio <sbrivio@redhat.com>

COMMON_DIR :=../common
SRCS := seitan.c $(COMMON_DIR)/common.c operations.c
HEADERS := $(COMMON_DIR)/common.h $(COMMON_DIR)/gluten.h operations.h
BIN := $(OUTDIR)seitan

TARGET := $(shell $(CC) -dumpmachine)
# Get 'uname -m'-like architecture description for target
TARGET_ARCH := $(shell echo $(TARGET) | cut -f1 -d- | tr [A-Z] [a-z])
TARGET_ARCH := $(shell echo $(TARGET_ARCH) | sed 's/powerpc/ppc/')

AUDIT_ARCH := $(shell echo $(TARGET_ARCH) | tr [a-z] [A-Z] | sed 's/^ARM.*/ARM/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/I[456]86/I386/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/PPC64/PPC/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/PPCLE/PPC64LE/')

CFLAGS += -DTMP_DATA_SIZE=1000
CFLAGS += -Wall -Wextra -pedantic -I$(COMMON_DIR)

seitan: $(SRCS) $(HEADERS)
	$(CC) $(CFLAGS) -o $(BIN) $(SRCS)

all: seitan

clean:
	rm -f $(BIN)
