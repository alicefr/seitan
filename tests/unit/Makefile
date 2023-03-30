# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright 2023 Red Hat GmbH
# Author: Alice Frosi <afrosi@redhat.com>

COMMON_DIR := ../../common
OP_DIR := ../../
COOKER_DIR := ../../cooker
DBG_DIR := ../../debug

SRCS_FILTER := $(COOKER_DIR)/filter.c $(DBG_DIR)/disasm.c $(COMMON_DIR)/common.c
HEADERS_FILTER := $(COOKER_DIR)/filter.h $(DBG_DIR)/disasm.h $(COMMON_DIR)/common.h

HEADERS_OP_CALL := $(COMMON_DIR)/gluten.h  $(OP_DIR)/operations.h
SRCS_OP_CALL := $(OP_DIR)/operations.c

HEADERS_OP := $(COMMON_DIR)/gluten.h  $(OP_DIR)/operations.h \
		   $(COMMON_DIR)/common.h testutil.h
SRCS_OP := $(COMMON_DIR)/common.c $(OP_DIR)/operations.c util.c

TARGET := $(shell $(CC) -dumpmachine)
TARGET_ARCH := $(shell echo $(TARGET) | cut -f1 -d- | tr [A-Z] [a-z])
TARGET_ARCH := $(shell echo $(TARGET_ARCH) | sed 's/powerpc/ppc/')

AUDIT_ARCH := $(shell echo $(TARGET_ARCH) | tr [a-z] [A-Z] | sed 's/^ARM.*/ARM/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/I[456]86/I386/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/PPC64/PPC/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/PPCLE/PPC64LE/')

CFLAGS += -Wall -Wextra -pedantic
CFLAGS += -I$(COMMON_DIR) -I$(OP_DIR) -I$(COOKER_DIR) -I$(DBG_DIR)
CFLAGS += -lcheck
CFLAGS += -DSEITAN_AUDIT_ARCH=AUDIT_ARCH_$(AUDIT_ARCH) -DTMP_DATA_SIZE=1000

test: test-filter test-operations test-op-call

test-filter-build: test_filter_build.c $(SRCS_FILTER) $(HEADERS_FILTER)
	$(CC) $(CFLAGS) -o test-filter-build $(SRCS_FILTER) \
		test_filter_build.c
		./test-filter-build

test-op-call: test_op_call.c $(SRCS_OP_CALL) $(HEADERS_OP_CALL)
	$(CC) $(CFLAGS) -o test-op-call $(SRCS_OP_CALL) \
		test_op_call.c
		./test-op-call

test-operations: test_operations.c $(SRCS_OP) $(HEADERS_OP)
	$(CC) $(CFLAGS) -o test-operations $(SRCS_OP) \
		test_operations.c
	./test-operations
