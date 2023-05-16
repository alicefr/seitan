# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright 2023 Red Hat GmbH
# Author: Alice Frosi <afrosi@redhat.com>

MAIN_DIR := ../../
COMMON_DIR := ../../common
OP_DIR := ../../
COOKER_DIR := ../../cooker
DBG_DIR := ../../debug

SRCS_FILTER_BUILD := $(COOKER_DIR)/filter.c $(DBG_DIR)/disasm.c $(COMMON_DIR)/common.c
HEADERS_FILTER_BUILD := $(COOKER_DIR)/filter.h $(DBG_DIR)/disasm.h $(COMMON_DIR)/common.h

SRCS_FILTER := $(COOKER_DIR)/filter.c $(COMMON_DIR)/common.c util.c \
	       $(DBG_DIR)/disasm.c
HEADERS_FILTER := $(COOKER_DIR)/filter.h $(COMMON_DIR)/common.h \
		  $(DBG_DIR)/disasm.h testutil.h

HEADERS_OP_CALL := testutil.h $(COMMON_DIR)/gluten.h  $(OP_DIR)/operations.h \
                   $(COMMON_DIR)/common.h $(COMMON_DIR)/util.h
SRCS_OP_CALL := $(COMMON_DIR)/common.c $(OP_DIR)/operations.c util.c $(COMMON_DIR)/util.c

HEADERS_OP := $(COMMON_DIR)/gluten.h  $(OP_DIR)/operations.h \
		   $(COMMON_DIR)/common.h testutil.h $(COMMON_DIR)/util.h
SRCS_OP := $(COMMON_DIR)/common.c $(OP_DIR)/operations.c util.c $(COMMON_DIR)/util.c

HEADERS_ERROR := $(COMMON_DIR)/gluten.h  $(OP_DIR)/operations.h \
		   $(COMMON_DIR)/common.h testutil.h $(COMMON_DIR)/util.h
SRCS_ERROR := $(COMMON_DIR)/common.c $(OP_DIR)/operations.c util.c $(COMMON_DIR)/util.c

TARGET := $(shell $(CC) -dumpmachine)
TARGET_ARCH := $(shell echo $(TARGET) | cut -f1 -d- | tr [A-Z] [a-z])
TARGET_ARCH := $(shell echo $(TARGET_ARCH) | sed 's/powerpc/ppc/')

AUDIT_ARCH := $(shell echo $(TARGET_ARCH) | tr [a-z] [A-Z] | sed 's/^ARM.*/ARM/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/I[456]86/I386/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/PPC64/PPC/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/PPCLE/PPC64LE/')

CFLAGS += -Wall -Wextra -pedantic
CFLAGS += -I$(MAIN_DIR) -I$(OP_DIR)  -I$(DBG_DIR)
CFLAGS += -lcheck
CFLAGS += -DSEITAN_AUDIT_ARCH=AUDIT_ARCH_$(AUDIT_ARCH)

test: test-filter test-operations test-op-call

build-filter-build: test_filter_build.c $(SRCS_FILTER_BUILD) $(HEADERS_FILTER_BUILD)
	$(CC) $(CFLAGS) -o filter-build $(SRCS_FILTER) \
		test_filter_build.c

test-filter-build: build-filter-build
	./filter-build

build-filter: test_filter.c $(SRCS_FILTER) $(HEADERS_FILTER)
	        $(CC) $(CFLAGS) -o filter $(SRCS_FILTER) \
                test_filter.c

test-filter: build-filter
	./filter

build-op-call: test_op_call.c $(SRCS_OP_CALL) $(HEADERS_OP_CALL)
	$(CC) $(CFLAGS) -o op-call $(SRCS_OP_CALL) \
		test_op_call.c

test-op-call: build-op-call
	./op-call

build-operations: test_operations.c $(SRCS_OP) $(HEADERS_OP)
	$(CC) $(CFLAGS) -o operations $(SRCS_OP) \
		test_operations.c

test-operations: build-operations
	./operations

build-error-checks: test_errors.c $(SRCS_ERROR) $(HEADERS_ERROR)
	$(CC) $(CFLAGS) -o error_checks $(SRCS_ERROR) \
		test_errors.c

test-error-checks: build-error-checks
	./error_checks
clean:
	rm -f operations  op-call filter filter-build
