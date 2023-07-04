# SPDX-License-Identifier: GPL-2.0-or-later
#
# seitan - Syscall Expressive Interpreter, Transformer and Notifier
#
# Copyright 2023 Red Hat GmbH
# Authors: Alice Frosi <afrosi@redhat.com>
#	   Stefano Brivio <sbrivio@redhat.com>

DIR := $(shell pwd)
OUTDIR ?= $(DIR)
export OUTDIR

COMMON_DIR := $(DIR)/common
BIN := $(OUTDIR)/seitan
SRCS := seitan.c $(COMMON_DIR)/common.c $(COMMON_DIR)/util.c  operations.c
HEADERS := $(COMMON_DIR)/common.h $(COMMON_DIR)/gluten.h \
	   $(COMMON_DIR)/util.h operations.h

CFLAGS += -DTMP_DATA_SIZE=1000
CFLAGS += -Wall -Wextra -pedantic -std=c99 -I$(COMMON_DIR)

all: cooker eater seitan

.PHONY: cooker
cooker:
	$(MAKE) -C cooker

.PHONY: eater
eater:
	$(MAKE) -C eater

.PHONY: seitan
seitan: $(SRCS) $(HEADERS)
	$(CC) $(CFLAGS) -o $(BIN) $(SRCS)

.PHONY: debug
debug:
	$(MAKE) -C debug

.PHONY: clean
clean:
	rm -f $(BIN)
	$(MAKE) -C cooker clean
	$(MAKE) -C eater clean
	$(MAKE) -C debug clean

numbers.h:
	./scripts/nr_syscalls.sh

test-unit:
	$(MAKE) -C tests/unit

# TODO: remove the build binary when cooker is ready
build-test-images: seitan eater
	$(MAKE) -C tests-utils
	$(MAKE) -C debug build
	./build test.bpf
	sudo podman build -t test-seitan -f containerfiles/tests/seitan/Containerfile .
	sudo podman build -t test-eater -f containerfiles/tests/eater/Containerfile .

test-integration:
	python -m pytest tests/integration/seitan_containers.py
