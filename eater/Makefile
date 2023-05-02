# SPDX-License-Identifier: GPL-3.0-or-later
#
# seitan - Syscall Expressive Interpreter, Transformer and Notifier
#
# eater/Makefile - Makefile for seitan-eater
#
# Copyright 2023 Red Hat GmbH
# Author: Alice Frosi <afrosi@redhat.com>

COMMON_DIR :=../common
SRCS := $(COMMON_DIR)/common.c eater.c
HEADERS := $(COMMON_DIR)/common.h
BIN := $(OUTDIR)/seitan-eater
CFLAGS += -Wall -Wextra -pedantic -I$(COMMON_DIR)

eater: $(SRCS) $(HEADERS)
	$(CC) $(CFLAGS) -o $(BIN) $(SRCS)

all: eater

clean:
	rm -f $(BIN)
