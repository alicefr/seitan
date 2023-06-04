# SPDX-License-Identifier: GPL-2.0-or-later
#
# seitan - Syscall Expressive Interpreter, Transformer and Notifier
#
# eater/Makefile - Makefile for seitan-eater
#
# Copyright 2023 Red Hat GmbH
# Author: Alice Frosi <afrosi@redhat.com>

COMMON_DIR :=../common
COOKER_DIR := ../cooker
SRCS := $(COMMON_DIR)/common.c eater.c
HEADERS := $(COMMON_DIR)/common.h $(COOKER_DIR)/filter.h
BIN := $(OUTDIR)/seitan-eater
CFLAGS += -Wall -Wextra -pedantic -I$(COMMON_DIR) -I$(COOKER_DIR)

eater: $(SRCS) $(HEADERS)
	$(CC) $(CFLAGS) -o $(BIN) $(SRCS)

all: eater

clean:
	rm -f $(BIN)
