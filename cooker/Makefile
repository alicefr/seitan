# SPDX-License-Identifier: GPL-3.0-or-later
#
# seitan - Syscall Expressive Interpreter, Transformer and Notifier
#
# cooker/Makefile - Makefile for seitan-cooker
#
# Copyright 2023 Red Hat GmbH
# Author: Stefano Brivio <sbrivio@redhat.com>

COMMON_DIR := ../common
SRCS := calls.c emit.c gluten.c main.c parse.c parson.c $(COMMON_DIR)/util.c calls/net.c
HEADERS := calls.h cooker.h emit.h gluten.h parse.h parson.h calls/net.h $(COMMON_DIR)/util.h
BIN := $(OUTDIR)seitan-cooker

cooker: $(SRCS) $(HEADERS)
	$(CC) -O0 -g -Wall -Wextra -pedantic -std=c99 -I$(COMMON_DIR) -o $(BIN) $(SRCS)

all: cooker

clean:
	rm -f cooker
