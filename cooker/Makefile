# SPDX-License-Identifier: GPL-3.0-or-later
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

SRCS := calls.c emit.c gluten.c main.c parse.c parson.c			\
        $(COMMON)/util.c						\
        calls/net.c
HEADERS := calls.h cooker.h emit.h gluten.h parse.h parson.h		\
           $(COMMON)/gluten.h $(COMMON)/util.h				\
           calls/net.h

$(BIN): $(SRCS) $(HEADERS)
	$(CC) $(CFLAGS) -o $(BIN) $(SRCS)

all: $(BIN)

clean:
	rm -f $(BIN)
