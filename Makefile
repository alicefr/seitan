# SPDX-License-Identifier: GPL-3.0-or-later
#
# seitan - Syscall Expressive Interpreter, Transformer and Notifier
#
# Copyright 2023 Red Hat GmbH
# Authors: Alice Frosi <afrosi@redhat.com>, Stefano Brivio <sbrivio@redhat.com>

DIR := $(shell pwd)
OUTDIR ?= $(DIR)/

export OUTDIR

all: cooker eater seitan

cooker:
	$(MAKE) -C src/cooker

eater:
	$(MAKE) -C src/eater

seitan:
	$(MAKE) -C src/seitan

debug:
	$(MAKE) -C src/debug

clean:
	$(MAKE) -C src/cooker clean
	$(MAKE) -C src/seitan clean
	$(MAKE) -C src/eater clean
	$(MAKE) -C src/debug clean

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
