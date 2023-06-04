<!---
SPDX-License-Identifier: GPL-2.0-or-later
Copyright (c) 2023 Red Hat GmbH
Author: Stefano Brivio <sbrivio@redhat.com>
-->

<style>
.markdown-body {
  display: block;
  font-family: Roboto Mono, monospace;
  font-weight: 200;
  font-size: 13pt;
  line-height: 1.5;
}

div > ul {
  float: left;
}
</style>

<img src="/static/seitan.svg" alt="seitan diagram"
 style="object-fit: contain; width: 70%; float: left">

* **build-filter**
    * build BPF binary-search tree

* **build-table**
    * build transformation table

* **seitan-eater**
    * load BPF blob
    * attach filter
    * call blocking syscall
    * on return, start binary

* **seitan**
    * load transformation table blob
    * listen to netlink proc connector
    * look for seitan-eater, once found:
    * get seccomp notifier via pidfd_getfd()
    * listen to it, new syscall:
        * look up in transformation table
        * load args from memory
        * execute transformation, unblock, or block
        * return, optionally injecting context
