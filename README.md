<!---
SPDX-License-Identifier: GPL-2.0-or-later
Copyright (c) 2023 Red Hat GmbH
Author: Stefano Brivio <sbrivio@redhat.com>
-->

<link rel="stylesheet" type="text/css" href="/static/asciinema-player.css" />
<script src="/static/asciinema-player.min.js"></script>

## *seitan* was at [DevConf.CZ 2023](https://devconfcz2023.sched.com/event/1MYkc/seitan-a-plant-based-recipe-against-syscall-anxiety)! Check out the [slides](https://seitan.rocks/static/seitan_devconf_2023.pdf) and the [recording](https://seitan.rocks/static/seitan_devconf_2023.webm)

<div style="display: grid; grid-template-columns: 60% auto;">
<div>
  <img src="/static/seitan.svg" alt="seitan diagram" width="98%">
</div>
<div style="text-align: justify">

<h2>
<i>seitan</i> is a framework to filter, transform and impersonate system calls,
enabling privilege reduction in container and virtualisation engines
</h2>

It allows you to filter and replay only the system calls you need, instead of
running things as root, or granting capabilities to processes.

<ul>
<li><pre style="display: inline">seitan-cooker</pre> builds a BPF program and a
  bytecode file (<i>gluten</i>) from a recipe with matches on system calls and
  corresponding actions</li>
<li><pre style="display: inline">seitan-eater</pre> loads the BPF program
  associated to the process context into the kernel, and runs the target
  process. Container engines such as Podman can directly load this program via
  OCI annotations instead</li>
<li><pre style="display: inline">seitan</pre> is the supervisor, getting
  notifications via <pre style="display: inline">seccomp_unotify</pre>,
  interpreting them according to <i>gluten</i>, and triggering the configured
  actions as a result</li>
</ul>

<h5>Note that this project and its documentation still have some rough edges! No versions, no packages yet.</h5>

<h4>Do you want to know more?</h4>
Watch the <a href="#demo-handle-and-impersonate-connect-of-a-target-process-in-several-ways">demos</a> below, ask your questions on the
users'
<a href="https://lists.seitan.rocks/postorius/lists/seitan-user.seitan.rocks/">list</a>,
<a href="https://matrix.to/#/#seitan:libera.chat">chat</a> with us.

<h4>Do you want to contribute?</h4>
Send patches to the development
<a href="https://lists.seitan.rocks/postorius/lists/seitan-dev.seitan.rocks/">list</a>...
<u><b>and</b></u> <a href="https://matrix.to/#/#seitan:libera.chat">chat</a> with us!

</div>
</div>

## Demo: handle and impersonate `connect()` of a target process in several ways

<div id="demo_connect" style="width: 99%;"></div>

## Demo: issue `mknod()` on behalf of a Podman container

<div id="demo_mknod" style="width: 99%;"></div>
<script>
AsciinemaPlayer.create('/static/seitan-connect.cast',
		       document.getElementById('demo_connect'),
		       { cols: 112, rows: 24, preload: true, poster: 'npt:0:2' });
AsciinemaPlayer.create('/static/seitan-mknod.cast',
		       document.getElementById('demo_mknod'),
		       { cols: 112, rows: 24, preload: true, poster: 'npt:0:2' });
</script>
