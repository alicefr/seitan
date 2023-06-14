#!/bin/sh -ef
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# web/demo_connect.sh: Prepare asciinema(1) demo for connect example
#
# Copyright (c) 2023 Red Hat GmbH
# Author: Stefano Brivio <sbrivio@redhat.com>
#         Alice Frosi <afrosi@redhat.com>

SESSION=demo
VIDEO=seitan-connect

source web/common.sh

split_panes() {
	tmux split-window -h
	tmux send-keys -t $SESSION 'PS1="$ " && clear' ENTER
	tmux split-window -v
	tmux send-keys -t $SESSION 'PS1="$ " && clear' ENTER
}

SCRIPT_cooker='
cat demo/connect.hjson
###
clear
./seitan-cooker demo/connect.hjson demo/connect.gluten demo/connect.bpf
###
clear
'

SCRIPT_socat='
#
echo abcd > abcd
socat UNIX-LISTEN:/tmp/demo.sock -
#
'

SCRIPT_eater_connect='
#
./seitan-eater -i demo/connect.bpf -- socat OPEN:abcd UNIX-CONNECT:/cool.sock
#
'

SCRIPT_eater_connect_error='
#
./seitan-eater -i demo/connect.bpf -- socat OPEN:abcd UNIX-CONNECT:/error.sock
#
'

SCRIPT_seitan='
#
./seitan -p $(pgrep seitan-eater) -i demo/connect.gluten
'

printf '\e[8;22;80t'

setup_common

tmux send-keys -t $SESSION -l 'reset'
tmux send-keys -t $SESSION C-m
tmux rename-window -t $SESSION 'Seitan demo: generate input files'

asciinema rec --overwrite ${VIDEO}.cast -c 'tmux attach -t $SESSION' &
sleep 1
#tmux refresh-client

PSEITAN=$(get_first_pane)
PEATER=$((PSEITAN+1))
PSERVER=$((PEATER+1))

# Input generation
tmux select-pane -t $PSEITAN
script cooker

# First part
split_panes

tmux select-pane -t $PSERVER
tmux rename-window -t $SESSION 'Seitan demo: connect to another path'
script socat

tmux select-pane -t $PEATER
script eater_connect
tmux select-pane -t $PSEITAN
script seitan
sleep 4

# Use only 2 panes
clear_panes
tmux kill-pane -t $PSERVER

# Second part
tmux rename-window -t $SESSION 'Seitan demo: error injection (EPERM)'
tmux select-pane -t $PEATER
script eater_connect_error
tmux select-pane -t $PSEITAN
script seitan

teardown_common
gzip -fk9 ${VIDEO}.cast
