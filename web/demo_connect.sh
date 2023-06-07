#!/bin/sh -ef
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# web/demo_connect.sh: Prepare asciinema(1) demo for connect example
#
# Copyright (c) 2023 Red Hat GmbH
# Author: Stefano Brivio <sbrivio@redhat.com>
#         Alice Frosi <afrosi@redhat.com>

SEITAN_DIR=$(pwd)
SESSION=demo
VIDEO=seitan-connect
PSEITAN=1
PEATER=2
PSERVER=3

setup_common() {
	tmux new-session -d -s $SESSION
	tmux send-keys -t $SESSION 'PS1="$ "'
	tmux send-keys -t $SESSION C-m
	tmux send-keys -t $SESSION clear
	tmux send-keys -t $SESSION C-m

	tmux set -t $SESSION window-status-format '#W'
	tmux set -t $SESSION window-status-current-format '#W'
	tmux set -t $SESSION status-left ''
	tmux set -t $SESSION window-status-separator ''

	tmux set -t $SESSION window-status-style 'bg=colour1 fg=colour15 bold'
	tmux set -t $SESSION status-right ''
	tmux set -t $SESSION status-style 'bg=colour1 fg=colour15 bold'
	tmux set -t $SESSION status-right-style 'bg=colour1 fg=colour15 bold'
	tmux send-keys -t $SESSION "cd ${SEITAN_DIR}" ENTER
	sleep 1
}

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
socat UNIX-LISTEN:/tmp/demo.sock -
#
'

SCRIPT_eater_connect='
#
./seitan-eater -i demo/connect.bpf -- socat OPEN:abcd UNIX-CONNECT:/var/run/pr-helper.sock
#
'

SCRIPT_eater_connect_fake='
#
./seitan-eater -i demo/connect.bpf -- socat - UNIX-CONNECT:/fake.sock
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

cmd_write() {
	__str="${@}"
	while [ -n "${__str}" ]; do
		__rem="${__str#?}"
		__first="${__str%"$__rem"}"
		if [ "${__first}" = ";" ]; then
			tmux send-keys -t $SESSION -l '\;'
		else
			tmux send-keys -t $SESSION -l "${__first}"
		fi
		sleep 0.05 || :
		__str="${__rem}"
	done
	sleep 2
	tmux send-keys -t $SESSION "C-m"
}

script() {
	IFS='
'
	for line in $(eval printf '%s\\\n' \$SCRIPT_${1}); do
		unset IFS
		case ${line} in
		"@")	tmux send-keys -t $SESSION C-m	;;
		"#"*)	sleep ${#line}			;;
		*)	cmd_write "${line}"		;;
		esac
		IFS='
'
	done
	unset IFS
}

wait_seitan_exit() {
	while [ "$(pgrep seitan)" != "" ] ; do sleep 1; done
}

clear_panes() {
	wait_seitan_exit
	panes=$(tmux list-panes |awk '{ print $1 }' | sed 's/://')
	for p in $panes
	do
		tmux select-pane -t $p
	        tmux send-keys -t $SESSION clear
	        tmux send-keys -t $SESSION C-m
	done
	sleep 1
}

teardown_common() {
	sleep 5
	tmux kill-session -t $SESSION
	sleep 5
}

printf '\e[8;22;80t'

setup_common

tmux send-keys -t $SESSION -l 'reset'
tmux send-keys -t $SESSION C-m
tmux rename-window -t $SESSION 'Seitan demo: generate input files'

asciinema rec --overwrite ${VIDEO}.cast -c 'tmux attach -t $SESSION' &
sleep 1
tmux refresh-client

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
tmux rename-window -t $SESSION 'Seitan demo: mock connect syscall'
tmux select-pane -t $PEATER
script eater_connect_fake
tmux select-pane -t $PSEITAN
script seitan

sleep 4
clear_panes

# Third part
tmux rename-window -t $SESSION 'Seitan demo: error injection (EPERM)'
tmux select-pane -t $PEATER
script eater_connect_error
tmux select-pane -t $PSEITAN
script seitan

teardown_common
gzip -fk9 ${VIDEO}.cast
