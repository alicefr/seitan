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

script() {
        IFS='
'
        for line in $(eval printf '%s\\\n' \$SCRIPT_${1}); do
                unset IFS
                case ${line} in
                "@")    tmux send-keys -t $SESSION C-m  ;;
                "#"*)   sleep ${#line}                  ;;
                *)      cmd_write "${line}"             ;;
                esac
                IFS='
'
        done
        unset IFS
}

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

get_first_pane() {
	pane=$(tmux list-panes | awk 'NR==1{ print $1 }' | sed 's/://')
	echo $pane
}

teardown_common() {
        sleep 5
        tmux kill-session -t $SESSION
        sleep 5
}
