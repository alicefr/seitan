#!/bin/sh -ef


SESSION=dmknod
VIDEO=seitan-mknod
source web/common.sh

split_panes() {
	tmux split-window -h
	tmux send-keys -t $SESSION 'PS1="$ " && clear' ENTER
}

SCRIPT_podman_no_seitan='
sudo podman run -ti \
	--runtime /usr/bin/crun -u 1000 \
	--rm --cap-drop ALL \
	quay.io/fedora/fedora \
	mknod /dev/lol c 1 7
##
'

SCRIPT_cooker='
clear
cat demo/mknod.hjson
###
clear
./seitan-cooker demo/mknod.hjson demo/mknod.gluten demo/mknod.bpf
###
clear
'

SCRIPT_seitan='
sudo ./seitan -s /tmp/seitan.sock -i demo/mknod.gluten
##
'

SCRIPT_podman_seitan="
sudo podman run -ti --runtime /usr/bin/crun -u 1000 --rm  --cap-drop ALL \\
        --annotation run.oci.seccomp_bpf_data=\"$(base64 -w0 demo/mknod.bpf)\" \
        --annotation run.oci.seccomp.receiver=/tmp/seitan.sock \\
	quay.io/fedora/fedora \\
	sh -c 'mknod /dev/lol c 1 7 && ls /dev/lol'
##
"

# Pre-pull image before starting the recording
sudo podman pull quay.io/fedora/fedora

setup_common

tmux send-keys -t $SESSION -l 'reset'
tmux send-keys -t $SESSION C-m
tmux rename-window -t $SESSION 'Seitan demo: run mknod in container'
sleep 10

PSEITAN=$(get_first_pane)
PPODMAN=$((PSEITAN+1))

asciinema rec --overwrite ${VIDEO}.cast -c 'tmux attach -t $SESSION' &
tmux refresh-client

script podman_no_seitan
script cooker

# Start seitan and podman
split_panes
tmux select-pane -t $PSEITAN
script seitan
tmux select-pane -t $PPODMAN
script podman_seitan

teardown_common
gzip -fk9 ${VIDEO}.cast
