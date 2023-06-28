#!/bin/bash
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# create_coreos_vm.sh: Create a Fedora CoreOS VM for testing with libvirt.
#   The VM can be accessed using user: coreos password: test
#
# Copyright (c) 2023 Red Hat GmbH
# Author: Alice Frosi <afrosi@redhat.com>

BUTANE_CONFIG="fcos_test.bu"
IGNITION_CONFIG=$(pwd)/"fcos_test.ign"
VM_NAME="fcos-test"
VCPUS="2"
RAM_MB="2048"
STREAM="stable"
DISK_GB="10"
IMAGE_PREFIX="fedora-coreos-"

IGNITION_DEVICE_ARG=(--qemu-commandline="-fw_cfg name=opt/com.coreos/config,file=${IGNITION_CONFIG}")
URL=https://builds.coreos.fedoraproject.org/streams/stable.json
URL_IMAGES=https://builds.coreos.fedoraproject.org/prod/streams/stable/builds/38.20230609.3.0/x86_64
LAST_RELEASE=$(curl -s $URL| jq '.architectures.x86_64[].qemu.release| select( . != null )' |tr -d "\"")
IMAGE_NAME=${IMAGE_PREFIX}${LAST_RELEASE}-qemu.x86_64.qcow2
LIBVIRT_IMAGES=$HOME/.local/share/libvirt/images
IMAGE=${LIBVIRT_IMAGES}/${IMAGE_NAME}

set -e

# Don't execute the script if VM is still exists in libvirt
if virsh --connect="qemu:///system" list --all | grep ${VM_NAME} ; then
	echo "VM ${VM_NAME} still exists"
	exit 0
fi

# Avoid to download the image if it is already present locally
if [ ! -f "${IMAGE}" ] ; then
	podman run --pull=always --rm -v ${LIBVIRT_IMAGES}:/data -w /data \
    		quay.io/coreos/coreos-installer:release \
    		download -s "${STREAM}" -p qemu -f qcow2.xz --decompress
fi

# Create ignition file from butane config
podman run --interactive --rm --security-opt label=disable \
	--volume $(pwd):/pwd --workdir /pwd quay.io/coreos/butane:release \
       --pretty --strict ${BUTANE_CONFIG=} > ${IGNITION_CONFIG}

# Setup the correct SELinux label to allow access to the config
chcon --verbose --type svirt_home_t ${IGNITION_CONFIG}

# Install the VM
# Note: if you encounter any issues with the installation with permission denied
# for the backing storage, please try to check ACL permissions with getfacl -e
# $HOME/.local and eventually fix them with setfacl -m u:qemu:rx $HOME/.local
virt-install --connect="qemu:///system" --name="${VM_NAME}" --vcpus="${VCPUS}" --memory="${RAM_MB}" \
        --os-variant="fedora-coreos-$STREAM" --import --graphics=none \
        --disk="size=${DISK_GB},backing_store=${IMAGE}" \
        --network bridge=virbr0 "${IGNITION_DEVICE_ARG[@]}"
