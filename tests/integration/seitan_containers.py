#!/usr/bin/env python3

from podman import PodmanClient
import unittest

# The test requires podman root as seitan needs privileged capabilities
uri = "unix:///run/podman/podman.sock"

def create_containers(syscall):
    with PodmanClient(base_url=uri) as client:
        test_image = "quay.io/seitan/test-eater:latest"
        test_cont_name = "test"
        test_container = client.containers.run(test_image,
                                               name = test_cont_name,
                                               detach = True,
                                               # TODO: fix command line
                                               command = ["/usr/bin/sleep", "100"],
                                               tty = True)
        # Create seitan container
        seitan_image = "quay.io/seitan/test-seitan:latest"
        seitan_cont_name = "seitan-test"
        seitan_container = client.containers.run(seitan_image,
                                                 name = seitan_cont_name,
                                                 detach = True,
                                                 tty = True,
                                                 network_mode= "host",
                                                 privileged = True,
                                                 pid_mode = "host")
        return test_container, seitan_container

def find_pid_of_test(container):
    with PodmanClient(base_url=uri) as client:
        res = container.inspect()
        # Right now return pid of the init process, otherwise for the childs
        # find childs pids -> /proc/10166/task/<pid>/children and the select those with the right executable
        # readlink /proc/<child-pid>/exe == test binary
        return (res["State"]["Pid"])

class TestSyscallInContainer(unittest.TestCase):
    def test_connect(self):
        test, seitan = create_containers("connect")
        self.assertEqual(test.status, "running")
        self.assertEqual(seitan.status, "running")
        find_pid_of_test(test)
        # TODO: Exec into the seitan container and pass the pid and gluten

unittest.main()
