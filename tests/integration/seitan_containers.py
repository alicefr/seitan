#!/usr/bin/env python3

from podman import PodmanClient
from podman.domain.containers import Container
from podman import errors
from waiting import wait, TimeoutExpired
import pytest
import time

# The test requires podman root as seitan needs privileged capabilities
uri = "unix:///run/podman/podman.sock"
eater_image = "test-eater:latest"
seitan_image = "test-seitan:latest"

class ContainerConfig:
    def __init__(self, seitan, eater,
                 exit_code_seitan, exit_code_eater, error_seitan, error_eater,
                 process, proc_args = []):
        self.client = PodmanClient(base_url=uri)
        self.exit_code_seitan = exit_code_seitan
        self.exit_code_eater = exit_code_eater
        self.error_seitan = error_seitan
        self.error_eater = error_eater

        # Create eater container
        self.eater = self.client.containers.run(eater_image,
                                                name = eater,
                                                detach = True,
                                                user = "1000",
                                                tty = True,
                                                command = ["/usr/bin/seitan-eater",
                                                           "-i",
                                                           "/var/run/test-filters/test.bpf",
                                                           "--",
                                                           process] + proc_args)
        res = self.eater.inspect()
        pid = (res["State"]["Pid"])
        if not isinstance(pid, int):
            sys.exit("pid isn't an integer:", pid)

        # Create seitan container
        self.seitan = self.client.containers.run(seitan_image,
                                                 name = seitan,
                                                 detach = True,
                                                 tty = True,
                                                 remove = True,
                                                 pid_mode = "host",
                                                 network_mode= "host",
                                                 privileged = True,
                                                 command = [ "/usr/bin/seitan",
                                                            "-p", str(pid),
                                                            # TODO: replace /dev/null with input file
                                                            "-i", "/dev/null"])
    def wait_containers_creation(self):
        self.eater.wait(interval="2s")
        self.seitan.wait(interval="2s")

    def wait_container_terminate(self):
        def check_container_status(container: "Container"):
            if(container.inspect()["State"]["Status"]) == "exited":
                return True
            return False
        wait(lambda: check_container_status(self.eater), timeout_seconds=5)

    def print_logs(self):
        print("Output seitan:")
        self.seitan.logs()
        print("Output eater:")
        self.eater.logs()

    def check_results(self):
        self.wait_containers_creation()
        self.wait_container_terminate()
        self.print_logs()
        print("Got:", self.seitan.inspect() ["State"]["ExitCode"], "Expected:", self.exit_code_seitan)
        assert (self.seitan.inspect() ["State"]["ExitCode"]) == self.exit_code_seitan
        assert (self.eater.inspect()["State"]["ExitCode"]) == self.exit_code_eater
        assert (self.seitan.inspect()["State"]["Error"]) == self.error_seitan
        assert (self.eater.inspect()["State"]["Error"]) == self.error_eater

    def restart_seitan(self):
        self.seitan.restart()

    def stop_eater(self):
        self.eater.stop()

def clean_up_containers(containers = []):
    with PodmanClient(base_url=uri) as client:
        for c in containers:
            client.containers.remove(c, force = True)

@pytest.fixture()
def seitan_container(request):
    return "seitan_"+request.node.name

@pytest.fixture()
def eater_container(request):
    return "eater_"+request.node.name

@pytest.fixture(autouse=True)
def setup(seitan_container, eater_container):
    try:
        clean_up_containers([seitan_container,eater_container])
    except errors.exceptions.NotFound as e:
        print("No previous container existing")
    yield
    try:
        print("Delete ", seitan_container, eater_container)
        clean_up_containers([seitan_container,eater_container])
    except errors.exceptions.NotFound as e:
        print("Containers already be removed")


def test_simple(seitan_container, eater_container):
    test = ContainerConfig(seitan=seitan_container, eater=eater_container,
                           exit_code_seitan=0, exit_code_eater=0,
                           error_seitan="", error_eater= "",
                           process = "true")
    test.check_results()

def test_restart_seitan(seitan_container, eater_container):
    test = ContainerConfig(seitan=seitan_container, eater=eater_container,
                           exit_code_seitan=0, exit_code_eater=137,
                           error_seitan="", error_eater= "",
                           process = "sleep", proc_args = ["1000"])
    # Give seitan some time to unblock the eater
    # TODO: find a better way to detect that sleep has started
    time.sleep(10)
    test.restart_seitan()
    test.stop_eater()
    test.check_results()
