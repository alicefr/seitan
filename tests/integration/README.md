<!---
SPDX-License-Identifier: GPL-2.0-or-later
Copyright (c) 2023 Red Hat GmbH
Author: Alice Frosi <afrosi@redhat.com>
-->

# Howto setup and run the integration tests

The integration tests require access to podman socket activation (root) as
seitan requires high privileges.

1. Enable podman:
```bash
$ sudo systemctl enable podman
$ sudo systemctl startpodman
```

2. Build the container images needed for the tests: For sake of simplicity, the
   build requires root to be ready to be used. Otherwise, you can build using
rootless, and then either pushing them to a registry or loading them into the
image storage of root podman.
```bash
$ build-test-images
```

3. Create a python virtual environment to install the python packages (this is
   needed only the first time):
```bash
$ python -m venv venv
$ ls venv/
bin  include  lib  lib64  pyvenv.cfg
```

4. Enable the virtual environment:
```bash
$ source venv/bin/activate
(venv) $
```

5. Install the required python packages:
```bash
(venv) $ pip install -r tests/integration/requirements.txt
```

6. Run the tests:
```
(venv) $ sudo -E PATH=$PATH  make test-integration
```

7. Exit from the virtual environment:
```bash
(venv) $ deactivate
```
