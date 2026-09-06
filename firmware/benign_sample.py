#!/usr/bin/env python3
"""M2 benign analysis fixture.

Used ONLY inside the M2 sandbox (temp dir, sample cwd). It performs three
clearly benign, observable behaviors that the sandbox reports on:

  1. touches / creates a text file in the sandbox cwd
  2. creates a sub-directory with a binary blob
  3. binds a TCP listener on 127.0.0.1 (ephemeral port) and attempts a
     connection to the local discard port (127.0.0.1:9)

It never writes outside its own working directory and never exfiltrates
anything. Intended purpose: educational verification that the sandbox
correctly observes filesystem + socket behavior.
"""

import os
import socket
import time


def main():
    cwd = os.getcwd()

    with open(os.path.join(cwd, "exfil.txt"), "w") as f:
        f.write("legitimate benign sandbox fixture\n")

    os.makedirs(os.path.join(cwd, "crafted"), exist_ok=True)
    with open(os.path.join(cwd, "crafted", "data.bin"), "wb") as f:
        f.write(bytes(range(256)) * 4)

    try:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
    except OSError:
        listener = None

    try:
        probe = socket.create_connection(("127.0.0.1", 9), timeout=0.5)
        probe.close()
    except OSError:
        pass

    # keep the listener observable for the /proc poller
    time.sleep(1.0)

    if listener is not None:
        listener.close()


if __name__ == "__main__":
    main()