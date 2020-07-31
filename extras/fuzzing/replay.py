#!/usr/bin/env python3

import os
import pexpect
import sys
import time

prompt = "DBGvpp# "

def send_expect(command, delay=0.5, show=False):
    global child
    child.sendline(command)
    child.expect(prompt)
    if show:
        print(child.before.decode("ascii"))
    time.sleep(delay)

def get_trace(filename, delay=0.5, show=False):
    """Return the trace corresponding to the input in `filename`."""
    send_expect(f"pfuzz enable pg0 replay {filename}", delay, show)
    send_expect("clear trace", delay, show)
    send_expect("trace add pg-input 1", delay, show)
    send_expect("show trace", delay, show)

def main():
    global child
    if len(sys.argv) != 2:
        print(f"Usage: ./replay.py <path to directory with inputs>")
        print("a fresh instance of ./run.sh replay should be running")
        sys.exit(1)
    path = sys.argv[1]

    files = [os.path.join(path, f) for f in os.listdir(path)]
    files = [f for f in files if os.path.isfile(f)]
    files = [f for f in files if not f.endswith(".trace")]
    print("Will process the following files:")
    print("\n".join(files))
    print()

    # Initialization
    print("Initiating connection with VPP...", end="", flush=True)
    child = pexpect.spawn("telnet localhost 5002")
    child.expect(prompt)
    print("Done")
    send_expect("set terminal pager off", delay=0.1, show=False)
    for path in files:
        print(f"{path}... ", end="", flush=True)
        top = time.time()
        get_trace(path, delay=0.1, show=False)
        trace = child.before.decode("ascii")
        with open(f"{path}.trace", "w") as f:
            f.write(trace)
            t = time.time() - top
            print(f"Done in {t:.2f}s")

if __name__ == "__main__":
    main()
