# Unix API socket EOF repro

On Linux, compile the read interposer and run the repro against a VPP build:

```sh
gcc -shared -fPIC -Wall -Wextra -Werror stale_errno_read.c -o stale_errno_read.so
python3 run_repro.py /path/to/vpp/build ./stale_errno_read.so
```

The interposer makes `read()` leave `errno` equal to `EAGAIN` when it returns
zero on the test API socket. The runner closes a client connection and checks
that VPP does not spin. It returns a nonzero status on failure.

This is an integration repro rather than a `make test` case because it needs
Linux `/proc`, `LD_PRELOAD`, and a standalone VPP process.
