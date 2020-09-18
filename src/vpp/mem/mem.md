# VPP mem preload {#mempreload_doc}

Internal VPP memory allocations rely on VPP main-heap, however when using
external libraries, esp. in plugins (eg. OpenSSL library used by the IKEv2
plugin), those external libraries usually manages memory using the standard
libc `malloc()`/`free()`/... calls. This, in turn, makes use of the default
libc heap.

VPP has no knowledge of this heap and tools such as memory traces cannot be
used.

In order to enable the use of standard VPP debugging tools, this library
replaces standard libc memory management calls with version using VPP
main-heap.

To use it, you need to use the `LD_PRELOAD` mechanism, eg.
```
~# LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libvppmem_preload.so /usr/bin/vpp -c /etc/vpp/startup.conf
```

You can then use tools such as memory traces as usual.
