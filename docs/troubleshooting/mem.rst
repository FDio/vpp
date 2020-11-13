.. _memleak:

*****************
Memory leaks
*****************

Memory traces
=============

VPP supports memory traces to help debug (suspected) memory leaks. Each
allocation/deallocation is instrumented so that the number of allocations and
current global allocated size is maintained for each unique allocation stack
trace.

Looking at a memory trace can help diagnose where memory is (over-)used, and
comparing memory traces at different point in time can help diagnose if and
where memory leaks happen.

To enable memory traces on main-heap:

.. code-block:: console

    $ vppctl memory-trace on main-heap

To dump memory traces for analysis:

.. code-block:: console

    $ vppctl show memory-trace on main-heap
    Thread 0 vpp_main
      base 0x7fffb6422000, size 1g, locked, unmap-on-destroy, name 'main heap'
	page stats: page-size 4K, total 262144, mapped 30343, not-mapped 231801
	  numa 0: 30343 pages, 118.53m bytes
	total: 1023.99M, used: 115.49M, free: 908.50M, trimmable: 908.48M
	  free chunks 451 free fastbin blks 0
	  max total allocated 1023.99M

      Bytes    Count     Sample   Traceback
     31457440        1 0x7fffbb31ad00 clib_mem_alloc_aligned_at_offset + 0x80
				      clib_mem_alloc_aligned + 0x26
				      alloc_aligned_8_8 + 0xe1
				      clib_bihash_instantiate_8_8 + 0x76
				      clib_bihash_init2_8_8 + 0x2ec
				      clib_bihash_init_8_8 + 0x6a
				      l2fib_table_init + 0x54
				      set_int_l2_mode + 0x89
				      int_l3 + 0xb4
				      vlib_cli_dispatch_sub_commands + 0xeee
				      vlib_cli_dispatch_sub_commands + 0xc62
				      vlib_cli_dispatch_sub_commands + 0xc62
       266768     5222 0x7fffbd79f978 clib_mem_alloc_aligned_at_offset + 0x80
				      vec_resize_allocate_memory + 0xa8
				      _vec_resize_inline + 0x240
				      unix_cli_file_add + 0x83d
				      unix_cli_listen_read_ready + 0x10b
				      linux_epoll_input_inline + 0x943
				      linux_epoll_input + 0x39
				      dispatch_node + 0x336
				      vlib_main_or_worker_loop + 0xbf1
				      vlib_main_loop + 0x1a
				      vlib_main + 0xae7
				      thread0 + 0x3e
    ....

libc memory traces
==================

Internal VPP memory allocations rely on VPP main-heap, however when using
external libraries, esp. in plugins (eg. OpenSSL library used by the IKEv2
plugin), those external libraries usually manages memory using the standard
libc malloc()/free()/... calls. This, in turn, makes use of the default
libc heap.

VPP has no knowledge of this heap and tools such as memory traces cannot be
used.

In order to enable the use of standard VPP debugging tools, this library
replaces standard libc memory management calls with version using VPP
main-heap.

To use it, you need to use the `LD_PRELOAD` mechanism, eg.

.. code-block:: console

    ~# LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libvppmem_preload.so /usr/bin/vpp -c /etc/vpp/startup.conf

You can then use tools such as memory traces as usual.
