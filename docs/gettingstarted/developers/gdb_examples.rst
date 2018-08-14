.. _gdb_examples:

.. toctree::

GDB Examples
===============

In this section we have a few useful gdb commands.

Starting GDB
----------------------------

Once at the gdb prompt, VPP can be started by isuuing the following commands:

.. code-block:: console

   (gdb) run -c /etc/vpp/startup.conf
   Starting program: /scratch/vpp-master/build-root/install-vpp_debug-native/vpp/bin/vpp -c /etc/vpp/startup.conf
    [Thread debugging using libthread_db enabled]
    Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
    vlib_plugin_early_init:361: plugin path /scratch/vpp-master/build-root/install-vpp_debug-native/vpp/lib/vpp_plugins:/scratch/vpp-master/build-root/install-vpp_debug-native/vpp/lib64/vpp_plugins
    ....

Backtrace
----------------------------

If you encounter issues when running VPP, such as VPP terminating due to a segfault
or abort signal, then you can run the VPP debug binary and then execute **backtrace** or **bt**.

.. code-block:: console

    (gdb) bt
    #0  ip4_icmp_input (vm=0x7ffff7b89a40 <vlib_global_main>, node=0x7fffb6bb6900, frame=0x7fffb6725ac0) at /scratch/vpp-master/build-data/../src/vnet/ip/icmp4.c:187
    #1  0x00007ffff78da4be in dispatch_node (vm=0x7ffff7b89a40 <vlib_global_main>, node=0x7fffb6bb    6900, type=VLIB_NODE_TYPE_INTERNAL, dispatch_state=VLIB_NODE_STATE_POLLING, frame=0x7fffb6725ac0, last_time_stamp=10581236529    65565) at /scratch/vpp-master/build-data/../src/vlib/main.c:988
    #2  0x00007ffff78daa77 in dispatch_pending_node (vm=0x7ffff7b89a40 <vlib_global_main>, pending_f    rame_index=6, last_time_stamp=1058123652965565) at /scratch/vpp-master/build-data/../src/vlib/main.c:1138
    ....

Get to the GDB prompt
---------------------------------------

When VPP is running, you can get to the command prompt by entering CTRL-c.

Breakpoints
---------------------------------------

When at the GDB prompt, set a breakpoint by using the commands below:

.. code-block:: console

    (gdb) break ip4_icmp_input
    Breakpoint 4 at 0x7ffff6b9c00b: file /scratch/vpp-master/build-data/../src/vnet/ip/icmp4.c, line 142.

List the breakpoints already set:

.. code-block:: console

    (gdb) i b
    Num     Type           Disp Enb Address            What
    1       breakpoint     keep y   0x00007ffff6b9c00b in ip4_icmp_input at /scratch/vpp-master/build-data/../src/vnet/ip/icmp4.c:142
        breakpoint already hit 3 times
    2       breakpoint     keep y   0x00007ffff6b9c00b in ip4_icmp_input at /scratch/vpp-master/build-data/../src/vnet/ip/icmp4.c:142
    3       breakpoint     keep y   0x00007ffff640f646 in tw_timer_expire_timers_internal_1t_3w_1024sl_ov 
        at /scratch/vpp-master/build-data/../src/vppinfra/tw_timer_template.c:775

Delete a breakpoint:

.. code-block:: console

    (gdb) del 2
    (gdb) i b
    Num     Type           Disp Enb Address            What
    1       breakpoint     keep y   0x00007ffff6b9c00b in ip4_icmp_input at /scratch/vpp-master/build-data/../src/vnet/ip/icmp4.c:142
	breakpoint already hit 3 times
    3       breakpoint     keep y   0x00007ffff640f646 in tw_timer_expire_timers_internal_1t_3w_1024sl_ov 
        at /scratch/vpp-master/build-data/../src/vppinfra/tw_timer_template.c:775

Step/Next/List
---------------------------------------

Step through the code using (s)tep into, (n)ext, and list some lines before and after where you are with list.

.. code-block:: console

    Thread 1 "vpp_main" hit Breakpoint 1, ip4_icmp_input (vm=0x7ffff7b89a40 <vlib_global_main>, node=0x7fffb6bb6900, frame=0x7fffb6709480)
        at /scratch/jdenisco/vpp-master/build-data/../src/vnet/ip/icmp4.c:142
    142	{
    (gdb) n
    143	  icmp4_main_t *im = &icmp4_main;
    (
    (gdb) list
    202	      vlib_put_next_frame (vm, node, next, n_left_to_next);
    203	    }
    204	
    205	  return frame->n_vectors;
    206	}
    207	
    208	/* *INDENT-OFF* */
    209	VLIB_REGISTER_NODE (ip4_icmp_input_node,static) = {
    210	  .function = ip4_icmp_input,
    211	  .name = "ip4-icmp-input",

Examining Data and packets
-----------------------------------------------

To look at data and packets use e(x)amine or (p)rint.


For example in this code look at the ip packet:

.. code-block:: console

    (gdb) p/x *ip0
    $3 = {{ip_version_and_header_length = 0x45, tos = 0x0, length = 0x5400,
    fragment_id = 0x7049, flags_and_fragment_offset = 0x40, ttl = 0x40, protocol = 0x1,
    checksum = 0x2ddd, {{src_address = {data = {0xa, 0x0, 0x0, 0x2},
    data_u32 = 0x200000a, as_u8 = {0xa, 0x0, 0x0, 0x2}, as_u16 = {0xa, 0x200},
    as_u32 = 0x200000a}, dst_address = {data = {0xa, 0x0, 0x0, 0xa}, data_u32 = 0xa00000a,
    as_u8 = {0xa, 0x0, 0x0, 0xa}, as_u16 = {0xa, 0xa00},  as_u32 = 0xa00000a}},
    address_pair = {src = {data = {0xa, 0x0, 0x0, 0x2}, data_u32 = 0x200000a,
    as_u8 = {0xa, 0x0, 0x0, 0x2}, as_u16 = {0xa, 0x200},  as_u32 = 0x200000a},
    dst = {data = {0xa, 0x0, 0x0, 0xa}, data_u32 = 0xa00000a, as_u8 = {0xa, 0x0, 0x0, 0xa},
    as_u16 = {0xa, 0xa00}, as_u32 = 0xa00000a}}}}, {checksum_data_64 =
    {0x40704954000045, 0x200000a2ddd0140}, checksum_data_64_32 = {0xa00000a}},
    {checksum_data_32 = {0x54000045, 0x407049, 0x2ddd0140, 0x200000a, 0xa00000a}}}
      
Then the icmp header

.. code-block:: console

    (gdb) p/x *icmp0
    $4 = {type = 0x8, code = 0x0, checksum = 0xf148}

Then look at the actual bytes:

.. code-block:: console

    (gdb) x/50w ip0
    0x7fde9953510e:	0x54000045	0x00407049	0x2ddd0140	0x0200000a
    0x7fde9953511e:	0x0a00000a	0xf1480008	0x03000554	0x5b6b2e8a
    0x7fde9953512e:	0x00000000	0x000ca99a	0x00000000	0x13121110
    0x7fde9953513e:	0x17161514	0x1b1a1918	0x1f1e1d1c	0x23222120
