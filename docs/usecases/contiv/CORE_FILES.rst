Capturing VPP core dumps
========================

In order to debug a crash of VPP, it is required to provide a coredump
file, which allows backtracing of the VPP issue. The following items are
the requirements for capturing a coredump:

1. Disable k8s Probes to Prevent k8s from Restarting the POD with a Crashed VPP
-------------------------------------------------------------------------------

As described in
`BUG_REPORTS.md <BUG_REPORTS.html#collecting-the-logs-in-case-of-crash-loop>`__.

2. Modify VPP Startup config file
---------------------------------

In ``/etc/vpp/contiv-vswitch.conf``, add the following lines into the
``unix`` section:

::

   unix {
       ...
       coredump-size unlimited
       full-coredump
   }

3. Turn on Coredumps in the Vswitch Container
---------------------------------------------

After re-deploying Contiv-VPP networking, enter bash shell in the
vswitch container (use actual name of the vswitch POD -
``contiv-vswitch-7whk7`` in this case):

::

   kubectl exec -it contiv-vswitch-7whk7 -n kube-system -c contiv-vswitch bash

Enable coredumps:

::

   mkdir -p /tmp/dumps
   sysctl -w debug.exception-trace=1
   sysctl -w kernel.core_pattern="/tmp/dumps/%e-%t"
   ulimit -c unlimited
   echo 2 > /proc/sys/fs/suid_dumpable

4. Let VPP Crash
----------------

Now repeat the steps that lead to the VPP crash. You can also force VPP
to crash at the point where it is running (e.g., if it is stuck) by
using the SIGQUIT signal:

::

   kill -3 `pidof vpp`

5. Locate and Inspect the Core File
-----------------------------------

The core file should appear in ``/tmp/dumps`` in the container:

::

   cd /tmp/dumps
   ls
   vpp_main-1524124440

You can try to backtrace, after installing gdb:

::

   apt-get update && apt-get install gdb
   gdb vpp vpp_main-1524124440
   (gdb) bt

6. Copy the Core File Out of the Container
------------------------------------------

Finally, copy the core file out of the container. First, while still
inside the container, pack the core file into an archive:

::

   cd /tmp/dumps
   tar cvzf vppdump.tar.gz vpp_main-1524124440

Now, on the host, determine the docker ID of the container, and then
copy the file out of the host:

::

   docker ps | grep vswitch_contiv
   d7aceb2e4876        c43a70ac3d01                                             "/usr/bin/supervisor…"   25 minutes ago      Up 25 minutes                           k8s_contiv-vswitch_contiv-vswitch-zqzn6_kube-system_9923952f-43a6-11e8-be84-080027de08ea_0

   docker cp d7aceb2e4876:/tmp/dumps/vppdump.tar.gz .

Now you are ready to file a bug on `GitHub <https://github.com/fdio/vpp/issues>`__
and attach the core file.
