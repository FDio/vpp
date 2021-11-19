.. _sec_lab_vpp_intro:

Lab: Taking the VPP Container Testbench for a Spin
==================================================

Assuming the reader has already acquired the test bench build scripts, let's
start with building it.

.. code-block:: shell
   :linenos:

   vagrant@ubuntu-focal$> make
   # Client image.
   DOCKER_BUILDKIT=1 docker build \
                   --file Dockerfile.vpp_testbench \
                   --build-arg HEALTHCHECK_PORT=8123 \
                   --tag vpp-testbench-client:local \
                   --target client_img \
                   .
   ...
   ...
   ...
   DOCKER_BUILDKIT=1 docker build \
                   --file Dockerfile.vpp_testbench \
                   --build-arg HEALTHCHECK_PORT=8123 \
                   --tag vpp-testbench-server:local \
                   --target server_img \
                   .
   ...
   ...
   ...
    => exporting to image
    => => exporting layers
    => => writing image
    => => naming to docker.io/library/vpp-testbench-server:local
   0.0s
   Done.


Now, let's start up our newly built images as a pair of containers. The various
hashes throughout this document will differ from those shown in your own
console (perfectly fine). First, let's assume there are no running containers
on your system. We'll verify via ``docker ps``:


.. code-block:: shell
   :linenos:

   vagrant@ubuntu-focal$> docker ps
   CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES


OK: good initial conditions. Now, let's launch the containers:

.. code-block:: shell
   :linenos:

   vagrant@ubuntu-focal$> make start
   # Create Docker bridge network.
   bash -c " . vpp_testbench_helpers.sh; host_only_create_docker_networks; "
   6e071e533e239380b2fe92d6e0844c42736ec186226fbb20d89706f9a80f935f
   # Launch the containers.
   bash -c " . vpp_testbench_helpers.sh; host_only_run_testbench_client_container
   vpp-testbench-client:local; host_only_run_testbench_server_container
   vpp-testbench-server:local; "
   720fed0a94fd715694d73a41317f05a3f36860a6d5ae54db2d7cb7f2dcaf7924
   ccf166993d09e399f7b10d372c47cc9e72ce6092ef70ea206c699263da844e1b
   # Entrypoint scripts will bring up the various links.
   # Use "docker ps" to check status of containers, see if their health
   # probes are working as expected (i.e. "health"), etc.


Now, we can use ``docker ps`` to verify if the containers are up and running:

.. code-block:: shell
   :linenos:

   vagrant@ubuntu-focal$> docker ps
   CONTAINER ID   IMAGE                        COMMAND            CREATED STATUS                                  PORTS     NAMES
   7d8e3ab35111   vpp-testbench-server:local   "/entrypoint.sh"   3 seconds ago Up 2 seconds (health: starting)             vpp-testbench-server
   cc01e64b12da   vpp-testbench-client:local   "/entrypoint.sh"   4 seconds ago Up 3 seconds (health: starting)             vpp-testbench-client


Looking good so far. However, note the "health" status of the containers.
They're not yet ready. We can re-execute the ``docker ps`` command occasionally
until the containers are ready:

.. code-block:: shell
   :linenos:

   vagrant@ubuntu-focal$>  while true; do docker ps; sleep 1; done
   CONTAINER ID   IMAGE                        COMMAND            CREATED         STATUS                                     PORTS     NAMES
   42e9bcea7c58   vpp-testbench-server:local   "/entrypoint.sh"   1 second ago    Up Less than a second (health: starting)             vpp-testbench-server
   710287b40bd3   vpp-testbench-client:local   "/entrypoint.sh"   2 seconds ago   Up Less than a second (health: starting)             vpp-testbench-client
   42e9bcea7c58   vpp-testbench-server:local   "/entrypoint.sh"   30 seconds ago   Up 29 seconds (health: starting)             vpp-testbench-server
   710287b40bd3   vpp-testbench-client:local   "/entrypoint.sh"   31 seconds ago   Up 30 seconds (healthy)                      vpp-testbench-client
   CONTAINER ID   IMAGE                        COMMAND            CREATED          STATUS                    PORTS     NAMES
   42e9bcea7c58   vpp-testbench-server:local   "/entrypoint.sh"   31 seconds ago   Up 30 seconds (healthy)             vpp-testbench-server
   710287b40bd3   vpp-testbench-client:local   "/entrypoint.sh"   32 seconds ago   Up 31 seconds (healthy)             vpp-testbench-client


Not the most elegant approach, but it works. Onward.

.. note::

   How would one automate this step so that we're not having to manually watch
   the console until the containers are ready? What's something that we could
   put into a script our our ``Makefile`` to poll the containers until they're
   ready to use?

   .. raw:: html

      <details>
      <summary><a>Spoiler</a></summary>

   .. code-block:: shell

      # "Direct" approach.
      while true; do
          [ '"healthy"' = docker inspect --format "{{json .State.Health.Status }}" vpp-testbench-client] && break
      done

      # Could also use awk/grep/etc. against the output of "docker ps".

   .. raw:: html

      </details>

Now that our containers are up and running, let's drop a shell into the
"client" container:

.. code-block:: shell
   :linenos:

   vagrant@ubuntu-focal$> make shell_client

First, let's take a look at the default network configuration.

.. code-block:: shell
   :linenos:

   root@478ab126035e:/work# ip a
   1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
       link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
       inet 127.0.0.1/8 scope host lo
          valid_lft forever preferred_lft forever
   2: vxlan-vid-42: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UNKNOWN group default qlen 1000
       link/ether 3a:2c:19:cb:ca:35 brd ff:ff:ff:ff:ff:ff
       inet 169.254.10.1/24 scope global vxlan-vid-42
          valid_lft forever preferred_lft forever
   3: vpp-tap-0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UNKNOWN group default qlen 1000
       link/ether 02:fe:c5:52:63:12 brd ff:ff:ff:ff:ff:ff
       inet 169.254.12.1/24 scope global vpp-tap-0
          valid_lft forever preferred_lft forever
   635: eth0@if636: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
       link/ether 02:42:a9:fe:00:01 brd ff:ff:ff:ff:ff:ff link-netnsid 0
       inet 169.254.0.1/24 brd 169.254.0.255 scope global eth0
          valid_lft forever preferred_lft forever

Let's also enumerate the interfaces managed by VPP. For the help of the reader,
there is a shell function, ``vc``, which just launches ``vppctl`` with some
helpful default arguments.

.. code-block:: shell
   :linenos:

   root@478ab126035e:/work# type vc
   vc is a function
   vc ()
   {
       vppctl -s "${VPP_SOCK}" "${@}"
   }
   root@478ab126035e:/work# vc
       _______    _        _   _____  ___
    __/ __/ _ \  (_)__    | | / / _ \/ _ \
    _/ _// // / / / _ \   | |/ / ___/ ___/
    /_/ /____(_)_/\___/   |___/_/  /_/

   vpp# show int
                 Name               Idx    State  MTU (L3/IP4/IP6/MPLS)     Counter          Count
   local0                            0     down          0/0/0/0
   memif0/0                          1      up          9000/0/0/0     rx packets                     7
                                                                       rx bytes                     521
                                                                       tx packets                     7
                                                                       tx bytes                     503
   tap0                              2      up          9000/0/0/0     rx packets                     7
                                                                       rx bytes                     503
                                                                       tx packets                     7
                                                                       tx bytes                     521
   vpp#


.. note::

   One more exercise for the reader:
   1. From the client container, how would you ping the server container on the
   Linux-managed VXLAN interface?
   2. From the client container, how would you ping the server container on the
   VPP-managed TAP interface?
   3. A couple trivial web servers (using ``netcat``) are running on the server
   container. Besides looking at the ``Makefile`` recipes, how could one
   determine what ports and interfaces these servers are bound to, and
   how would one issue an HTTP GET query against them from the client
   container? (hint: you're allowed to log-in to the server container via
   ``make shell_server``, and the ``netstat`` command may be of use).

   .. raw:: html

      <details>
      <summary><a>Spoiler</a></summary>

   .. code-block:: shell

      1. ping 169.254.10.2
      2. ping 169.254.12.2
      3. make shell_server
           netstat -tulpn
             tcp        0      0 169.254.12.2:8000       0.0.0.0:*
             LISTEN      47/nc         
             tcp        0      0 169.254.10.2:8000       0.0.0.0:*
             LISTEN      34/nc 
           exit
         make shell_client
           root@478ab126035e:/work# curl 169.254.10.2:8000
             HOST:14f0df855445
             DATE:Fri Nov 19 16:36:57 UTC 2021
             Hello from the Linux interface.
           root@478ab126035e:/work# curl 169.254.12.2:8000
             HOST:14f0df855445
             DATE:Fri Nov 19 16:37:04 UTC 2021
             Hello from the VPP interface.
           exit

   .. raw:: html

      </details>

Now that we've done some quick exercises, let's clean-up the containers and
their associated resources.


.. code-block:: shell
   :linenos:

   vagrant@ubuntu-focal$> make stop
   # Terminate the containers.
   bash -c " . vpp_testbench_helpers.sh; host_only_kill_testbench_client_container vpp-testbench-client:local; host_only_kill_testbench_server_container vpp-testbench-server:local; "
   vpp-testbench-client
   Error: No such container: vpp-testbench-client
   vpp-testbench-server
   Error: No such container: vpp-testbench-server
   # Cleanup Docker bridge network.
   bash -c " . vpp_testbench_helpers.sh; host_only_destroy_docker_networks; "
   vpp-testbench-net

That's it for this section.

