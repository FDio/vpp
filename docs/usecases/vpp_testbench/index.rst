VPP Container Test Bench
========================

This project spins up a pair of Docker containers, both of which are running
Ubuntu 20.04 "Focal Fossa" (x86_64) along with VPP. At run-time, the containers
will attempt to create various links between each other, using both the Linux
networking stack as well as VPP, and will then send some simple traffic
back-and-forth (i.e. ICMP echo/ping requests and HTTP GET requests).

The intent of this example is to provide a relatively simple example of
connecting containers via VPP and allowing others to use it as a springboard of
sorts for their own projects and examples. Besides Docker and a handful of
common Linux command-line utlities, not much else is required to build this
example (due to most of the dependencies being lumped inside the containers
themselves).

Instructions - Short Version
----------------------------

The use of an Ubuntu 20.04 LTS Linux distro, running on x86_64 hardware, is
required for these labs. If your current workstation/PC/laptop/etc. is
unable to run such a setup natively, the reader is now tasked with figuring out
how to get such a setup in order. This can be accomplished, for example,
through the use of virtual machines  via tools like VirtualBox, or ``vagrant``.
As this can be a time consuming task for readers new to virtual machines, we
leave it as an exercise for the reader, as it is impractical to provide support
for such a task in this narrow/focused set of labs and tutorials.

This being said, it's quite probable that one could use these labs on different
flavors/distros of Linux, since the bulk of the work involved takes place
inside containers which are always set to use an Ubuntu 20.04 baseline.
However, for the sake of these labs, any other such setup is not supported.

- Replicate the file listings at the end of this document
  (:ref:`sec_file_listings_vpp_testbench`).  You can also directly acquire a
  copy of these files by cloning the VPP repo, and navigating to the
  ``docs/usecases/vpp_testbench/src`` path to save yourself the hassle of
  copy-pasting and naming the files. Once that's done, open a shell, and
  navigate to the location housing the project files.
- To build the project, simply run: ``make``
- To start up the containers and have all the initialization logic take place,
  run: ``make start``
- To trigger some basic traffic tests, run: ``make poll``
- To terminate the containers and clean-up associated resources, run ``make stop``
- To launch an interactive shell for the "client" container, run ``make
  shell_client``
- To launch an interactive shell for the "server" container, run ``make
  shell_server``

Instructions - Long Version
---------------------------

Directory Structure and File Purposes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

First, let's quickly review the purpose of the various files used in this
project.

* ``vpp_testbench_helpers.sh``: shell variables and helper functions re-used in
  other scripts in this project. Intended to be sourced (i.e. not intended to
  be run directly). Some of the helper functions are used at run-time within
  the containers, while others are intended to be run in the default namespace
  on the host operating system to help with run-time configuration/bringup of
  the testbench.
* ``Dockerfile.vpp_testbench``: used to build the various Docker images used in
  this project (i.e. so VPP, our test tools, etc.; are all encapsulated within
  containers rather than being deployed to the host OS).
* ``Dockerfile.vpp_testbench.dockerignore``: a "permit-list" to restrict what
  files we permit to be included in our Docker images (helps keep image size
  down and provides some minor security benefits at build time, at least in
  general).
* ``entrypoint_client.sh``: entrypoint script used by the "client" Docker
  container when it is launched.
* ``entrypoint_server.sh``: entrypoint script used by the "server" Docker
  container when it is launched.
* ``Makefile``: top-level script; used to trigger the artifacts and Docker
  image builds, provides rules for starting/testing/stopping the containers,
  etc.

Getting Started
^^^^^^^^^^^^^^^

First, we'll assume you are running on a Ubuntu 20.04 x86_64 setup (either on a
bare metal host or in a virtual machine), and have acquirec a copy of the
project files (either by cloning the VPP git repository, or duplicating them
from :ref:`sec_file_listings_vpp_testbench`). Now, just run ``make``. The
process should take a few minutes as it pulls the baseline Ubuntu Docker image,
applies system/package updates/upgrades via ``apt``, and installs VPP.

Next, one can start up the containers used by the project via ``make start``.
From this point forward, most testing, experiments, etc.; will likely involve
modifying/extending the ``poll_containers`` definition inside ``Makefile``
(probably easiest to just have it invoke a shell script that you write for your
own testing). Once you've completed various test runs, the entire deployment
can be cleaned-up via ``make stop``, and the whole process of starting,
testing, stopping, etc.; can be repeated as needed.

In addition to starting up the containers, ``make start`` will establish
variaous types of links/connections between the two containers, making use of
both the Linux network stack, as well as VPP, to handle the "plumbing"
involved. This is to allow various types of connections between the two
containers, and to allow the reader to experiment with them (i.e. using
``vppctl`` to congfigure or trace packets going over VPP-managed links, use
traditional Linux command line utilities like ``tcpdump``, ``iproute2``,
``ping``, etc.; to accomplish similar tasks over links managed purely by the
Linux network stack, etc.). Later labs will also encourage readers to compare
the two types of links (perhaps some performance metrics/profiling, or similar
tasks). This testbench project is effectively intended as a baseline workspace
upon which one may design and run the labs (or your own projects and examples,
whichever works for you).

Labs
----

.. toctree::
   labs/intro_to_vpp/index

Future Labs
-----------

.. note::

   Coming soon.

- Lab: Writing your First CLI Application (Querying Statistics)
- Lab: MACSWAP Plugin Revisited

.. _sec_file_listings_vpp_testbench:

File Listings
-------------

Makefile
^^^^^^^^

.. literalinclude:: src/Makefile
   :caption: Makefile
   :language: Makefile
   :linenos:

Dockerfile.vpp_testbench
^^^^^^^^^^^^^^^^^^^^^^^^

.. literalinclude:: src/Dockerfile.vpp_testbench
   :caption: Dockerfile.vpp_testbench
   :language: Dockerfile
   :linenos:

Dockerfile.vpp_testbench.dockerignore
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. literalinclude:: src/Dockerfile.vpp_testbench.dockerignore
   :caption: Dockerfile.vpp_testbench.dockerignore
   :language: Dockerfile
   :linenos:

vpp_testbench_helpers.sh
^^^^^^^^^^^^^^^^^^^^^^^^

.. literalinclude:: src/vpp_testbench_helpers.sh
   :caption: vpp_testbench_helpers.sh
   :language: shell
   :linenos:

entrypoint_client.sh
^^^^^^^^^^^^^^^^^^^^

.. literalinclude:: src/entrypoint_client.sh
   :caption: entrypoint_client.sh
   :language: shell
   :linenos:

entrypoint_server.sh
^^^^^^^^^^^^^^^^^^^^

.. literalinclude:: src/entrypoint_server.sh
   :caption: entrypoint_server.sh
   :language: shell
   :linenos:

