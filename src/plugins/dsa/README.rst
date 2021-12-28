Intel AVF device driver
=======================

Overview
--------

This plugins provides native device support for intel DATA STREAMING
ACCELERATOR (DSA). DSA is a high-performance data copy and transformation
accelerator that will be integrated in future intel processors.


Prerequisites
-------------

-  Driver requires idxd linux driver to be installed on the system,
   which supports DSA device.

-  Driver requires SVM feature enabled in idxd driver.

Known issues
------------

This driver is still in experimental phase, however it shows very good
performance numbers.

Usage
-----

System setup
~~~~~~~~~~~~

1. load idxd driver

::

   sudo modprobe idxd

2. Create several work queues for usage

::

   idxd_cfg.py -q 1 0
   idxd_cfg.py -q 1 2


Dsa Device Creation
~~~~~~~~~~~~~~~~~~~

Device can be dynamically created by using following CLI:

::

   create dsa 0.0


Dsa Device Deletion
~~~~~~~~~~~~~~~~~~~

Device can be deleted with following CLI:

::

   delete dsa 0.0

Dsa Device Statistics
~~~~~~~~~~~~~~~~~~~~~

Device statistics can be displayed with
``sh dsa <wq_name>`` command.
