.. _libmemif_index:

Memif library (libmemif)
========================

Shared memory packet interface (memif) provides high performance packet
transmit and receive between user application and Vector Packet
Processing (VPP) or multiple user applications. Using libmemif, user
application can create shared memory interface in master or slave mode
and connect to VPP or another application using libmemif. Once the
connection is established, user application can receive or transmit
packets using libmemif API.

.. figure:: /_images/libmemif_architecture.png
   :alt: Architecture

.. toctree::
    :maxdepth: 2

    libmemif_doc
    buildinstructions_doc
    gettingstarted_doc
    examples_doc
