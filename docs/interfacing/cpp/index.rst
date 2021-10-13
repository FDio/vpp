.. _cppvpp:

==============
C++ api client
==============

This describes how to write a C++ api client connecting to VPP's binary API.

Connecting to VPP is done with :

::

    auto err = con.connect("example_client", nullptr, 32, 32);


You can specify the path to the api socket/shared memory you want to connect to
with the second parameter (set to ``nullptr``, meaning default)

.. literalinclude:: ./api_example/api_example.cc
  :language: cpp

To build this you could use the following makefile

.. literalinclude:: ./api_example/Makefile
  :language: makefile

