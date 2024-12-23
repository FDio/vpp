.. _pythonvpp:

=================
Python API Client
=================

This describes how to write a Python3 API client connecting to VPP's binary API.

The VPP Python API client is located in the vpp-api/python directory of the VPP source tree.
It can also be installed from the Python package index.

Assuming that the vpp source code is located in ~/vpp.

0. Install vpp_papi from the Python package index:
   ::

      pip install vpp_papi

1. Build and install vpp-papi packet:
   ::

      python3 -m venv .venv
      source .venv/bin/activate
      cd ~/vpp/src/vpp-api/python
      python3 setup.py install

2. Check vpp-papi packet:
   ::

      (venv) $ pip list
      Package    Version
      ---------- -------
      pip        22.0.2
      setuptools 59.6.0
      vpp-papi   2.3.0

      (venv) $ python3
      Python 3.10.12 (main, Nov  6 2024, 20:22:13) [GCC 11.4.0] on linux
      Type "help", "copyright", "credits" or "license" for more information.
      >>> import vpp_papi
      >>>


3. This example will show API three based use cases:

   + Request/Reply

     - API: show_version

   + Dump/Details

     - API: sw_interface_dump

   + Events

     - API: want_interface_events

4. run api_example.py
   ::

        python3 ~/vpp/docs/interfacing/python/api_example/api_example.py

5. details

        more details function call, please refer to vpp api code and vpp_papi source code.

