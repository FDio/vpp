.. _pythonvpp:

=================
Python API Client
=================

This describes how to write a Python3 API client connecting to VPP's binary API.

1. Build and install vpp-papi packet:
   ::

      python3 -m venv /opt/test/venv
      source /opt/test/venv/bin/activate
      cd src/vpp-api/python
      python3 setup.py install

2. Check vpp-papi packet:
   ::

      (venv) root@alexan-PowerEdge-R740:/opt/api/python# pip list
      Package    Version
      ---------- -------
      pip        22.0.2
      setuptools 59.6.0
      vpp-papi   2.3.0

      (venv) root@alexan-PowerEdge-R740:/opt/api/python# python3
      Python 3.10.12 (main, Nov  6 2024, 20:22:13) [GCC 11.4.0] on linux
      Type "help", "copyright", "credits" or "license" for more information.
      >>> import vpp_papi
      >>>


3. This example will show API three based use cases:

   + Request/Reply
     - API: show_version

   + Dump/Details
     - API: sw_interface_dump

   + Want/Want_events
     - API: want_interface_events

4. run api_example.py
   ::

        python3 ./api_example/api_example.py -h
        usage: api_example.py [-h] [--core-json-dir CORE_JSON_DIR] [--plugins-json-dir PLUGINS_JSON_DIR]

        VPP API Client Script

        options:
          -h, --help            show this help message and exit
          --core-json-dir CORE_JSON_DIR
                        Path to VPP core JSON directory (default: /opt/vpp/build-root/install-vpp_debug-native/vpp/share/vpp/api/core)
          --plugins-json-dir PLUGINS_JSON_DIR
                        Path to VPP plugins JSON directory (default: /opt/vpp/build-root/install-vpp_debug-native/vpp/share/vpp/api/plugins)

5. details

        more details function call, please refer to vpp api code and vpp_papi source code.
