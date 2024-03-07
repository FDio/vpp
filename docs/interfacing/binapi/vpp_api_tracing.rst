How To Use The API Trace Tools
==============================

Introduction
------------

The VPP platform implements a set of binary APIs that control-plane
agents can use to configure the VPP data plane.
The VPP engine can trace, print, and replay binary API traces.
This is an extremely powerful mechanism. When the data plane fails to pass
traffic, any number of factors may be involved. Often, the data plane is
simply not configured correctly.

API trace replay is very fast. Replaying 100,000 control-plane operations
takes a fraction of a second - even though it may have taken an hour or
more to accumulate that many transactions.
There's no requirement for you to replay an API trace using the exact
binary which generated the trace.
It's often handy to add scaffolding to a debug image to work out what's
going wrong. As long as the API definitions are consistent, you can add
scaffolding, test bug fixes, and so forth.

Capturing API traces
--------------------

The usual method for capturing a binary API trace is to configure API tracing
from the command-line or in the startup.conf file:

.. code-block:: shell

    api-trace { on }

For more details of possible config options for tracing check the
configuration reference:

:ref:`configuration_reference`.

Current packaging always enables API tracing at data-plane start time. Alternatively,
the debug Command-line Interface (CLI) api trace on command can be used at any time:

.. code-block:: shell

    vpp# api trace on

You can always check the status of the api tracing from the vpp shell:

.. code-block:: shell

    vpp# api trace status

Using the API Test Tool to Create a Sample API Trace
----------------------------------------------------

Start the API test tool, located in /usr/bin/vpp_api_test.
The complete help for vpp_api_test:

.. code-block:: shell

    # vpp_api_test --help
    vpp_api_test: usage [in <f1> ... in <fn>] [out <fn>] [script] [json]
    [plugin_path <path>][default-socket][socket-name <name>]
    [plugin_name_filter <filter>][chroot prefix <path>]

vpp_api_test tries to load plugins by default from the path
/usr/lib/x86_64-linux-gnu/vpp_api_test_plugins/ on an ubuntu 22.04 installation,
you can load plugins from different path by calling the tool with plugin_path
option.
vpp_api_test by default connects to api.sock under /run/vpp/api.sock
(see `API_SOCKET_FILE <https://github.com/FDio/vpp/blob/e574736322733ec5a126ca01efb958570e5355eb/src/vlibmemory/socket_api.h#L26>`_)

The API test tool exec command sends
debug CLI commands to the data-plane, and prints the results:

.. code-block:: shell

    # vpp_api_test
    vat# exec show interface
            Name               Idx       State          Counter          Count
        host-eth0                         1      up     1500/1500/1500/1500 rx packets                 839
                                                                    rx bytes                  422610
                                                                    tx packets                     1
                                                                    tx bytes                      42
                                                                    drops                        838
                                                                    ip4                          396
                                                                    ip6                            5
        local0                            0     down          0/0/0/0

Use the help command in the API test tool to see all of the APIs that it
knows about. With a very few exceptions related to uploading statistics:

.. code-block:: shell

    vat# help
    Help is available for the following:
    acl_add_replace
    acl_add_replace_from_file
    acl_del
    acl_dump
    <snip> ## type help yourself to see the entire list...

It doesn't know about all of the data plane binary APIs, for that use the
``vat2`` tool:

.. code-block:: shell

    # vat2 sw_interface_dump '{"sw_if_index": 0, "name_filter_valid": 0, "name_filter": ""}'

``vat2`` is available also under /usr/bin/ on an Ubuntu 22.04 installation.

Create and Save a Real API Trace
--------------------------------

For the case of this example let's create a loopback interface from the
API test tool:

.. code-block:: shell

    vat# create_loopback
    vat# exec show interface
            Name               Idx       State          Counter          Count
        host-eth0                         1      up     1500/1500/1500/1500 rx packets                 839
                                                                    rx bytes                  422610
                                                                    tx packets                     1
                                                                    tx bytes                      42
                                                                    drops                        838
                                                                    ip4                          396
                                                                    ip6                            5
        local0                            0     down          0/0/0/0
        loop0                             1     down         9000/0/0/0

If you check the status of the API trace, you will see that the used number increased:

.. code-block:: shell

    vpp# api trace status
    RX trace: used 316 of 262144 items, is enabled, has not wrapped

You can check what is in the trace:

.. code-block:: shell

    vpp# api trace dump

You can save the trace to file:

.. code-block:: shell

    vpp# api trace save demo.api
    API trace saved to /tmp/demo.api

Replay the API Trace
--------------------

Before you continue stop vpp, to be sure that all the interfaces are lost.
With your saved dump file (/tmp/demo.api) you can replay all the API calls
with the api trace tool:

.. code-block:: shell

    vpp# api trace replay /tmp/demo.api

Additional Things to Know About API Tracing
-------------------------------------------

The API trace replay command takes additional arguments, including "first <NNN> and
"last <NNN>". When trying to figure out precisely which API message caused an issue,
rapid binary and/or linear searches may be performed.
