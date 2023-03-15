.. _govpp:

==============
Go api (govpp)
==============

If you are writing a Go application that needs to control and manage VPP, the `GoVPP <https://github.com/FDio/govpp>`__ is a toolset providing a client library that will allow you to connect to VPP and interact with VPP binary API, Stats API and more.

Components involved
===================

The API client connecting to VPP consists of several elements :

* First, everything stems from the api definition living in the VPP repository. The message definitions live in ``*.api`` files that you will find instances of in most VPP plugins.
* The repository contains an api generator ``make json-api-files`` that converts those ``.api`` files into ``.json`` files to be consumed by language specific bindings.
* The program ingesting these ``.json`` files is called ``binapi-generator`` and lives inside `GoVPP <https://github.com/FDio/govpp>`__. It contains the logic converting them to ``.ba.go`` files with the appropriate struct definitions matching all the api messages defined in the ``.api`` files.
* `GoVPP <https://github.com/FDio/govpp>`__'s repo also contains the logic for attaching to VPP's binary API socket, and wrappers for sending and receiving messages over it.

Getting started
===============

Generating the API bindings from the VPP source
-----------------------------------------------

* First create your project directory (watch out for path as it is important for go modules) :

.. code:: bash

    mkdir -p $HOME/myproject

* Run the bindings generation at the root of the repo :

.. code:: bash

    cd <vpp_repo_dir>/vpp
    make ARGS="--output-dir=$HOME/myproject/vppbinapi --import-prefix=mygit.com/myproject/vppbinapi" go-api-files


.. note::

    The two options are similar but specify two different things. The output-dir option sets the directory where the generated bindings will be stored. The import prefix sets the go package name to be used in the generated bindings, this will be the string to be used in your ``import ( "" )`` in go. Both can or can not match depending on your ``go.mod``.


This should prompt you with the name of the directory were the generated go api bindings live. (e.g. ``Go API bindings were generated to myproject/vppbinapi``)

Generating the API bindings from the VPP package
------------------------------------------------

* You should find its corresponding ``api.json`` files present on your system, typically in ``/usr/share/vpp/api/``

.. code:: bash

    # First install the binary API generator
    #   It will be installed to $GOPATH/bin/binapi-generator
    #   or $HOME/go/bin/binapi-generator
    go install go.fd.io/govpp/cmd/binapi-generator@latest

    # Run the binapi-generator
    $GOPATH/bin/binapi-generator \
      --input=/usr/share/vpp/api/ \
      --output-dir=$HOME/myproject/vppbinapi \
      --import-prefix=mygit.com/myproject/vppbinapi

This should output the go bindings to ``$HOME/myproject/vppbinapi``

Launch VPP
==========

.. code:: bash

    mkdir -p /tmp/vpp
    cat << EOF > /tmp/startup.conf
    unix {nodaemon cli-listen /tmp/vpp/api.sock}
    plugins {
        path /vpp/build-root/install-vpp_debug-native/vpp/lib/x86_64-linux-gnu/vpp_plugins
        plugin dpdk_plugin.so { disable }
    }
    EOF

    # If VPP was built from source:
    <vpp_repo_dir>/build-root/install-vpp_debug-native/vpp/bin/vpp -c /tmp/startup.conf

    # If VPP was installed from package:
    vpp -c /tmp/startup.conf


Connecting to VPP
=================

Once you have your go bindings in ``$HOME/myproject/vppbinapi``, you can start building an agent leveraging them. A typical agent would look like this

* Back to your project directory, add govpp as a dependency

.. code:: bash

    cd "$HOME/myproject"
    go mod init mygit.com/myproject
    go get go.fd.io/govpp@latest

* Create ``main.go`` in ``$HOME/myproject`` like below :

.. code-block:: go

    package main

    import (
        "os"
        "fmt"

        "go.fd.io/govpp"
        "go.fd.io/govpp/api"

        "mygit.com/myproject/vppbinapi/af_packet"
        interfaces "mygit.com/myproject/vppbinapi/interface"
        "mygit.com/myproject/vppbinapi/interface_types"
    )

    func CreateHostInterface(ch api.Channel, ifName string) (uint32, error) {
        response := &af_packet.AfPacketCreateReply{}
        request := &af_packet.AfPacketCreate{HostIfName: ifName}
        err := ch.SendRequest(request).ReceiveReply(response)
        if err != nil {
            return 0, err
        } else if response.Retval != 0 {
            return 0, fmt.Errorf("AfPacketCreate failed: req %+v reply %+v", request, response)
        }
        return uint32(response.SwIfIndex), nil
    }

    func InterfaceAdminUp(ch api.Channel, swIfIndex uint32) error {
        request := &interfaces.SwInterfaceSetFlags{
            SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
            Flags:     interface_types.IF_STATUS_API_FLAG_ADMIN_UP,
        }
        response := &interfaces.SwInterfaceSetFlagsReply{}
        err := ch.SendRequest(request).ReceiveReply(response)
        if err != nil {
            return err
        }
        return nil
    }

    func main() {
        // Connect to VPP
        conn, err := govpp.Connect("/tmp/vpp/api.sock")
        defer conn.Disconnect()
        if err != nil {
            fmt.Printf("Could not connect: %s\n", err)
            os.Exit(1)
        }

        // Open channel
        ch, err := conn.NewAPIChannel()
        defer ch.Close()
        if err != nil {
            fmt.Printf("Could not open API channel: %s\n", err)
            os.Exit(1)
        }

        swIfIndex, err := CreateHostInterface(ch, "eth0")
        if err != nil {
            fmt.Printf("Could not create host interface: %s\n", err)
            os.Exit(1)
        }
        err = InterfaceAdminUp(ch, swIfIndex)
        if err != nil {
            fmt.Printf("Could not set interface up: %s\n", err)
            os.Exit(1)
        }

        fmt.Printf("Created host interface & set it up, id=%d\n", swIfIndex)
    }

*  Finally build and launch application. This will connect to VPP on its API socket ``/tmp/vpp/api.sock``, create an AF_PACKET interface on ``eth0`` and set it up

.. code:: bash

    cd "$HOME/myproject"
    go build
    ./myproject

