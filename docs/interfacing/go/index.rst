.. _govpp:

==============
Go api (govpp)
==============

If you are writing a Control plane in GO that interfaces with VPP, `GoVPP <https://github.com/FDio/govpp>`__ is the library that will allow you to connect to VPP, and program it through its binary API socket.

Components involved
===================

The API client connecting to VPP consists of several elements :

* First, everything stems from the api definition living in the VPP repository. The message definitions live in ``*.api`` files that you will find instances of in most VPP plugins.
* The repository contains an api generator ``make json-api-files`` that converts those ``.api`` files into ``.json`` files to be consumed by language specific bindings.
* The program ingesting these ``.json`` files is called ``binapi-generator`` and lives inside `GoVPP <https://github.com/FDio/govpp>`__. It contains the logic converting them to ``.ba.go`` files with the appropriate struct definitions matching all the api messages defined in the ``.api`` files.
* `GoVPP <https://github.com/FDio/govpp>`__'s repo also contains the logic for attaching to VPP's binary API socket, and wrappers for sending and receiving messages over it.

Getting started
===============

Generating the API bindings
---------------------------

* If you have the VPP repository cloned on your machine, you can simply run at the root of the repo :

.. code:: bash

    make ARGS="--output-dir=myproject/vppbinapi --import-prefix=mygit.com/myproject/vppbinapi" go-api-files

This should prompt you with the name of the directory were the generated go api bindings live. (e.g. ``Go API bindings were generated to myproject/vppbinapi``)

* If you have installed VPP from a package, you should find its corresponding ``api.json`` files present on your system, typically in ``/usr/share/vpp/api/``

.. code:: bash

    # First install the binary API generator
    #   It will be installed to $GOPATH/bin/binapi-generator
    #   or $HOME/go/bin/binapi-generator
    go install git.fd.io/govpp.git/cmd/binapi-generator@latest

    # Run the binapi-generator
    $GOPATH/bin/binapi-generator \
      --input-dir=/usr/share/vpp/api/ \
      --output-dir=myproject/vppbinapi \
      --import-prefix=mygit.com/myproject/vppbinapi

This should output the go bindings to ``myproject/vppbinapi``


Connecting to VPP
-----------------

Once you have your go bindings in ``myproject/vppbinapi``, you can start building an agent leveraging them. A typical agent would look like this

First create your project, and add govpp as a dependancy

.. code-block:: bash

    cd myproject
    go mod init mygit.com/myproject
    go get git.fd.io/govpp.git@latest

Then create a ``main.go`` file like this :

.. code-block:: go

    package main

    import (
        "os"
        "fmt"

        "git.fd.io/govpp.git"
        "git.fd.io/govpp.git/api"

        "mygit.com/myproject/vppbinapi/af_packet"
        interfaces "mygit.com/myproject/vppbinapi/interface"
        "mygit.com/myproject/vppbinapi/interface_types"
    )

    func CreateHostInterface (ch api.Channel, ifName string) (uint32, error) {
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
        conn, err := govpp.Connect("/run/vpp/api.sock")
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

Then a simple build & run should connect to VPP on its API socket ``/run/vpp/api.sock``, create an AF_PACKET interface on ``eth0`` and set it up

.. code-block:: bash

    go build
    ./myproject


