.. _add_plugin_goapi:

Add a plugin's GO API
=====================

In order to use your plugin's API with GO, you will need to use
a GO client and GO definitions of the API messages that you defined
in ``myplugin.api`` (go bindings).

These two things can be found in :ref:`govpp <https://github.com/FDio/govpp>`

* The API client lives in `./core`
* The api-generator lives in `./binapigen`
* A sample of its output (the go bindings) for VPP's latest version lives in `./binapi`

To generate the go bindings for your plugin. Assuming :
* ``/home/vpp`` is a VPP clone with your plugin in it.
* ``/home/controlplane`` is a go controlplane repo

.. code-block:: console

    $ mkdir /home/controlplane/vpp-go-bindings
    $ git clone https://github.com/FDio/govpp>
    $ cd govpp
    $ BINAPI_DIR=/home/controlplane/vpp-go-bindings VPP_DIR=/home/vpp make gen-binapi-from-code

This will generate the go-bindings in ``/home/controlplane/vpp-go-bindings``
For example ``vpp-go-bindings/myplugin/myplugin.ba.go`` will contain :

.. code-block:: go

    // MypluginEnableDisable defines message 'myplugin_enable_disable'.
    type MypluginEnableDisable struct {
	    EnableDisable bool                           `binapi:"bool,name=enable_disable" json:"enable_disable,omitempty"`
	    SwIfIndex     interface_types.InterfaceIndex `binapi:"interface_index,name=sw_if_index" json:"sw_if_index,omitempty"`
    }


You can then use the generated go bindings in your go code like this :

.. code-block:: go

    package main

    import (
	    "fmt"
	    "git.fd.io/govpp.git"
	    "git.fd.io/govpp.git/binapi/interfaces"
	    "git.fd.io/govpp.git/binapi/vpe"

	    "myplugin.io/controlplane/vpp-go-bindings/myplugin/myplugin"
    )

    func main() {
	    // Connect to VPP
	    conn, _ := govpp.Connect("/run/vpp/api.sock")
	    defer conn.Disconnect()

	    // Open channel
	    ch, _ := conn.NewAPIChannel()
	    defer ch.Close()

	    request := &vpe.MypluginEnableDisable{
		EnableDisable: true,
	    }
	    reply := &vpe.MypluginEnableDisableReply{}

	    err := ch.SendRequest(request).ReceiveReply(reply)
	    if err != nil {
		    fmt.Errorf("SendRequest: %w\n", err)
	    }
    }

As you will need to import (or ``go get "git.fd.io/govpp.git"``) to leverage the API
client in your code, you might want to use the api-generator directly from the
clone ``go build`` fetches for you. You can do this with :

.. code-block:: console

  $ export GOVPP_DIR=$(go list -f '{{.Dir}}' -m git.fd.io/govpp.git)
  $ cd $GOVPP_DIR && go build -o /some/bin/dir ./cmd/binapi-generator
  $ # instead of make gen-binapi-from-code you can rewrite the code to target
  $ # your version ./binapi-generator
