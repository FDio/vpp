.. _containerCreation:

.. toctree::

Creating Containers
___________________

Make sure you have gone through :ref:`installingVPP` on the system you want to create containers on.

After VPP is installed, get root privileges with:

.. code-block:: console

  $ sudo bash

Then install packages for containers such as lxc:

.. code-block:: console

  # apt-get install bridge-utils lxc

As quoted from the `lxc.conf manpage <https://linuxcontainers.org/it/lxc/manpages/man5/lxc.conf.5.html>`_,  "container configuration is held in the config stored in the container's directory.
A basic configuration is generated at container creation time with the default's recommended for the chosen template as well as extra default keys coming from the default.conf file."

"That *default.conf* file is either located at /etc/lxc/default.conf or for unprivileged containers at ~/.config/lxc/default.conf."

Since we want to ping between two containers, we'll need to **add to this file**.

Look at the contents of *default.conf*, which should initially look like this:

.. code-block:: console
    
    # cat /etc/lxc/default.conf
    lxc.network.type = veth
    lxc.network.link = lxcbr0
    lxc.network.flags = up
    lxc.network.hwaddr = 00:16:3e:xx:xx:xx

As you can see, by default there is one veth interface.

Now you will *append to this file* so that each container you create will have an interface for a Linux bridge and an unconsumed second interface.

You can do this by piping *echo* output into *tee*, where each line is separated with a newline character *\\n* as shown below. Alternatively, you can manually add to this file with a text editor such as **vi**, but make sure you have root privileges. 

.. code-block:: console

    # echo -e "lxc.network.name = veth0\nlxc.network.type = veth\nlxc.network.name = veth_link1"  | sudo tee -a /etc/lxc/default.conf

Inspect the contents again to verify the file was indeed modified:

.. code-block:: console

    # cat /etc/lxc/default.conf
    lxc.network.type = veth
    lxc.network.link = lxcbr0
    lxc.network.flags = up
    lxc.network.hwaddr = 00:16:3e:xx:xx:xx
    lxc.network.name = veth0
    lxc.network.type = veth
    lxc.network.name = veth_link1


After this, we're ready to create the containers.

Creates an Ubuntu Xenial container named "cone".

.. code-block:: console

      # lxc-create -t download -n cone -- --dist ubuntu --release xenial --arch amd64 --keyserver hkp://p80.pool.sks-keyservers.net:80


If successful, you'll get an output similar to this:

.. code-block:: console
    
    You just created an Ubuntu xenial amd64 (20180625_07:42) container.

    To enable SSH, run: apt install openssh-server
    No default root or user password are set by LXC.


Make another container "ctwo".

.. code-block:: console

     # lxc-create -t download -n ctwo -- --dist ubuntu --release xenial --arch amd64 --keyserver hkp://p80.pool.sks-keyservers.net:80


List your containers to verify they exist:


.. code-block:: console

     # lxc-ls
     cone ctwo


Start the first container:

.. code-block:: console
    
    # lxc-start --name cone

And verify its running:

.. code-block:: console
    
    # lxc-ls --fancy
    NAME STATE   AUTOSTART GROUPS IPV4 IPV6 
    cone RUNNING 0         -      -    -    
    ctwo STOPPED 0         -      -    -  


.. note::

    Here are some `lxc container commands <https://help.ubuntu.com/lts/serverguide/lxc.html.en-GB#lxc-basic-usage>`_ you may find useful:


    .. code-block:: console

          $ sudo lxc-ls --fancy
          $ sudo lxc-start --name u1 --daemon
          $ sudo lxc-info --name u1
          $ sudo lxc-stop --name u1
          $ sudo lxc-destroy --name u1
