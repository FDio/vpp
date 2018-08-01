.. _VagrantVMSetup:

.. toctree::

Accessing your VM
^^^^^^^^^^^^^^^^^
ssh into the newly created box:

.. code-block:: shell

    $ vagrant ssh <id>

Sample output looks like:

.. code-block:: console

  $ vagrant ssh c1c
  Welcome to Ubuntu 16.04 LTS (GNU/Linux 4.4.0-21-generic x86_64)

   * Documentation:  https://help.ubuntu.com/
  Last login: Mon Jun 25 08:05:38 2018 from 10.0.2.2
  vagrant@localhost:~$


.. note::
  
  Type **exit** in the command-line if you want to exit the VM.

Become the root with:

.. code-block:: shell

    $ sudo bash

Now *install* VPP in the VM. Keep in mind that VPP is already built (but not yet installed) at this point based on the commands from the provisioned script *build.sh*. 

When you ssh into your Vagrant box you will be placed in the directory */home/vagrant*. Change directories to */vpp/build-root*, and run these commands to install VPP based on your OS and architechture:

For Ubuntu systems:

.. code-block:: shell
    
    # dpkg -i *.deb

For CentOS systems:

.. code-block:: shell
    
    # rpm -Uvh *.rpm


Since VPP is now installed, you can start running VPP with:

.. code-block:: shell
  
    # service vpp start
