.. _vppinaws:

.. toctree::

VPP in AWS
___________________

Warning: before starting this guide you should have a minimum knowledge on how `AWS works <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/concepts.html>`_!

First of all, you should log into your Virtual Machine inside AWS (we suggest to create an instance with Ubuntu 16.04 on a m5 type) and download some useful packages to make VPP installation as smooth as possible: 

.. code-block:: console

 $ sudo apt-get update
 $ sudo apt-get upgrade
 $ sudo apt-get install build-essential
 $ sudo apt-get install python-pip
 $ sudo apt-get install libnuma-dev
 $ sudo apt-get install make
 $ sudo apt install libelf-dev



Afterwards, types the following commands to install VPP:

.. code-block:: console

 $ curl -s https://packagecloud.io/install/repositories/fdio/1807/script.deb.sh | sudo bash




In this case we downloaded VPP version 18.07 but actually you can use any VPP version available. Then, you can install VPP with all of its plugins: 


.. code-block:: console

 $ sudo apt-get update
 $ sudo apt-get install vpp
 $ sudo apt-get install vpp-plugins vpp-dbg vpp-dev vpp-api-java vpp-api-python vpp-api-lua



Now, you need to bind the NICs (Network Card Interface) to VPP. Firstly you have the retrieve the PCI addresses of the NICs you want to bind:

.. code-block:: console

 $ sudo lshw -class network -businfo




The PCI addresses have a format similar to this: 0000:00:0X.0. Once you retrieve them, you should copy them inside the startup file of VPP:

.. code-block:: console

 $ sudo nano /etc/vpp/startup.conf



Here, inside the dpdk block, copy the PCI addresses of the NIC you want to bind to VPP.


.. code-block:: console

  dev 0000:00:0X.0




Now you should install DPDK package. This will allow to bind the NICs to VPP through a script available inside the DPDK package:

.. code-block:: console

 $  wget https://fast.dpdk.org/rel/dpdk-18.08.tar.xz
 $  tar -xvf dpdk-18.08.tar.xz
 $  cd ~/dpdk-18.08/usertools/



and open the script:

.. code-block:: console

 $ ./dpdk-setup.sh



When the script is running, you should be able to execute several options. For the moment, just  install  T=x86_64-native-linuxapp-gcc and then close the script. Now go inside:

.. code-block:: console

 $ cd ~/dpdk-18.08/x86_64-native-linuxapp-gcc/



and type:

.. code-block:: console

 $ sudo modprobe uio
 $ sudo insmod kmod/igb_uio.ko


In this way, the PCIs  addresses should appear inside the setup file of DPDK and therefore you  can bind them:

.. code-block:: console

 $ ./dpdk-setup.sh



Inside the script, bind the NICs using the option 24.

Finally restart VPP and the NICs should appear inside VPP CLI:

.. code-block:: console

 $ sudo service vpp stop
 $ sudo service vpp start
 $ sudo vppctl show int




Notice that if you stop the VM, you need to bind again the NICs.





















