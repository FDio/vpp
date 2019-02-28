.. _vppinazure:

.. toctree::

VPP in Azure
___________________




Before starting, a few notes:

* in our configuration we use only DPDK 18.02, since with the newer versions, such as DPDK 18.05, we obtained several problems during VPP installation (mostly related with MLX4 PMD Drivers). 

* Some of the commands are taken from `Azure’s DPDK page <https://docs.microsoft.com/en-us/azure/virtual-network/setup-dpdk>`_.

To bring DPDK inside Azure, we perform the following procedure:

Firstly, we install the DPDK dependencies:

.. code-block:: console

 $ sudo add-apt-repository ppa:canonical-server/dpdk-azure –y
 $ sudo apt-get update
 $ sudo apt-get install -y librdmacm-dev librdmacm1 build-essential libnuma-dev libmnl-dev

Then, we download DPDK 18.02:

.. code-block:: console

 $ sudo wget https://fast.dpdk.org/rel/dpdk-18.02.2.tar.xz
 $ tar -xvf dpdk-18.02.2.tar.xz

Finally, we build DPDK, modifying first its configuration files in order to make VPP compatible with MLX4 drivers:

Inside config/common_base, modify:

.. code-block:: console

  CONFIG_RTE_BUILD_SHARED_LIB=n
  CONFIG_RTE_LIBRTE_MLX4_PMD=y
  CONFIG_RTE_LIBRTE_MLX4_DLOPEN_DEPS=y
  CONFIG_RTE_LIBRTE_TAP_PMD=y
  CONFIG_RTE_LIBRTE_FAILSAFE_PMD=y

and then:

.. code-block:: console

 $ make config T=x86_64-native-linuxapp-gcc
 $ sed -ri 's,(MLX._PMD=)n,\1y,' build/.config
 $ make

Finally we build DPDK:

.. code-block:: console

 $ make install T=x86_64-native-linuxapp-gcc DESTDIR=/home/ciscotest/test EXTRA_CFLAGS='-fPIC -pie'

And we reboot the instance:

.. code-block:: console

 $ reboot istance

After the reboot, we type these commands:

.. code-block:: console

 $ echo 1024 | sudo tee /sys/devices/system/node/node*/hugepages/hugepages-2048kB/nr_hugepages
 $ mkdir /mnt/huge
 $ sudo mount -t hugetlbfs nodev /mnt/huge
 $ grep Huge /proc/meminfo
 $ modprobe -a ib_uverbs
 $ cd x86_64-native-linuxapp-gcc/
 $ ls
 $ cd lib/
 $ ls
 $ sudo cp librte_pmd_mlx4_glue.so.18.02.0 /usr/lib

**Now we focus on VPP installation:**

In our configuration we use VPP 18.07.

We perform this procedure in order to install VPP 18.07 with an external DPDK configuration inside Azure.

Firstly, we download VPP

.. code-block:: console

 $ git clone https://gerrit.fd.io/r/vpp
 $ git checkout v18.07

Then, we build VPP, using the external DPDK configuration we previously made:

We modify the path inside the vpp.mk file:

.. code-block:: console

 $ build-data/platforms/vpp.mk
 $ vpp_uses_external_dpdk = yes
 $ vpp_dpdk_inc_dir = <PATH_TO_DESTDIR_NAME_FROM_ABOVE>/include/dpdk/
 $ vpp_dpdk_lib_dir =<PATH_TO_DESTDIR_NAME_FROM_ABOVE>/lib

<PATH_TO_DESTDIR_NAME_FROM_ABOVE> is whatever the path used when compiling DPDK above. These paths have to be absolute path in order for it to work.

we modify build-data/platforms/vpp.mk to use

.. code-block:: console

 vpp_uses_dpdk_mlx4_pmd = yes

.. code-block:: console

 $ make build
 $ cd build-root/
 $ make V=0 PLATFORM=vpp TAG=vpp install-deb
 $ sudo dpkg -i *.deb

Finally, we modify the startup.conf file:

.. code-block:: console

 $ cd /etc/vpp
 $ sudo nano startup.conf

Inside the DPDK block, the following commands:

.. code-block:: console


 ## Whitelist specific interface by specifying PCI address
 dev 000X:00:0X.0
 dev 000X:00:0X.0
 
 # Running failsafe
 vdev net_vdev_netvsc0,iface=eth1
 vdev net_vdev_netvsc1,iface=eth2

*Please refer to Azure DPDK document to pick the right iface to use for failsafe vdev.*


and finally:

.. code-block:: console

 $ sudo service vpp stop
 $ sudo service vpp start
 $ sudo service vpp status
 $ sudo vppctl

Now VPP will work inside Azure!








