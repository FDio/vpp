.. _boxSetup:

.. toctree::


Vagrantfiles
============

A `Vagrantfile <https://www.vagrantup.com/docs/vagrantfile/>`_ contains the box and provision configuration settings for your VM. The syntax of Vagrantfiles is Ruby (Ruby experience is not necessary).

The command **vagrant up** creates a *Vagrant Box* based on your Vagrantfile. A Vagrant box is one of the motivations for using Vagrant - its a "development-ready box" that can be copied to other machines to recreate the same environment. 

It's common for people to think that a Vagrant box *is* the VM. But rather, the VM is *inside* a Vagrant box, with the box containing additional configuration options you can set, such as VM options, scripts to run on boot, etc.

This `Vagrant website for boxes <https://app.vagrantup.com/boxes/search>`_  shows you how to configure a basic Vagrantfile for your specific OS and VM software.


Box configuration 
_________________


Looking at the :ref:`vppVagrantfile`, we can see that the default OS is Ubuntu 16.04 (since the variable *distro* equals *ubuntu1604* if there is no VPP_VAGRANT_DISTRO variable set - thus the **else** case is executed.)

.. code-block:: ruby

    # -*- mode: ruby -*-
    # vi: set ft=ruby :

    Vagrant.configure(2) do |config|

      # Pick the right distro and bootstrap, default is ubuntu1604
      distro = ( ENV['VPP_VAGRANT_DISTRO'] || "ubuntu1604")
      if distro == 'centos7'
        config.vm.box = "centos/7"
        config.vm.box_version = "1708.01"
        config.ssh.insert_key = false
      elsif distro == 'opensuse'
        config.vm.box = "opensuse/openSUSE-42.3-x86_64"
        config.vm.box_version = "1.0.4.20170726"
      else
        config.vm.box = "puppetlabs/ubuntu-16.04-64-nocm"

As mentioned in the previous page, you can specify which OS and VM provider you want for your Vagrant box from the `Vagrant boxes page <https://app.vagrantup.com/boxes/search>`_, and setting your ENV variable appropriately in *env.sh*.

Next in the Vagrantfile, you see some *config.vm.provision* commands. As paraphrased from `Basic usage of Provisioners <https://www.vagrantup.com/docs/provisioning/basic_usage.html>`_, by default these are only run *once* - during the first boot of the box.

.. code-block:: ruby

    config.vm.provision :shell, :path => File.join(File.dirname(__FILE__),"update.sh")
    config.vm.provision :shell, :path => File.join(File.dirname(__FILE__),"build.sh"), :args => "/vpp vagrant"

The two lines above set the VM to run two scripts during its first bootup: an update script *update.sh* that does basic updating and installation of some useful tools, as well as *build.sh* that builds (but does **not** install) VPP in the VM. You can view these scripts on your own for more detail on the commands used.


Looking further in the :ref:`vppVagrantfile`, you can see more Ruby variables being set to ENV's or to a default value:

.. code-block:: ruby

    # Define some physical ports for your VMs to be used by DPDK
    nics = (ENV['VPP_VAGRANT_NICS'] || "2").to_i(10)
    for i in 1..nics
      config.vm.network "private_network", type: "dhcp"
    end

    # use http proxy if avaiable
    if ENV['http_proxy'] && Vagrant.has_plugin?("vagrant-proxyconf")
     config.proxy.http     = ENV['http_proxy']
     config.proxy.https    = ENV['https_proxy']
     config.proxy.no_proxy = "localhost,127.0.0.1"
    end

    vmcpu=(ENV['VPP_VAGRANT_VMCPU'] || 2)
    vmram=(ENV['VPP_VAGRANT_VMRAM'] || 4096)


You can see how the box or VM is configured, such as the amount of NICs (defaults to 3 NICs: 1 x NAT - host access and 2 x VPP DPDK enabled), CPUs (defaults to 2), and RAM (defaults to 4096 MB).


Box bootup
__________


Once you're satisfied with your *Vagrantfile*, boot the box with:

.. code-block:: shell

    $ vagrant up

Doing this above command will take quite some time, since you are installing a VM and building VPP. Take a break and get some scooby snacks while you wait.

To confirm it is up, show the status and information of Vagrant boxes with: 

.. code-block:: console

  $ vagrant global-status
  id       name    provider   state    directory                                           
  -----------------------------------------------------------------------------------------
  d90a17b  default virtualbox poweroff /home/centos/andrew-vpp/vppsb/vpp-userdemo          
  77b085e  default virtualbox poweroff /home/centos/andrew-vpp/vppsb2/vpp-userdemo         
  c1c8952  default virtualbox poweroff /home/centos/andrew-vpp/testingVPPSB/extras/vagrant 
  c199140  default virtualbox running  /home/centos/andrew-vpp/vppsb3/vpp-userdemo 

  You will have only one machine running, but I have multiple as shown above.

.. note::

  To poweroff your VM, type:

  .. code-block:: shell

     $ vagrant halt <id>

  To resume your VM, type:

  .. code-block:: shell

     $ vagrant resume <id>
     
  To destroy your VM, type:

  .. code-block:: shell

     $ vagrant destroy <id>

  Note that "destroying" a VM does not erase the box, but rather destroys all resources allocated for that VM. For other Vagrant commands, such as destroying a box, refer to the `Vagrant CLI Page <https://www.vagrantup.com/docs/cli/>`_.