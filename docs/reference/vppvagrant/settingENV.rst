.. _settingENV:

.. toctree::


Setting your ENV Variables
==========================


The :ref:`vppVagrantfile` used in the VPP repo sets the configuration options based on your ENV (environment) variables, or to default the configuration at specified values if your ENV variables are not initialized (if you did not run the *env.sh* script found below). 

This is the *env.sh* script found in *vpp/extras/vagrant*. When run, the script sets ENV variables using the **export** command.

.. code-block:: bash

    export VPP_VAGRANT_DISTRO="ubuntu1604"
    export VPP_VAGRANT_NICS=2
    export VPP_VAGRANT_VMCPU=4
    export VPP_VAGRANT_VMRAM=4096 

In the :ref:`vppVagrantfile`, you can see these same ENV variables used (discussed on the next page).

Adding your own ENV variables is easy. For example, if you wanted to setup proxies for your VM, you would add to this file the **export** commands found in the :ref:`building VPP commands section <building>`. Note that this only works if the ENV variable is defined in the :ref:`vppVagrantfile`.

Once you're finished with *env.sh* script, and you are in the directory containing *env.sh*, run the script to set the ENV variables with:

.. code-block:: shell
   
   $ source ./env.sh
