.. _usingvppconfig.rst:

*******
Running
*******

The vpp-config utility provides the user with several different menus. This allows the
user to configure ports, some performance characteristics, the number of huge pages
and install/uninstall the released FD.io packages.

It is recommended that the menu command options, noted below as *"x)"*, are run in
this order (command option 4 first, then options 1,2,3):

#. :ref:`4) List/Install/Uninstall VPP <config-command-four>`
#. :ref:`1) Show basic system information <config-command-one>`
#. :ref:`2) Dry Run <config-command-two>`
#. :ref:`3) Full Configuration <config-command-three>`

Once vpp-config is installed as a root user, then run the following code:

.. code-block:: console

    $ sudo -H bash
    # vpp-config
    
    Welcome to the VPP system configuration utility
    
    These are the files we will modify:
        /etc/vpp/startup.conf
        /etc/sysctl.d/80-vpp.conf
        /etc/default/grub
    
    Before we change them, we'll create working copies in /usr/local/vpp/vpp-config/dryrun
    Please inspect them carefully before applying the actual configuration (option 3)!
    
    What would you like to do?
    
    1) Show basic system information
    2) Dry Run (Will save the configuration files in /usr/local/vpp/vpp-config/dryrun for inspection)
    4) List/Install/Uninstall VPP.
    q) Quit
    
    Command:

Default Values
==============

If you do not choose to modify the default for any of the questions prompted by vpp-config, then
you may press the **ENTER** key to select the default options:

* Questions that ask [Y/n], the capital letter Y is the default answer.
* Numbers have their default within brackets, such as in [1024], the 1024 is the default.   
