.. _dplugins:

Plugins
=======

vlib implements a straightforward plug-in DLL mechanism. VLIB client
applications specify a directory to search for plug-in .DLLs, and a name
filter to apply (if desired). VLIB needs to load plug-ins very early.

Once loaded, the plug-in DLL mechanism uses dlsym to find and verify a
vlib\_plugin\_registration data structure in the newly-loaded plug-in.

For more on plugins please refer to :ref:`sample_plugin`.
