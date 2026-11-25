.. _ssh_plugin:

SSH CLI
=======

The ssh plugin gives the VPP CLI to users who log in with an SSH client. It
needs the ``libssh`` development files (``libssh-dev`` on Debian and Ubuntu) at
build time, the plugin is not built without them.

Compared to telnet, an SSH session is encrypted and authenticated, and VPP
learns the terminal of the user from the client: its size, the changes of the
size, and whether it takes ANSI sequences.

Configuration
-------------

The plugin is off unless the ``ssh`` section, with something in it, is in the
startup configuration:

.. code-block:: text

   ssh {
     port 2222
     user alice {
       key ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExample
     }
   }

``port``
   TCP port to listen on, the default is 2222.

``listen-address``
   Address to listen on, the default is 127.0.0.1. VPP gives full control of
   the system to anybody who logs in, do not listen on a wider network than
   needed.

``host-key``
   File with the private key of the host. When it is not set, the file
   ``ssh_host_ed25519_key`` in the configuration directory is used, which is
   ``/etc/vpp`` for root and ``$XDG_CONFIG_HOME/vpp`` for the other users, see
   ``config-dir`` in the ``unix`` section. The file has to exist, VPP never
   creates it and does not start without it, so that the clients see the same
   key after every restart. Create it once, as the user who runs VPP, with an
   OpenSSH private key without a passphrase:

   .. code-block:: console

      $ mkdir -p <dir> && ssh-keygen -t ed25519 -N '' -f <dir>/ssh_host_ed25519_key

   The file must not be accessible by the group or others (``chmod 600``),
   and it must be on a file system which survives a reboot. The clients can
   check the key against the ``.pub`` file next to it, or against the
   fingerprint which ``show ssh-server host`` prints.

``user <name>``
   A user who may log in. Its block has one or more ``key <type> <base64>``
   lines, the public keys the user logs in with. Take the type and the key
   from the ``.pub`` file of the user, without the comment at the end, for
   example ``ssh-ed25519 AAAA...``.

At least one user is needed, and VPP does not start when the section is
wrong. Only public key authentication is available, there are no passwords.

Using it
--------

.. code-block:: console

   $ ssh -p 2222 alice@127.0.0.1

The session is an ordinary CLI session, ``quit`` or ``exit`` ends it. Remote
commands (``ssh host command``), port forwarding and file transfer are not
supported, the server only gives an interactive terminal.

``show ssh-server`` shows the address and the port, the host key, the users and
the sessions. ``show ssh-server host``, ``show ssh-server users`` and
``show ssh-server sessions`` show one of them each, and take ``| json``.

A connection which has not logged in within a minute is closed, and at most 16
sessions are open at the same time.
