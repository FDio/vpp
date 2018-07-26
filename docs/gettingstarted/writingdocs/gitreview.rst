.. _gitreview:

***************************
Merging FD.io VPP documents
***************************

This section describes how to get FD.io VPP documents reviewed and merged.

Git Review
==========

The VPP documents use the gerrit server and git review.

Clone with ssh
--------------

To get FD.io VPP documents reviewed the VPP repository should be cloned with ssh.

Use the following to setup you ssh key

.. code-block:: console

    $ ssh-keygen -t rsa
    $ keychain
    $ cat ~/.ssh/id_rsa.pub 

Copy that key to the gerrit server.
Then clone the repo with:

.. code-block:: console

    $ git clone ssh://gerrit.fd.io:29418/vpp
    $ cd vpp

New patch
--------------

To get a new patch reviewed use the following:

.. code-block:: console

    $ git status
    $ git add <filename>
    $ git commit -s
    $ git review

If the patch is a draft use the following:

.. note::

    $ git review -D


To get back to the master:

.. code-block:: console

    $ git reset --hard origin/master
    $ git checkout master

Existing patch
--------------

To modify an existing patch:


.. code-block:: console

    $ git status
    $ git add <filename>
    $ git commit --amend
    $ git review
