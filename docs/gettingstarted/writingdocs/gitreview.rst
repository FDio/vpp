.. _gitreview:

***************************
Merging FD.io VPP documents
***************************

This section describes how to get FD.io VPP documents reviewed and merged.

Setup
-----

If you don't have a Linux Foundation ID, `create one here. <https://identity.linuxfoundation.org/>`_

With your Linux Foundation ID credentials sign into `Gerrit Code Review at gerrit.fd.io <https://gerrit.fd.io/r/login/%23%2Fq%2Fstatus%3Aopen>`_

ssh keys
--------

To get FD.io VPP documents reviewed the VPP repository should be cloned with ssh. You should be logged into Gerrit Code Review as noted above.

Create your public and private ssh key with:

.. code-block:: console

    $ ssh-keygen -t rsa
    $ keychain
    $ cat ~/.ssh/id_rsa.pub 

Copy **all** the contents of the public key (id_rsa.pub) output by the above **cat** command. Then go to your `SSH Public keys settings page <https://gerrit.fd.io/r/#/settings/ssh-keys>`_, click **Add Key ...**, paste your public key, and finally click **Add**.  

Clone with ssh
--------------

Clone the repo with:

.. code-block:: console

    $ git clone ssh://gerrit.fd.io:29418/vpp
    $ cd vpp

Depending on your system, you might get "permission denied" when trying to clone the repo.
In this case, perform the following steps:

Add the private ssh key to your keychain:

.. code-block:: console

    $ ssh-add ~/.ssh/id_rsa

Next, go to your `SSH Public keys settings page <https://gerrit.fd.io/r/#/settings/ssh-keys>`_ and look for the **ssh-rsa Sever Host Key**. Copy **all** the contents of the key, which starts with "[gerrit.fd.io]:29418 ssh-rsa ....."

Once copied, append the copied ssh-rsa Server Host Key to the file *~/.ssh/known_hosts*

.. code-block:: console

    $ echo "PASTE_SERVER_HOST_KEY_HERE" >> ~/.ssh/known_hosts 

Finally, clone the repo with:

.. code-block:: console

    $ git clone ssh://YOUR_GERRIT_USERNAME@gerrit.fd.io:29418/vpp
    $ cd vpp


Git Review
==========

The VPP documents use the gerrit server and git review for submitting and fetching patches.

"git-review is a command-line tool for Git / Gerrit to submit a change or to fetch an existing one."

git-review is not installed with git by default, so `follow the steps to install it here. <https://www.mediawiki.org/wiki/Gerrit/git-review>`_ 

New patch
---------

Make sure you modified the correct files with:

.. code-block:: console

    $ git status
    $ git diff

To get a new patch reviewed use the following:

.. code-block:: console

    $ git add <filename>
    $ git commit -s -m "<DIRECTORY_YOU_ARE_CHANGING>: <COMMIT_MESSAGE>"
    $ git review

.. note::

    If the patch is a draft use the following:

    .. code-block:: console

        $ git review -D

After submitting a review, reset where the HEAD is pointing to with:

.. code-block:: console

    $ git reset --hard origin/master

Existing patch
--------------

To modify an existing patch:


.. code-block:: console

    $ git review -d <review number>
    $ git status
    $ git add <filename>
    $ git commit --amend
    $ git review
