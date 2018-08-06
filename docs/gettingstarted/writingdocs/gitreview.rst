.. _gitreview:

***************************
Merging FD.io VPP documents
***************************

This section describes how to get FD.io VPP documents reviewed and merged.

Setup
-----

If you don't have a Linux Foundation ID, `create one here. <https://identity.linuxfoundation.org/>`_

With your Linux Foundation ID credentials sign into `Gerrit Code Review at gerrit.fd.io <https://gerrit.fd.io/r/login/%23%2Fq%2Fstatus%3Aopen>`_

`Install git-review, <https://www.mediawiki.org/wiki/Gerrit/git-review>`_ which is a "command-line tool for Git / Gerrit to submit a change or to fetch an existing one."

If you're on Ubuntu, install keychain:

.. code-block:: console

    $ sudo apt-get install keychain

ssh keys
--------

To get FD.io VPP documents reviewed the VPP repository should be cloned with ssh. You should be logged into Gerrit Code Review as noted above.

Create your public and private ssh key with:

.. code-block:: console

    $ ssh-keygen -t rsa
    $ keychain
    $ cat ~/.ssh/id_rsa.pub 

Copy **all** the contents of the public key (id_rsa.pub) output by the above **cat** command. Then go to your `SSH Public keys settings page <https://gerrit.fd.io/r/#/settings/ssh-keys>`_, click **Add Key ...**, paste your public key, and finally click **Add**.  

If you **did not** install keychain, start *ssh-agent* and add the private key manually:

.. code-block:: console

    $ eval "$(ssh-agent -s)"
    $ ssh-add ~/.ssh/id_rsa

.. note:: 

    MacOS or Windows users can `follow the steps here to generate and add ssh keys. <https://help.github.com/articles/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent/#platform-mac>`_ 

.. _clone-ssh:

Clone with ssh
--------------

Clone the repo with:

.. code-block:: console

    $ git clone ssh://gerrit.fd.io:29418/vpp
    $ cd vpp

This will only work if the name of the user on your system matches your Gerrit username.

Otherwise, clone with:

.. code-block:: console

    $ git clone ssh://YOUR_GERRIT_USERNAME@gerrit.fd.io:29418/vpp
    $ cd vpp

When attempting to clone the repo it will ask if you want to add the Server Host Key to the list of known hosts. Type **yes** and hit enter.

If it did not ask to add the Server Host Key to the list of known hosts (on my MacOS system it didn't), you have to add it manually. If so, perform the following steps:

Go to your `SSH Public keys settings page <https://gerrit.fd.io/r/#/settings/ssh-keys>`_ and look for the **ssh-rsa Sever Host Key**. Copy **all** the contents of the key, which starts with "[gerrit.fd.io]:29418 ssh-rsa ....."

Once copied, append the copied ssh-rsa Server Host Key to the file *~/.ssh/known_hosts*

.. code-block:: console

    $ echo "PASTE_SERVER_HOST_KEY_HERE" >> ~/.ssh/known_hosts 

Then repeat the cloning step above.

Git Review
==========

The VPP documents use the gerrit server and git review for submitting and fetching patches.


New patch
---------

Make sure you modified the correct files with:

.. code-block:: console

    $ git status
    $ git diff

To get a new patch reviewed use the following:

.. code-block:: console

    $ git add <filename>
    $ git commit -s -m "<OPTIONAL_TAG>: <COMMIT_MESSAGE>"
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

The "change number" used below is in the URL of the review. You can find changes that you own by typing in the Gerrit search bar "owner:self", or find changes based on reviewers by typing in the Gerrit search bar "reviewer:self".

After clicking an individual review, the change number can be found in the URL at "https://gerrit.fd.io/r/#/c/<CHANGE_NUMBER>/"

To view an existing patch:

.. code-block:: console

    $ git review -d <change number>
    $ git status
    $ git diff

.. caution::

    If you have made changes and do "git review -d <change number>", your current changes will try to be stashed so that the working tree can change to the review branch you specified. If you want to make sure you don't lose your changes, clone another Gerrit repo into a new directory using the cloning steps shown in :ref:`clone-ssh`, and perform "git review -d <change number>" in this new directory.

To modify an existing patch, make sure you modified the correct files, and apply the patch with:

.. code-block:: console

    $ git review -d <change number>
    $ git status
    $ git diff

    $ git add <filename>
    $ git commit --amend
    $ git review
