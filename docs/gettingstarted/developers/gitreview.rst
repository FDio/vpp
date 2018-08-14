.. _gitreview:

*******************************
Getting a Patch Reviewed
*******************************

This section describes how to get FD.io VPP sources reviewed and merged.

Setup
========

If you don't have a Linux Foundation ID, `create one here. <https://identity.linuxfoundation.org/>`_

With your Linux Foundation ID credentials sign into `Gerrit Code Review at gerrit.fd.io <https://gerrit.fd.io/r/login/%23%2Fq%2Fstatus%3Aopen>`_

`Install git-review, <https://www.mediawiki.org/wiki/Gerrit/git-review>`_ which is a "command-line tool for Git / Gerrit to submit a change or to fetch an existing one."

If you're on Ubuntu, install keychain:

.. code-block:: console

    $ sudo apt-get install keychain

ssh keys
-------------

To get FD.io VPP documents reviewed the VPP repository should be cloned with ssh. You should be logged into Gerrit Code Review as noted above.

Create your public and private ssh key with:

.. code-block:: console

    $ ssh-keygen -t rsa
    $ keychain
    $ cat ~/.ssh/id_rsa.pub 

Copy **all** the contents of the public key (id_rsa.pub) output by the above **cat** command. Then go to your `SSH Public keys settings page <https://gerrit.fd.io/r/#/settings/ssh-keys>`_, click **Add Key ...**, paste your public key, and finally click **Add**.  

.. _clone-ssh:

Clone with ssh
==============

Clone the repo with:

.. code-block:: console

    $ git clone ssh://gerrit.fd.io:29418/vpp
    $ cd vpp

This will only work if the name of the user on your system matches your Gerrit username.

Otherwise, clone with:

.. code-block:: console

    $ git clone ssh://YOUR_GERRIT_USERNAME@gerrit.fd.io:29418/vpp
    $ cd vpp

When attempting to clone the repo Git will prompt you asking if you want to add the Server Host Key to the list of known hosts. Enter **yes** and press the **Enter** key.

Git Review
===========

The VPP documents use the gerrit server, and git review for submitting and fetching patches.


New patch
-----------------

When working with a new patch, use the following commands to get your patch reviewed.

Make sure you have modified the correct files by issuing the following commands:

.. code-block:: console

    $ git status
    $ git diff

Then add and commit the patch. You may want to add a tag to the commit comments.
For example for a document with only patches you should add the tag **DOCS:**.

.. code-block:: console

    $ git add <filename>
    $ git commit -s -m "<*TAG*>: <*COMMIT_MESSAGE*>"
    $ git review

If you are creating a draft, meaning you do not want your changes reviewed yet, do the following:

.. code-block:: console

    $ git review -D

After submitting a review, reset where the HEAD is pointing to with:

.. code-block:: console

    $ git reset --hard origin/master

Existing patch
-----------------------

The "change number" used below is in the URL of the review.

After clicking an individual review, the change number can be found in the URL at "https://gerrit.fd.io/r/#/c/<*CHANGE_NUMBER*>/"

To view an existing patch:

.. code-block:: console

    $ git review -d <change number>
    $ git status
    $ git diff

.. caution::

    If you have made changes and do "git review -d <change number>", your current
    changes will try to be stashed so that the working tree can change to the review branch
    you specified. If you want to make sure you don't lose your changes, clone another Gerrit
    repo into a new directory using the cloning steps shown in :ref:`clone-ssh`, and perform
    "git review -d <change number>" in this new directory.

To modify an existing patch, make sure you modified the correct files, and apply the patch with:

.. code-block:: console

    $ git review -d <change number>
    $ git status
    $ git diff

    $ git add <filename>
    $ git commit --amend
    $ git review

When you're done viewing or modifying a branch, get back to the master branch with:

.. code-block:: console

    $ git reset --hard origin/master
    $ git checkout master

Resolving a Conflict
--------------------------------

If a change has a conflict it should be resolved with the following:git-review -d <Gerrit change #>

.. code-block:: console

    $ git rebase origin/master
       while (conflicts)
          <fix conflicts>
          $ git rebase --continue
    $ git review



