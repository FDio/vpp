.. _gitreview:

*******************************
Getting a Patch Reviewed
*******************************

This section describes how to get FD.io VPP sources reviewed and merged.

Review Guidelines
=================

Reviewers have limited time to review patches. In order to help them, please consider the following guidelines:
 - make sure your patch is clear and concise. If your patch is large, consider breaking it into smaller patches.
 - add the relevant maintainers as reviewer in gerrit. You can look at the `MAINTAINERS <https://git.fd.io/vpp/tree/MAINTAINERS>`_ file.
 - make sure to answer any question or comment from the reviewers in a timely manner.

If your patch is not reviewed within a reasonable time, consider reaching out to the `VPP mailing list <https://lists.fd.io/g/vpp-dev>`_ asking for a review.

There is an auto-abandon policy for patches that have not seen any activity for 6 months.
Such patches will be automatically abandoned by a bot.
Please consider this as a nudge for you to refresh and restore it, and ask for a review again.

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

    $ git clone ssh://<YOUR_GERRIT_USERNAME>@gerrit.fd.io:29418/vpp
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
For example for a document with only patches you should add the tag **docs:**.

.. code-block:: console

    $ git add <filename>
    $ git commit -s

The commit comment should have something like the following comment:

.. code-block:: console

   docs: A brief description of the commit

   Type: Improvement (The type of commit this could be: Improvement, Fix or Feature)

   A detailed description of the commit could go here.

Push the patch for review.

.. code-block:: console

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

When you're done viewing or modifying a branch, get back to the master branch by entering:

.. code-block:: console

    $ git reset --hard origin/master
    $ git checkout master

Patch Conflict Resolution
-------------------------

Two different patch conflict scenarios arise from time to
time. Sometime after uploading a patch to https://gerrit.fd.io, the
gerrit UI may show a patch status of "Merge Conflict."

Or, you may attempt to upload a new patch-set via "git review," only to
discover that the gerrit server won't allow the upload due to an upstream
merge conflict.

In both cases, it's [usually] fairly simple to fix the problem. You
need to rebase the patch onto master/latest. Details vary from case to
case.

Here's how to rebase a patch previously uploaded to the Gerrit server
which now has a merge conflict. In a fresh workspace cloned from
master/latest, do the following:

.. code-block:: console

    $ git-review -d <*Gerrit change #*>
    $ git rebase origin/master
       while (conflicts)
          <fix conflicts>
          $ git rebase --continue
    $ git review

In the upload-failure case, use caution: carefully **save your work**
before you do anything else!

Rebase your patch and try again. Please **do not** re-download ["git
review -d"] the patch from the gerrit server...:

.. code-block:: console

    $ git rebase origin/master
       while (conflicts)
          <fix conflicts>
          $ git rebase --continue
    $ git review

