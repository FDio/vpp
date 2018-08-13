.. _pushingapatch:

=================
Github Repository
=================

**The github repository is only being used as a source for readthedocs.**
**There should be no reason for the typical developer to use this repository.**
**It should only be used by a document developer.**

Overview
________

This section will cover how to fork your own branch of the `fdioDocs/vpp-docs <https://github.com/fdioDocs/vpp-docs>`_ repository, clone that repo locally to your computer, make changes to it, and how to issue a pull request when you want your changes to be reflected on the main repo.

.. toctree::

Forking your own branch
_______________________
 
In your browser, navigate to the repo you want to branch off of. In this case, the `fdioDocs/vpp-docs <https://github.com/fdioDocs/vpp-docs>`_ repo. At the top right of the page you should see this:

.. figure:: /_images/ForkButtons.png
   :alt: Figure: Repository options on Github 
   :scale: 50%
   :align: right

|
|
|

Click on "Fork", and then a pop-up should appear where you should then click your Github username. Once this is done, it should automatically take you to the Github page where your new branch is located, just like in the image below.

.. figure:: /_images/usernameFork.png
   :alt: Figure: Your own branch of the main repo on Github
   :scale: 35%
   :align: center


Now your **own branch** can be **cloned** to your computer using the URL (https://github.com/YOURUSERNAME/vpp-docs) of the Github page where your branch is located.


Creating a local repository
___________________________

Now that you have your own branch of the main repository on Github, you can store it locally on your computer. In your shell, navigate to the directory where you want to store your branch/repo. Then execute:

.. code-block:: console

   $ git clone https://github.com/YOURUSERNAME/vpp-docs

This will create a directory on your computer named **vpp-docs**, the name of the repo.

Now that your branch is on your computer, you can modify and build files however you wish.

If you are not on the master branch, move to it.

.. code-block:: console

    $ git checkout master


Keeping your files in sync with the main repo
_____________________________________________

The following talks about remote branches, but keep in mind that there are currently *two* branches, your local "master" branch (on your computer), and your remote "origin or origin/master" branch (the one you created using "Fork" on the Github website).

You can view your *remote* repositories with:

.. code-block:: console

   $ git remote -v

At this point, you may only see the remote branch that you cloned from.

.. code-block:: console

   Macintosh:docs Andrew$ git remote -v
   origin  https://github.com/a-olechtchouk/vpp-docs (fetch)
   origin  https://github.com/a-olechtchouk/vpp-docs (push) 

Now you want to create a new remote repository of the main vpp-docs repo (naming it upstream).

.. code-block:: console

   $ git remote add upstream https://github.com/fdioDocs/vpp-docs


You can verify that you have added a remote repo using the previous **git remote -v** command.

.. code-block:: console

   $ git remote -v
   origin  https://github.com/a-olechtchouk/vpp-docs (fetch)
   origin  https://github.com/a-olechtchouk/vpp-docs (push)
   upstream    https://github.com/fdioDocs/vpp-docs (fetch)
   upstream    https://github.com/fdioDocs/vpp-docs (push) 


If there have been any changes to files in the main repo (hopefully not the same files you were working on!), you want to make sure your local branch is in sync with them.

To do so, fetch any changes that the main repo has made, and then merge them into your local master branch using:

.. code-block:: console

   $ git fetch upstream
   $ git merge upstream/master


.. note:: **This is optional, so don't do these commands if you just want one local branch!!!**

    You may want to have multiple branches, where each branch has its own different features, allowing you to have multiple pull requests out at a time. To create a new local branch:

.. code-block:: shell

     $ git checkout -b cleanup-01
     $ git branch
     * cleanup-01
       master
       overview

    Now you can redo the previous steps for "Keeping your files in sync with the main repo" for your newly created local branch, and then depending on which branch you want to send out a pull reqest for, proceed below.


Pushing to your branch
______________________

Now that your files are in sync, you want to add modified files, commit, and push them from *your local branch* to your *personal remote branch* (not the main fdioDocs repo).

To check the status of your files, run:

.. code-block:: console

   $ git status


In the output example below, I deleted gettingsources.rst, made changes to index.rst and pushingapatch.rst, and have created a new file called buildingrst.rst.

.. code-block:: console

   Macintosh:docs Andrew$ git status
   On branch master
   Your branch is up-to-date with 'origin/master'.
   Changes to be committed:
     (use "git reset HEAD <file>..." to unstage)

       deleted:    tasks/writingdocs/gettingsources.rst

   Changes not staged for commit:
     (use "git add <file>..." to update what will be committed)
     (use "git checkout -- <file>..." to discard changes in working directory)

       modified:   tasks/writingdocs/index.rst
       modified:   tasks/writingdocs/pushingapatch.rst

   Untracked files:
     (use "git add <file>..." to include in what will be committed)

       tasks/writingdocs/buildingrst.rst



To add files (use **git add -A** to add all modified files):

.. code-block:: console

   $ git add FILENAME1 FILENAME2

Commit and push using: 

.. code-block:: console

   $ git commit -m 'A descriptive commit message for two files.'

Push your changes for the branch where your changes were made

.. code-block:: console

   $ git push origin <branch name>

Here, your personal remote branch is "origin" and your local branch is "master".

.. note::

    Using **git commit** after adding your files saves a "Snapshot" of them, so it's very hard to lose your work if you *commit often*.



Initiating a pull request (Code review)
_______________________________________

Once you've pushed your changes to your remote branch, go to your remote branch on Github (https://github.com/YOURUSERNAME/vpp-docs), and click on "New pull request". 

.. figure:: /_images/issuePullReq.png
   :alt: Figure: Your own branch of the main repo on Github
   :scale: 35%
   :align: center

This will bring you to a "Comparing changes" page. Click "Create new pull request".

.. figure:: /_images/createNewPullReq.png
   :scale: 35%
   :align: left

|
|
|

Which will open up text fields to add information to your pull request.

.. figure:: /_images/examplePullReq.png
   :scale: 35%
   :align: center


   Then finally click "Create pull request" to complete the pull request.

Your documents will be reviewed. To this same branch make the changes requested from the review and then push your new changes. There is no need to create another pull request.

.. code-block:: console

   $ git commit -m 'A descriptive commit message for the new changes'
   $ git push origin <branch name>


Additional Git commands
_______________________

You may find some of these Git commands useful:

Use **git diff** to quickly show the file changes and repo differences of your commits.

Use **git rm FILENAME** to stop tracking a file and to remove it from your remote branch and local directory. Use flag **-r** to remove folders/directories. E.g (**git rm -r oldfolder**)


.. _fdioDocs: https://github.com/fdioDocs/vpp-docs

