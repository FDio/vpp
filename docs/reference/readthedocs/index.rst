.. _readthedocs:

Read The Docs
=================

`Read the Docs <https://readthedocs.org/>`_ is a website that "simplifies software documentation by automating building, versioning, and hosting of your docs for you". Essentially, it accesses your Github repo to generate the **index.html** file, and then displays it on its own *Read the Docs* webpage so others can view your documentation. 

Create an account on *Read the Docs* if you haven't already.

Go to your `dashboard <https://readthedocs.org/dashboard/>`_ , and click on "Import a Project".

.. figure:: /_images/importReadDocs.png
   :scale: 35%
   :align: left

   This will bring you to a page where you can choose to import a repo from your Github account (only if you've linked your Github account to your Read the Docs account), or to import a repo manually. In this example, we'll do it manually. Click "Import Manually".

|
|
|
|
|
|
|



This will bring you to a page that asks for your repo details. Set "Name" to your forked repo name, or whatever you want. Set "Repository URL" to the URL of your forked repo (https://github.com/YOURUSERNAME/vpp-docs). "Repository type" should already be selected to "Git". Then click "Next".


.. figure:: /_images/importRTDManually.png
   :scale: 35%
   :align: left

|
|
|
|
|
|
|
|
|
|
|
|
|
|
|
|
|
|
|
|
|
|
|


This will bring you to a project page of your repo on Read the Docs. You can confirm it's the correct repo by checking on the right side of the page the Repository URL.

Then click on "Build Version".

.. figure:: /_images/buildVerRTD.png
   :scale: 35%
   :align: left

|
|
|
|
|
|
|
|
|
|
|
|
|
|
|
|
|
|
|
|
|
|
|

Which takes you to another page showing your recent builds. 

Then click on "Build Version:". This should "Trigger" a build. After about a minute or so you can refresh the page and see that your build "Passed". 


.. figure:: /_images/passedBuild.png
   :scale: 35%
   :align: left


|
|
|
|
|
|
|
|
|
|
|
|
|
|
|
|
|
|
|
|
|


Now on your builds page from the previous image, you can click "View Docs" at the top-right, which will take you a *readthedocs.io* page of your generated build!

.. figure:: /_images/rtdWebpage.png
   :scale: 30%
   :align: left
