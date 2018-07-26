.. _jvpp:

.. toctree::

Getting jvpp jar
-------------------
VPP provides java bindings which can be downloaded at:

* https://nexus.fd.io/content/repositories/fd.io.release/io/fd/vpp/jvpp-core/18.01/jvpp-core-18.01.jar

Getting jvpp via maven
-------------------------

**1. Add the following to the repositories section in your ~/.m2/settings.xml to pick up the fd.io maven repo:**

.. code-block:: console

  <repository>
   <id>fd.io-release</id>
   <name>fd.io-release</name>
   <url>https://nexus.fd.io/content/repositories/fd.io.release/</url>
   <releases>
     <enabled>false</enabled>
   </releases>
   <snapshots>
     <enabled>true</enabled>
   </snapshots>
 </repository>

For more information on setting up maven repositories in settings.xml, please look at:

* https://maven.apache.org/guides/mini/guide-multiple-repositories.html 

**2. Then you can get jvpp by putting in the dependencies section of your pom.xml file:**

.. code-block:: console

 <dependency>
   <groupId>io.fd.vpp</groupId>
   <artifactId>jvpp-core</artifactId>
   <version>17.10</version>
 </dependency>

For more information on maven dependency managment, please look at:

* https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html
