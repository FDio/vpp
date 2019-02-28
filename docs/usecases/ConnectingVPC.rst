.. _ConnectingVPC:

.. toctree::

Interconnecting VPCs with Segment Routing & Performance Evaluation
____________________________________________________________________

Before reading this part, you should have a minimum understading of AWS, especially on `VPC concepts <https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html>`_.



.. figure:: /_images/Connecting_VPC.svg

Figure 1:  Simplified view of our final configuration.


In this section we will set VPP as Gateway of our VPC and, thanks to its support to Segment Routing per IPV6, we will interconnect several VPCs together. Figure 1 shows what will be our final configuration. We are interested in interconnecting several VPCs together since we could perform Service Chaining inside AWS.

Now we focus on the basic elements you should deploy inside the VPC in order to make  this configuration works. Here you can find some scripts `to automate the deployment of these resources <https://github.com/francescospinelli94/Automating-Deployment-VPP>`_.
In our VPC we will have two instances: one, in which we will install VPP and the other one which will be our Client/Server machine. We suggest you to create 3 subnets inside your VPC: one associated with IPv4 addresses, for reaching your VMs through SSH. The second one, also with IPV4 addresses, that allows connectivity between the Client/Server machine and the VPP machine. Finally you need a third one, with both IPv4 and IPv6 address, to connect VPP with the Amazon IGW and we will use IPv6 addresses to implement Segment Routing. Moreover you have to attach to the Client/Server machine one additional NIC, while instead to the VPP machine you have to attach 2 different NIC. One will be used inside the IPv6 subnet while the other one will allow communications with the other VM. you can find an example in Figure 2


.. figure:: /_images/vpc_scheme.svg

Figure 2: Example of the resourses present inside our VPC


Notice that the following example works with two VPCs, where in each of them there are a VM with VPP and a VM. Hence,  you will have to execute the same commands also in the other VPC to make the connection between the two VPC possibile.


Now, create a new VM instance (you can use same setting as before (Ubuntu Server 16.04 and m5 type)) and attach a NIC. Remember that the two Client/Server machine's NICs should stay in two different IPv4 Subnet. Afterwards, on the VM's terminal execute these commands:

.. code-block:: console

 $ sudo /sbin/ip -4 addr add 10.1.2.113/24 dev ens6
 $ sudo ifconfig ens6 up
 $ sudo /sbin/ip -4 route add 10.2.0.0/16 via 10.1.4.117

Basically you are setting up the interface which you will use to reach VPP and telling that all the traffic belonging to the subnet 10.2.0.0/16, which in our case is the one of the other VPC, should go through VPP's interface. Remember also to do the same thing in the route table menu of the Amazon Console Management.

Now go to the terminal of VPP, enter in the VPP CLI and type these commands to  set up the two virtual interfaces. To see how to bind the NICs to VPP, see here (Link AWS in VPP).

.. code-block:: console

 vpp# set int state VirtualFunctionEthernet0/6/0 up
 vpp# set int state VirtualFunctionEthernet0/7/0 up

Here instead you are assigning the IP addresses to the network interfaces.

.. code-block:: console

 vpp# set int ip address VirtualFunctionEthernet0/6/0 10.1.4.117/24
 vpp# set int ip address VirtualFunctionEthernet0/7/0 2600:1f14:e0e:7f00:f672:1039:4e41:e68/64

Afterwards, you should use the Segment Routing's functionalities. Note that for the localsid address we are using a different IPv6 address (you can generate another one through the Amazon console)


.. code-block:: console

 vpp# set sr encaps source addr 2600:1f14:e0e:7f00:f672:1039:4e41:e68
 vpp# sr localsid address 2600:1f14:e0e:7f00:8da1:c8fa:5301:1d1f behavior end.dx4     	VirtualFunctionEthernet0/6/0 10.1.4.117
 vpp# sr policy add bsid c:1::999:1  next 2600:1f14:135:cc00:43c1:e860:7ce9:e94a encap
 vpp# sr steer l3 10.2.5.0/24 via  bsid c:1::999:1

Finally, you are setting the ip6 discovery, telling which is the next hop (the IGW). Notice that the MAC address is the MAC address of the IGW.

.. code-block:: console


 vpp# set ip6 neighbor VirtualFunctionEthernet0/7/0 fe80::84f:3fff:fe2a:aaf0 0a:4f:3f:2a:aa:f0
 vpp# ip route add ::/0 via fe80::84f:3fff:fe2a:aaf0 VirtualFunctionEthernet0/7/0


Now go in the other VM instance in the other VPC, which could be located in another Amazon Region, and do the same commands. First in the VM:

.. code-block:: console

 vpp# sudo /sbin/ip -4 addr add 10.2.5.190/24 dev ens6
 vpp# sudo ifconfig ens6 up
 vpp# sudo /sbin/ip -4 route add 10.2.0.0/16 via 10.2.5.21

Then, in VPP:

.. code-block:: console

 vpp# set int state VirtualFunctionEthernet0/6/0 up
 vpp# set int state VirtualFunctionEthernet0/7/0 up
 vpp# set int ip address VirtualFunctionEthernet0/6/0 10.2.5.21/24
 vpp# set int ip address VirtualFunctionEthernet0/7/0 2600:1f14:135:cc00:13b9:ff74:348d:7642/64
 vpp# set sr encaps source addr 2600:1f14:135:cc00:13b9:ff74:348d:7642
 vpp# sr policy add bsid c:3::999:1  next 2600:1f14:e0e:7f00:8da1:c8fa:5301:1d1f encap
 vpp# sr steer l3 10.1.4.0/24 via bsid c:3::999:1
 vpp# set ip6 neighbor VirtualFunctionEthernet0/7/0 fe80::86a:b7ff:fe5d:73c0 0a:4c:fd:b8:c1:3e
 vpp# ip route add ::/0 via fe80::86a:b7ff:fe5d:73c0 VirtualFunctionEthernet0/7/0

Now if you try ping your Server machine from your Client Machine you should be able to reach it.

If you are interested in Performance evaluation inside this scenario, we will present a poster at INFOCOM'19, in which will be present our performance evaluation of Segment routing inside AWS:

*Francesco  Spinelli,  Luigi  Iannone,  and  Jerome  Tollet. “Chaining  your  Virtual  Private  Clouds  with  Segment Routing”. In:2019 IEEE INFOCOM Poster (INFOCOM2019 Poster). Paris, France, Apr. 2019*


**Troubleshooting**

* Remember to disable source/dest check on the VPP and VMs Network Card interfaces. You can do it through the Amazon Console.

* The commands work with VPP version 18.07. If you're using a different version, probably the syntax of some VPP commands will be slightly different.

* Be careful: if you stop your VM with VPP you will need to attach again the two NICs to VPP.
