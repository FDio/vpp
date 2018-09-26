.. _contivVPP:

FD.io VPP with Contiv-VPP
=========================

Contiv - VPP
------------

Contiv unifies containers, VMs, and bare metal with a single networking fabric, allowing container networks to be addressable from VM and bare-metal networks. `Contiv-VPP <https://github.com/contiv/vpp>`_ is Kubernetes CNI plugin based on the FD.io VPP, which provides network connectivity between PODs.

Quickstart
----------

You can get started with Contiv-VPP in one of two ways:

* Use the `Contiv-VPP Vagrant Installation instructions <https://github.com/contiv/vpp/blob/master/vagrant/README.md>`_ to start a simulated Kubernetes cluster with a couple of hosts running in VirtualBox VMs. This is the easiest way to bring up a cluster for exploring the capabilities and features of Contiv-VPP.
* Use the `Contiv-specific kubeadm install instructions <https://github.com/contiv/vpp/blob/master/docs/MANUAL_INSTALL.md>`_ to manually install Kubernetes with Contiv-VPP networking on one or more bare-metals.
* Use the `Aarch64-specific kubeadm install instructions <https://github.com/contiv/vpp/blob/master/docs/arm64/MANUAL_INSTALL_ARM64.md>`_ to manually install Kubernetes with Contiv-VPP networking on one or more bare-metals of Aarch64 platform.
