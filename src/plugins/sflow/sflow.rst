.. _Sflow_agent:

.. toctree::

SFlow Monitoring Agent
======================

Overview
________

This plugin implements the random packet-sampling and interface
telemetry streaming required to support standard sFlow export
on Linux platforms. The overhead incurred by this monitoring is
minimal, so that detailed, real-time traffic analysis can be
achieved even under high load conditions, with visibility into
any fields that appear in the packet headers. If the VPP linux-cp
plugin is running then interfaces will be mapped to their
equivalent Linux tap ports.

Example Configuration
_____________________

::
    sflow sampling-rate 10000
    sflow polling-interval 20
    sflow header-bytes 128
    sflow enable GigabitEthernet0/8/0
    sflow enable GigabitEthernet0/9/0
    sflow enable GigabitEthernet0/a/0
    ...
    sflow enable GigabitEthernet0/a/0 disable

Detailed notes
______________

Each VPP worker that has at least one interface, will create a FIFO
and enqueues samples to it from the interfaces it is servicing that
are enabled. There is a process running in the main thread that will
dequeue the FIFOs periodically. If the FIFO is full, the worker will
drop samples, which helps ensure that (a) the main thread is not
overloaded with samples and (b) that individual workers and interfaces,
even when under high load, can't crowd out other interfaces and workers.

You can change the sampling-rate at runtime, but keep in mind that
it is a global variable that applies to workers, not interfaces.
This means that (1) all workers will sample at the same rate, and (2)
if there are multiple interfaces assigned to a worker, they'll share
the sampling rate which will undershoot, and similarly (3) if there
are multiple RX queues assigned to more than one worker, the effective
sampling rate will overshoot.

External Dependencies
_____________________

This plugin writes packet samples to the standard Linux netlink PSAMPLE
channel, so the kernel psample module must be loaded with modprobe or
insmod. As such, this plugin only works for Linux environments.

It also shares periodic interface counter samples vi netlink USERSOCK.
The host-sflow daemon, hsflowd, at https://sflow.net is one example of
a tool that will consume this feed and emit standard sFlow v5.
