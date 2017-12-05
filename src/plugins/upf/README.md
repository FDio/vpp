GTP-U User Plane Function (UPF) based on VPP
============================================

The GTP-UP plugins implements a GTP-U user plane based on 3GPP TS 23.214 and
3GPP TS 29.244 version 14.1.

Note: 3GPP Version 14.2+ changed the binary format of the PFCP protocol. The
      plugin has not yet been completely reviewed for required updates.

Working features:

* PFCP decoding of most (but not all IEs)
* PFCP heartbeat
* PFCP node related messages
* PFCP session related messages
* Uplink and Downlink Packet Detection Rules (PDR) and
  Forward Action Rules (FAR) -- (some parts)
* IPv4 -- inner and outer
* IPv6 -- inner and outer
* Usage Reporting Rules (URR)
* Sx Session Reports

No yet working:

* Buffer Action Rules (BAR)
* QoS Enforcement Rule (QER)

Limitations:

* does not work with DPDK plugin (the SDF ACLs use the DPDK ACL library,
  the plugin therefor call the DPDK initializers and this will clash
  with the DPDK plugin)
* FAR action with destination LI are not implemented

General limitations and known deficits:

* Error handling in Sx procedures is weak
* processing of Session Releated Procedures leaks memory from the messages
  and might leak memory from applying the rules to the session
* Session Deletion might leak memory
