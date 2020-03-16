GTP-U User Plane Function (UPF) based on VPP
============================================

Note: Upstream VPP README can be found [here](/README-VPP.md)

The UPF plugins implements a GTP-U user plane based on [3GPP TS 23.214][TS23214] and
[3GPP TS 29.244][TS29244] Release 15.

Current State
-------------

This UPF implementation is used in production in conjuction with [erGW][erGW] as
GGSN/PGW in multiple installation in several telecom operators (Tier 1 and smaller).

Working features
----------------

* PFCP protocol
  * en/decoding of most IEs
  * heartbeat
  * node related messages
  * session related messages
* Uplink and Downlink Packet Detection Rules (PDR) and
  Forward Action Rules (FAR) -- (some parts)
* IPv4 -- inner and outer
* IPv6 -- inner and outer
* Usage Reporting Rules (URR)
* PFCP Session Reports
* Linked Usage Reports

No yet working
--------------

* Buffer Action Rules (BAR)
* QoS Enforcement Rule (QER)

Limitations
-----------

* FAR action with destination LI are not implemented
* Ethernet bearer support

General limitations and known deficits
--------------------------------------

* Error handling in Sx procedures is weak

[erGW]: https://github.com/travelping/ergw
[TS23214]: http://www.3gpp.org/ftp/Specs/html-info/23214.htm
[TS29244]: http://www.3gpp.org/ftp/Specs/html-info/29244.htm
