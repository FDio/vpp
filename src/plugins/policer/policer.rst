.. _policer:

Policing
========

VPP implements several policer types, that don't always conform
to the related RFCs [#rfc2697]_ [#rfc2698]_ [#rfc4115]_.
Only policers implemented in VPP will be presented, along with
the differences they have compared to RFCs.

.. contents:: :local:
   :depth: 1


1 rate 2 color (1r2c)
---------------------

This is the most straightforward policer. There is no RFC describing it,
however we can found its description in many documentation [#juniper]_ [#cisco]_ .

A 1r2c policer is great to classify incoming packets into two categories:
conforming packets (said green), and violating ones (said red).

Parameters
~~~~~~~~~~

To set-up such a policer, only two parameters are needed:

Committed Information Rate (CIR)
  Given in bytes per second, this parameter is the average
  throughput allowed by the policer.

  It sets the limit between conforming arriving packets (those making the
  traffic fall below the CIR), and violating arriving packets
  (those making the traffic exceed the CIR).

Committed Burst Size (CBS)
  It represents the size (in bytes) of a token bucket used to allow
  some burstiness from the incoming traffic.

.. figure:: /_images/policer-1r2c-bucket.png
   :align: center
   :scale: 25%

   Figure 1: 1r2c bucket filling logic

The committed token bucket (C) is filling up at CIR tokens (bytes)
per second, up to CBS tokens. All overflowing tokens are lost.

Color-Blind algorithm
~~~~~~~~~~~~~~~~~~~~~

.. image:: /_images/policer-1r2c-blind.png
   :align: center
   :scale: 75%

|

Color-Aware algorithm
~~~~~~~~~~~~~~~~~~~~~

In online documentation, there is no trace of a color-aware 1r2c policer.
However, VPP implementation allows such a thing.

.. image:: /_images/policer-1r2c-aware.png
   :align: center
   :scale: 75%

|


1 rate 3 color (1r3c) RFC 2697 [#rfc2697]_
------------------------------------------

As for the `1 rate 2 color (1r2c)`_ policer, only one rate parameters is required
to setup a 1r3c policer. However, such a policer adds another kind of packet category:
exceeding ones (said yellow).

Parameters
~~~~~~~~~~

To set-up such a policer, three parameters are needed:

Committed Information Rate (CIR)
  As in the `1 rate 2 color (1r2c)`_ policer.

Committed Burst Size (CBS)
  As in the `1 rate 2 color (1r2c)`_ policer.

Excess Burst Size (EBS)
  It represents the size (in bytes) of a second token bucket used
  to allow an additional burstiness from the incoming traffic, when
  traffic as been below the CIR for some time.

.. figure:: /_images/policer-1r3c-bucket.png
   :align: center
   :scale: 25%

   Figure 2: 1r3c buckets filling logic

The committed token bucket (C) is filling up at CIR tokens (bytes)
per second, up to CBS tokens. When C is full, tokens are overflowing
into the excess token bucket (E), up to EBS tokens. Only overflowing
tokens from E are lost.

Color-Blind algorithm
~~~~~~~~~~~~~~~~~~~~~

.. image:: /_images/policer-1r3c-blind.png
   :align: center
   :scale: 75%

|

Color-Aware algorithm
~~~~~~~~~~~~~~~~~~~~~

.. image:: /_images/policer-1r3c-aware.png
   :align: center
   :scale: 75%

|

Notes
~~~~~

In the RFC 2697 [#rfc2697]_ describing the 1r3c policer, conforming (green) packets
only consume tokens from the token bucket C. Whereas, in VPP, they also consume tokens from E.

One way to stick to the RFC is then to set the EBS parameter to be superior to CBS, so that
EBS - CBS corresponds to the EBS from the RFC.

However, VPP does not enforce setting EBS > CBS, which could result in undesired behavior.

2 rate 3 color (2r3c) RFC 2698 [#rfc2698]_
------------------------------------------

Instead of setting the limit between yellow and red packets in terms of bursts,
as it is done by `1 rate 3 color (1r3c) RFC 2697`_ policers, two rate policers introduce
another rate parameter to discriminate between those two kinds of packets.

Parameters
~~~~~~~~~~

To set-up such a policer, four parameters are needed:

Committed Information Rate (CIR)
  As in the `1 rate 2 color (1r2c)`_ policer.

Committed Burst Size (CBS)
  As in the `1 rate 2 color (1r2c)`_ policer.

Peak Information Rate (PIR)
  Given in bytes per second, this parameter is the average
  throughput allowed by the policer when there is a peak in
  traffic.

  It sets a second limit between exceeding arriving packets
  (those making the traffic fall below the PIR, but above CIR),
  and violating arriving packets (those making the traffic exceed the PIR).

Peak Burst Size (PBS)
  It represents the size (in bytes) of a second token bucket used
  to allow an additional peak traffic.

.. figure:: /_images/policer-2r3c-bucket.png
   :align: center
   :scale: 25%

   Figure 2: 2r3c-rfc2698 buckets filling logic

The committed token bucket (C) is filling up at CIR tokens (bytes)
per second, up to CBS tokens. In the meantime, the peak token bucket (P)
is filling up at PIR tokens per second, up to PBS. All overflowing tokens
from C and P are lost.

Color-Blind algorithm
~~~~~~~~~~~~~~~~~~~~~

.. image:: /_images/policer-2r3c-blind.png
   :align: center
   :scale: 75%

|

Color-Aware algorithm
~~~~~~~~~~~~~~~~~~~~~

.. image:: /_images/policer-2r3c-aware.png
   :align: center
   :scale: 50%

|

Notes
~~~~~

To have a working policer, the condition PIR >= CIR needs to hold.
Indeed, since we assume that peak traffic should have a greater
rate than committed ones.


2 rate 3 color (2r3c) RFC 4115 [#rfc4115]_
------------------------------------------

The 2r3c-RFC4115 is an allowed choice by VPP. However, there is currently
no implementation of such a policer. Hence, the only two rate policer VPP
implements is the `2 rate 3 color (2r3c) RFC 2698`_ policer.


.. rubric:: References:

.. [#juniper] https://www.juniper.net/documentation/us/en/software/junos/traffic-mgmt-nfx/routing-policy/topics/concept/tcm-overview-cos-qfx-series-understanding.html
.. [#cisco] https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/qos_mqc/configuration/xe-16-8/qos-mqc-xe-16-8-book/qos-pkt-policing.html
.. [#rfc2697] https://www.rfc-editor.org/rfc/rfc2697.html
.. [#rfc2698] https://www.rfc-editor.org/rfc/rfc2698.html
.. [#rfc4115] https://www.rfc-editor.org/rfc/rfc4115.html
