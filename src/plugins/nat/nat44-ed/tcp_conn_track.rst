NAT44ED TCP connection tracking
===============================

TCP connection tracking in endpoint-dependent NAT is based on RFC 7857
and RFC 6146, which RFC 7857 references.

See RFC 7857 for the original graph - our graph is slightly different,
allowing creation of new session, while an old session is in transitory
timeout after seeing FIN packets from both sides:

After discussion on vpp-dev and with Andrew Yourtschenko we agreed that
it's friendly behaviour to allow creating a new session while the old
one is closed and in transitory timeout. The alternative means VPP is
insisting that a 5-tuple connection cannot be created while an old one
is finished and timing out. There is no apparent reason why our change
would break anything and we agreed that it could only help users.

::


                  +------------transitory timeout----------------+
                  |                                              |
                  |                           +-------------+    |
                  |       session created---->+    CLOSED   |    |
                  |                           +-------------+    |
                  |                             |         |      |
+-----+           |                            SYN       SYN     |
|     v           v                           IN2OUT   OUT2IN    |
| +->session removed                            |         |      |
| |  ^ ^    ^  ^  ^                             v         v      |
| |  | |    |  |  |                         +-------+ +-------+  |
| |  | |    |  |  +----transitory timeout---+SYN_I2O| |SYN_O2I+--+
| |  | |    |  |              +---------+   |-------| |-------|
| |  | |    |  +-transitory---+RST_TRANS|       |         |
| |  | |    |      timeout    +---------+      SYN       SYN
| |  | |    |                   |    ^       OUT2IN     IN2OUT
| |  | |    |                   |    |          |         |
| |  | |    |                   |    |          v         v
| |  | |    |                   |    |         +-----------+
| |  | |    |                   |    +--RST----+ESTABLISHED+<-SYN IN2OUT-+
| |  | |    |                   |              +-----------+             |
| |  | |    |                   +---data pkt-----^ | | |   ^             |
| |  | |    |                                      | | |   |             |
| |  | |    +----established timeout---------------+ | |   |             |
| |  | |                                             | |   |             |
| |  | |                    +-----FIN IN2OUT---------+ |   |             |
| |  | |                    v                          |   |             |
| |  | |                +-------+     +--FIN OUT2IN----+   |             |
| |  | +--established---+FIN_I2O|     |                    |             |
| |  |      timeout     +-------+     v       +-SYN OUT2IN-+             |
| |  |                      |     +-------+   |                          |
| |  +----established-------------+FIN_O2I| +--------------+             |
| |         timeout         |     +-------+ |REOPEN_SYN_I2O| +--------------+
| |                         |         |     +--------------+ |REOPEN_SYN_O2I|
| |                        FIN       FIN             ^  |    +--------------+
| |                      OUT2IN     IN2OUT           |  |           ^  |
| |                         |         |              |  |           |  |
| |                         v         v              |  |           |  |
| |                       +-------------+            |  |           |  |
| +--transitory timeout---+  FIN_TRANS  +-SYN IN2OUT-+  |           |  |
|                         +-------------+               |           |  |
|                                |                      |           |  |
|                                +--------SYN OUT2IN----|-----------+  |
|                                                       v              |
+------------------transitory timeout-------------------+<-------------+
