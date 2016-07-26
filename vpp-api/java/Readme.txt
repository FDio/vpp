= JVpp

JVpp is JNI based Java API for VPP.

== Features
It is:

* Asynchronous
* Fully generated
* Lightweight

== Architecture

FIXME: update the file after plugin support is merged
Current architecture is documented on the wiki page:
https://wiki.fd.io/view/VPP/Java_API/Plugin_support

JVpp and JNI


 JVpp Java

  /----------\             /--------\          /------------\    /------\
  | VppConn* |             |  JVpp  |          |  Callbacks |    | DTOs |
  \----+-----/             \----+---/          \------+-----/    \------/
       ^                        ^                     ^
       | implements             | implements          | implements
  /----+---------\         /----+-------\      /------+-----------\
  | VppConnImpl* +<--------+  JVppImpl  |      |  GlobalCallback  |
  \--------------/   uses  \---+--------/      \-------+----------/
                               |                       ^
                               | uses                  | calls back
                               |                       |
-------------------------------|-----------------------|---------------------
                               |                       |
                               |       +---------------+
 C JNI                         |       |
                               v       |              /------------\
                           /---+-------+--\     +---->+   jvpp.h*  |
                           |              +-----+     \------------/
                           |    jvpp.c*   |
                           |              +-----+     /------------\
                           \--------------/     +---->+ jvpp_gen.h |
                                                      \------------/

* Components marked with an asterisk contain manually crafted Java code, which in addition
to generated classes form jvpp. Exception applies to Callbacks and DTOs, since there are
manually crafted marker interfaces in callback and dto package (dto/JVppRequest, dto/JVppReply,
dto/JVppDump, dto/JVppReplyDump, callback/JVppCallback)

Note: jvpp.c calls back the GlobalCallback instance with every response. An instance of the
GlobalCallback is provided to jvpp.c by VppConnImpl while connecting to VPP.

Part of the JVpp is also Future facade. It is asynchronous API returning Future objects
on top of low level JVpp.


Future facade

        /-------------\           /--------------------\
        | FutureJVpp* |       +-->+ FutureJVppRegistry |
        \-----+-------/       |   \----------+---------/
              ^               |              ^
              | implements    | uses         | uses
              |               |              |
     /--------+----------\    |   /----------+---------\
     | FutureJVppFacade* +----+   | FutureJVppCallback |
     \---------+---------/        \----------+---------/
               |                             |
---------------|-----------------------------|-------------------------------
               | uses                        | implements
JVpp Java      |                             |
               |                             |
 /---------\   |                             |
 |   JVpp  +<--+                             |
 \----+----/                                 |
      ^                                      |
      | implements                           v
 /----+-------\                   /----------+-------\
 |  JVppImpl  |                   |  GlobalCallback  |
 \------------/                   \------------------/



Another useful utility of the JVpp is Callback facade. It is asynchronous API
capable of calling specific callback instance (provided when performing a call)
per call.


Callback facade

        /--------------\            /----------------------\
        | CallbackJVpp |        +-->+ CallbackJVppRegistry |
        \-----+--------/        |   \----------+-----------/
              ^                 |              ^
              | implements      | uses         | uses
              |                 |              |
     /--------+-----------\     |   /----------+-----------\
     | CallbackJVppFacade +-----+   | CallbackJVppCallback |
     \---------+----------/         \----------+-----------/
               |                             |
---------------|-----------------------------|-------------------------------
               | uses                        | implements
JVpp Java      |                             |
               |                             |
 /---------\   |                             |
 |   JVpp  +<--+                             |
 \----+----/                                 |
      ^                                      |
      | implements                           v
 /----+-------\                   /----------+-------\
 |  JVppImpl  |                   |  GlobalCallback  |
 \------------/                   \------------------/



== Package structure

* *org.openvpp.jvpp* - top level package for generated JVpp interface+ implementation and hand-crafted
VppConnection interface + implementation

** *dto* - package for DTOs generated from VPP API structures + base/marker hand-crafted interfaces
** *callback* - package for low-level JVpp callbacks and a global callback interface implementing each of the low-level JVppcallbacks
** *future* - package for future based facade on top of JVpp and callbacks
** *callfacade* - package for callback based facade on top of JVpp and callbacks. Allowing
users to provide callback per request
** *test* - package for JVpp standalone tests. Can also serve as samples for JVpp.

C code is structured into 3 files:

* *jvpp.c* - includes jvpp.h and jvpp_gen.h + contains hand crafted code for:

** VPP connection open/close
** Rx thread to java thread attach
** Callback instance store
* *jvpp.h* - contains hand-crafted macros and structures used by jvpp.c
* *jvpp_gen.h* - contains JNI compatible handlers for each VPP request and reply

== Code generators
All of the required code except the base/marker interfaces is generated using
simple python2 code generators. The generators use __defs_vpp_papi.py__ input
file produced by __vppapigen__ from vpe.api file.

=== JNI compatible C code
Produces __jvpp_gen.h__ file containing JNI compatible handlers for each VPP
request and reply.

[NOTE]
====
Source: jvpp_c_gen.py
====

=== Request/Reply DTOs
For all the structures in __defs_vpp_papi.py__ a POJO DTO is produced. Logically,
there are 4 types of DTOs:

* Request - requests that can be sent to VPP and only a single response is expected
* DumpRequest - requests that can be sent to VPP and a stream of responses is expected
* Reply - reply to a simple request or a single response from dump triggered response stream
* ReplyDump - collection of replies from a single dump request
* Notifications/Events - Not implemented yet

[NOTE]
====
Source: dto_gen.py
====

=== JVpp
Produces __JVpp.java__ and __JVppImpl.java__. This is the layer right above JNI compatible C
code.

[NOTE]
====
Source: jvpp_impl_gen.py
====

=== Callbacks
Produces callback interface for each VPP reply + a global callback interface called
__JVppGlobalCallback.java__ aggregating all of the callback interfaces. The JNI
compatible C code expects only a single instance of this global callback and calls
it with every reply.

[NOTE]
====
Source: callback_gen.py
====

=== Future facade
Produces an asynchronous facade on top of JVpp and callbacks, which returns a Future that provides
matching reply once VPP invocation finishes. Sources produced:
__FutureJVpp.java, FutureJVppFacade.java and FutureJVppCallback.java__

[NOTE]
====
Source: jvpp_future_facade_gen.py
====

=== Callback facade
Similar to future facade, only this facade takes callback objects as part of the invocation
and the callback is called with result once VPP invocation finishes. Sources produced:
__CallbackJVpp.java, CallbackJVppFacade.java and CallbackJVppCallback.java__

[NOTE]
====
Source: jvpp_callback_facade_gen.py
====
