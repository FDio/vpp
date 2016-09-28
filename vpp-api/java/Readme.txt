= JVpp

JVpp is JNI based Java API for VPP.

== Features
It is:

* Asynchronous
* Fully generated
* Lightweight

== Architecture

=== Plugin support

  /-------------\        /--------------\          /---------------\
  | JvppPlugin1 +<-------+ JVppRegistry +--------->+ VppConnection |
  \-------------/  inits \--+-----------/   uses   \---------------/
                            |
  /-------------\           |
  | JvppPlugin2 +<----------+ inits
  \-------------/           |
                            |
  ...                       |
                            |
  /----------\              |
  | JVppCore +<-------------+
  \----------/


VppRegistry opens connection to vpp (VppConnection) and manages jvpp plugins.
Each plugin needs to be registered in the VppRegistry. Registration involves
plugin initialization (providing JNI implementation with JVppCallback reference,
vpp client identifier and vpp shared memory queue address).

API user sends message by calling a method of appropriate plugin interface.
The call is delegated to JNI implementation provided by the particular plugin.
When JNI code receives reply, it invokes callback method of JVppCallback
that corresponds to the received message reply.

=== JVppCore as an example of JVpp plugin architecture

 JVpp Java

  /--------------\             /----------\          /------------\    /------\
  | JVppRegistry |             | JVppCore |          |  Callbacks |    | DTOs |
  \----+---------/             \----+-----/          \------+-----/    \------/
       ^                            ^                       ^
       | implements                 | implements            | implements
  /----+--------------\         /---+----------\      /-----+---------\
  | JVppRegistryImpl* +-------->+ JVppCoreImpl |      |  JVppCallback |
  \-------+-----------/  inits  \---+----------/      \-------+-------/
          |                          |                       ^
          |                          | uses                  | calls back
          |                          |                       |
----------|--------------------------|-----------------------|---------------------
          |                          |                       |
 C JNI    |                          +-------------------+   |       /-----------------\
          v                                              |   |   +-->+ jvpp_core_gen.h |
  /--------+--------\                                    |   |   |   \-----------------/
  | jpp_registry.c* +---+   /--------+----+----\         |   |   |
  \-----------------/   |   | << shared lib >> |        /-+--+---+------\
                        + ->+   jvpp_common*   <--------+  jvpp_core.c* |
                      uses  \------------------/  uses  \---------------/


* Components marked with an asterisk contain manually crafted code, which in addition
to generated classes form jvpp. Exception applies to Callbacks and DTOs, since there are
manually crafted marker interfaces in callback and dto package (dto/JVppRequest, dto/JVppReply,
dto/JVppDump, dto/JVppReplyDump, callback/JVppCallback)

Note: jvpp_core.c calls back the JVppCallback instance with every response. An instance of the
JVppCallback is provided to jvpp_core.c by JVppRegistryImpl on JVppCoreImpl initialization.

Part of the JVpp is also Future facade. It is asynchronous API returning Future objects
on top of low level JVpp. It wraps dump reply messages in one DTO using control_ping message
(provided by JVppRegistry).


Future facade

        /----------------\          /---------------\
        | FutureJVppCore |      +-->+ JVppRegistry* |
        \-----+----------/      |   \---------------/
              ^                 |
              | implements      | uses
              |                 |
     /--------+-------------\   |    /------------------------------\
     | FutureJVppCoreFacade +---+--->+ FutureJVppCoreFacadeCallback |
     \---------+------------/  uses  \-------+----------------------/
               |                             |
---------------|-----------------------------|-------------------------------
               | uses                        | implements
JVpp Java      |                             |
               |                             |
 /----------\  |                             |
 | JVppCore +<-+                             |
 \----+-----/                                |
      ^                                      |
      | implements                           v
 /----+---------\                   /--------+---------------\
 | JVppCoreImpl |                   | JVppCoreGlobalCallback |
 \--------------/                   \------------------------/



Another useful utility of the JVpp is Callback facade. It is asynchronous API
capable of calling specific callback instance (provided when performing a call)
per call.


Callback facade

        /------------------\          /---------------\
        | CallbackJVppCore |      +-->+ JVppRegistry* |
        \-----+------------/      |   \---------------/
              ^                   |
              | implements        | uses
              |                   |
     /--------+---------------\   |    /--------------------------\
     | CallbackJVppCoreFacade +---+--->+ CallbackJVppCoreCallback |
     \---------+--------------/  uses  \-----+--------------------/
               |                             |
---------------|-----------------------------|-------------------------------
               | uses                        | implements
JVpp Java      |                             |
               |                             |
 /----------\  |                             |
 | JVppCore +<-+                             |
 \----+-----/                                |
      ^                                      |
      | implements                           v
 /----+---------\                   /----------+-------------\
 | JVppCoreImpl |                   | JVppCoreGlobalCallback |
 \--------------/                   \------------------------/


== Package structure

* *io.fd.vpp.jvpp* - top level package for generated JVpp interface+ implementation and hand-crafted
VppConnection interface + implementation - packaged as jvpp-registry-version.jar

* *io.fd.vpp.jvpp.[plugin]* - top level package for generated JVpp interface + implementation
+ plugin's API tests - packaged as jvpp-[plugin]-version.jar

** *dto* - package for DTOs generated from VPP API structures + base/marker hand-crafted interfaces
(in case of jvpp-registry)
** *callback* - package for low-level JVpp callbacks and a global callback interface implementing each of
the low-level JVppcallbacks
** *future* - package for future based facade on top of JVpp and callbacks
** *callfacade* - package for callback based facade on top of JVpp and callbacks. Allowing
users to provide callback per request
** *test* - package for JVpp standalone tests. Can also serve as samples for JVpp.

C code is structured into modules:

* *jvpp_common* - shared library that provides jvpp_main_t reference used by jvpp_registry and plugins.

* *jvpp_registry* - native library used by JVppRegistryImpl, responsible for:

** VPP connection open/close
** Rx thread to java thread attach
** control ping message handling

* *jvpp_core* - native library used by jvpp core plugin:
** *jvpp_core.c* - contains hand crafted code for core plugin initialization
** *jvpp_core_gen.h* - contains generated JNI compatible handlers for all requests and replies defined in vpe.api

== Code generators
All of the required code except the base/marker interfaces is generated using
simple python2 code generators. The generators use __defs_vpp_papi.py__ input
file produced by __vppapigen__ from vpe.api file.

=== JNI compatible C code
Produces __jvpp_[plugin]_gen.h__ file containing JNI compatible handlers for each VPP
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
__JVpp[plugin]GlobalCallback.java__ aggregating all of the callback interfaces. The JNI
compatible C code expects only a single instance of this global callback and calls
it with every reply.

[NOTE]
====
Source: callback_gen.py
====

=== Future facade
Produces an asynchronous facade on top of JVpp and callbacks, which returns a Future that provides
matching reply once VPP invocation finishes. Sources produced:
__FutureJVpp[plugin].java, FutureJVpp[plugin]Facade.java and FutureJVpp[plugin]Callback.java__

[NOTE]
====
Source: jvpp_future_facade_gen.py
====

=== Callback facade
Similar to future facade, only this facade takes callback objects as part of the invocation
and the callback is called with result once VPP invocation finishes. Sources produced:
__CallbackJVpp[plugin].java, CallbackJVpp[plugin]Facade.java and CallbackJVpp[plugin]Callback.java__

[NOTE]
====
Source: jvpp_callback_facade_gen.py
====
