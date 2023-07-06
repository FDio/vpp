VPP API Language
================

The VPP binary API is a message passing API. The VPP API language is
used to define a RPC interface between VPP and its control plane. The
API messages supports shared memory transport and Unix domain sockets
(SOCK_STREAM).

The wire format is essentially that of a network formatted (big-endian)
packed C struct.

The VPP API compiler is located in *src/tools/vppapigen* and can
currently compile to JSON or C (used by the VPP binary itself).

Language definition
-------------------

Defining a messages
~~~~~~~~~~~~~~~~~~~

There are 3 types of message exchanges:

-  Request/Reply The client sends a request message and the server
   replies with a single reply message. The convention is that the reply
   message is named as method_name + \_reply.

-  Dump/Detail The client sends a “bulk” request message to the server,
   and the server replies with a set of detail messages. These messages
   may be of different type. A dump/detail call must be enclosed in a
   control ping block (Otherwise the client will not know the end of the
   bulk transmission). The method name must end with method + “\_dump”,
   the reply message should be named method + “\_details”. The exception
   here is for the methods that return multiple message types
   (e.g. sw_interface_dump). The Dump/Detail methods are typically used
   for acquiring bulk information, like the complete FIB table.

-  Events The client can register for getting asynchronous notifications
   from the server. This is useful for getting interface state changes,
   and so on. The method name for requesting notifications is
   conventionally prefixed with “want\_”. E.g. “want_interface_events”.
   Which notification types results from an event registration is
   defined in the service definition.

A message from a client must include the ‘client_index’, an opaque
cookie identifying the sender, and a ‘context’ field to let the client
match request with reply.

An example of a message definition. The client sends the show_version
request, the server replies with the show_version_reply.

The *client_index* and *context* fields are required in all requests.
The *context* is returned by the server and is used by the client to
match up request and reply messages.

.. code-block:: c

   define show_version
   {
     u32 client_index;
     u32 context;
   };
   define show_version_reply
   {
     u32 context;
     i32 retval;
     string program [32];
     string version [32];
     string build_date [32];
     /* The final field can be a variable length argument */
     string build_directory [];
   };

The flags are not used by the clients, but have special meaning for some
of the tracing and debugging of the API. The *autoreply* flag is a
shorthand for a reply message with just a *retval* field.

.. code-block:: c

       define : DEFINE ID '{' block_statements_opt '}' ';'
       define : flist DEFINE ID '{' block_statements_opt '}' ';'
       flist : flag
             | flist flag
       flag : MANUAL_PRINT
            | MANUAL_ENDIAN
            | DONT_TRACE
            | AUTOREPLY

       block_statements_opt : block_statements
       block_statements : block_statement
                        | block_statements block_statement
       block_statement : declaration
                       | option
       declaration : type_specifier ID ';'
                   | type_specifier ID '[' ID '=' assignee ']' ';'
       declaration : type_specifier ID '[' NUM ']' ';'
                   | type_specifier ID '[' ID ']' ';'
       type_specifier : U8
                      | U16
                      | U32
                      | U64
                      | I8
                      | I16
                      | I32
                      | I64
                      | F64
                      | BOOL
                      | STRING
       type_specifier : ID

Options
~~~~~~~

The *option* word is used to specify meta information. The only current
use is to specify a semantic version of the .api file itself.

Example:

.. code-block:: c

   option version = "1.0.0";

.. code-block:: c


       option : OPTION ID '=' assignee ';'
       assignee : NUM
                | TRUE
                | FALSE
                | STRING_LITERAL

Defining new types
~~~~~~~~~~~~~~~~~~

New user defined types are defined just like messages. A typedef has two
forms. It can either define an alias for a different type (or array).

Example:

.. code-block:: c

   typedef u8 ip4_address[4];
   typedef u8 ip6_address[16];

Where the above defines two new types *vl_api_ip4_address_t* and
*vl_api_ip6_address_t*. These are aliases for the underlying u8 array.

In the other form, it is used to specify an abstract data type.

.. code-block:: c

   enum address_family {
     ADDRESS_IP4 = 0,
     ADDRESS_IP6,
   };

   union address_union {
     vl_api_ip4_address_t ip4;
     vl_api_ip6_address_t ip6;
   };

   typedef address {
     vl_api_address_family_t af;
     vl_api_address_union_t un;
   };

Where the new type *vl_api_address_t*

.. code-block:: c

       typedef : TYPEDEF ID '{' block_statements_opt '}' ';'
       typedef : TYPEDEF declaration

Importing Definitions
~~~~~~~~~~~~~~~~~~~~~

You can use definitions from other .api files by importing them. To
import another .api’s definitions, you add an import statement to the
top of your file:

import “vnet/ip/ip_types.api”;

By default you can only use definitions from directly imported .api
files.

The API compiler searches for imported files in a set of directories
specified on the API compiler command line using the –includedir flag.

.. code-block:: c

   import : IMPORT STRING_LITERAL ';'

Comments
~~~~~~~~

The API language uses C style comments.

.. code-block:: c

   /* */
   //

Enumerations
~~~~~~~~~~~~

Enums are similar to enums in C.

Every enum definition must contain a constant that maps to zero as its
first element. This is because:

There must be a zero value, so that we can use 0 as a numeric default
value. The zero value needs to be the first element.

As in C, enums can be used as flags or just as numbers. The on-wire, and
in memory representation size of an enum can be specified. Not all
language bindings will support that. The default size is 4 (u32).

Example

.. code-block:: c

   enum ip_neighbor_flags
   {
     IP_API_NEIGHBOR_FLAG_NONE = 0,
     IP_API_NEIGHBOR_FLAG_STATIC = 0x1,
     IP_API_NEIGHBOR_FLAG_NO_FIB_ENTRY = 0x2,
   };

Which generates the vl_api_ip_neighbor_flags_t in the C binding. In
Python that is represented as an IntFlag object
VppEnum.vl_api_ip_neighbor_flags_t.

.. code-block:: c

       enum : ENUM ID '{' enum_statements '}' ';'
       enum : ENUM ID ':' enum_size '{' enum_statements '}' ';'
       enum_size : U8
                 | U16
                 | U32
       enum_statements : enum_statement
                       | enum_statements enum_statement
       enum_statement : ID '=' NUM ','
                      | ID ','

Services
~~~~~~~~

The service statement defines the relationship between messages. For
request/response and dump/details messages it ties the request with the
reply. For events, it specifies which events that can be received for a
given ``want_*`` call.

Example:

.. code-block:: c

   service {
     rpc want_interface_events returns want_interface_events_reply
       events sw_interface_event;
   };

Which states that the request want_interface_events returns a
want_interface_events_reply and if enabled the client will receive
sw_interface_event messages whenever interface states changes.

.. code-block:: c

       service : SERVICE '{' service_statements '}' ';'
       service_statements : service_statement
                       | service_statements service_statement
       service_statement : RPC ID RETURNS NULL ';'
                            | RPC ID RETURNS ID ';'
                            | RPC ID RETURNS STREAM ID ';'
                            | RPC ID RETURNS ID EVENTS event_list ';'
       event_list : events
                  | event_list events
       events : ID
              | ID ','

Types
-----

Scalar Value Types
~~~~~~~~~~~~~~~~~~

========= ======== =============== ===========
.api type size     C type          Python type
========= ======== =============== ===========
i8        1        i8              int
u8        1        u8              int
i16       2        i16             int
u16       2        u16             int
i32       4        i32             int
u32       4        u32             int
i64       8        i64             int
u64       8        u64             int
f64       8        f64             float
bool      1        bool            boolean
string    variable vl_api_string_t str
========= ======== =============== ===========

User Defined Types
~~~~~~~~~~~~~~~~~~

vnet/ip/ip_types.api
^^^^^^^^^^^^^^^^^^^^

+--------------------+--------+-------------+-------------------------+
| .api type          | size   | C type      | Python type             |
+====================+========+=============+=========================+
| vl_api_address_t   | 20     | vl_ap       | `                       |
|                    |        | i_address_t | `<class 'ipaddress.IPv4 |
|                    |        |             | Address'> or <class 'ip |
|                    |        |             | address.IPv6Address'>`` |
+--------------------+--------+-------------+-------------------------+
| vl                 | 4      | vl_api_ip   | ``<class 'ip            |
| _api_ip4_address_t |        | 4_address_t | address.IPv4Address'>`` |
+--------------------+--------+-------------+-------------------------+
| vl                 | 16     | vl_api_ip   | ``<class 'ip            |
| _api_ip6_address_t |        | 6_address_t | address.IPv6Address'>`` |
+--------------------+--------+-------------+-------------------------+
| vl_api_prefix_t    | 21     | vl_a        | `                       |
|                    |        | pi_prefix_t | `<class 'ipaddress.IPv4 |
|                    |        |             | Network'> or <class 'ip |
|                    |        |             | address.IPv6Network'>`` |
+--------------------+--------+-------------+-------------------------+
| v                  | 5      | vl_api_i    | ``<class 'ip            |
| l_api_ip4_prefix_t |        | p4_prefix_t | address.IPv4Network'>`` |
+--------------------+--------+-------------+-------------------------+
| v                  | 17     | vl_api_i    | ``<class 'ip            |
| l_api_ip6_prefix_t |        | p6_prefix_t | address.IPv6Network'>`` |
+--------------------+--------+-------------+-------------------------+
| vl_api_ip4_add     | 5      | vl_api_ip4  | ``<class 'ipad          |
| ress_with_prefix_t |        | _address_wi | dress.IPv4Interface'>`` |
|                    |        | th_prefix_t |                         |
+--------------------+--------+-------------+-------------------------+
| vl_api_ip6_add     | 17     | vl_api_ip6  | ``<class 'ipad          |
| ress_with_prefix_t |        | _address_wi | dress.IPv6Interface'>`` |
|                    |        | th_prefix_t |                         |
+--------------------+--------+-------------+-------------------------+

vnet/ethernet/ethernet_types.api
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

+---------------------+------+---------------------+-------------------+
| .api type           | size | C type              | Python type       |
+=====================+======+=====================+===================+
| ``vl_               | 6    | ``vl_               | ``class 'vpp_pa   |
| api_mac_address_t`` |      | api_mac_address_t`` | pi.MACAddress'>`` |
+---------------------+------+---------------------+-------------------+

vnet/interface_types.api
^^^^^^^^^^^^^^^^^^^^^^^^

======================== ==== ======================== ===========
.api type                size C type                   Python type
======================== ==== ======================== ===========
vl_api_interface_index_t 4    vl_api_interface_index_t int
======================== ==== ======================== ===========

New explicit types
~~~~~~~~~~~~~~~~~~

String versus bytes
^^^^^^^^^^^^^^^^^^^

A byte string with a maximum length of 64:

.. code-block:: c

   u8 name[64];

Before the “string” type was added, text string were defined like this.
The implications of that was the user would have to know if the field
represented a \\0 ended C-string or a fixed length byte string. The wire
format of the ‘string’ type is a u32 length

An IPv4 or IPv6 address was previously defined like:

.. code-block:: c

   u8 is_ip6;
   u8 address[16];

Which made it hard for language bindings to represent the address as
anything but a byte string. The new explicit address types are shown
above.

Language generators
-------------------

The VPP API compiler currently has two output modules. One generating
JSON and one generating C header files that are directly used by the VPP
infrastructure and plugins.

The C/C++, Python, Go Lua, and Java language bindings are generated
based on the JSON files.

Future considerations
~~~~~~~~~~~~~~~~~~~~~

-  Generate C/C++ (vapi) client code directly from vppapigen
-  Embed JSON definitions into the API server, so dynamic languages
   can download them directly without going via the filesystem and JSON
   files.

API Change Process
------------------

Purpose
~~~~~~~

To minimize the disruptions to the consumers of the VPP API, while permitting
the innovation for the VPP itself.

Historically, API changes in VPP master branch were allowed at any point in time
outside of a small window between the API freeze milestone and RC1 milestone.
The API changes on the throttle branches were not permitted at all. This model
proved workable, however all the production use cases ended up on throttle
branches, with a lot of forklift activity when it is the time to upgrade to the
next branch.

This formally structured API change process harmonizes the behavior across all
the VPP branches, and allows more flexibility for the consumer, while permitting
the innovation in the VPP itself.

The Core Promise
~~~~~~~~~~~~~~~~

"If a user is running a VPP version N and does not use any deprecated APIs, they
should be able to simply upgrade the VPP to version N+1 and there should be no
API breakage".

In-Progress, Production and Deprecated APIs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This proposal adds a classification of stability of an API call:

-   "In-Progress": APIs in the process of the development, experimentation, and
    limited testing.

-   "Production": tested as part of the "make test", considered stable for general
    usage.

-   "Deprecated": used as a flag on Production APIs which are slated to be
    deprecated in the future release.

The "In-Progress" APIs or the APIs with the semantic version of 0.x.y are not
subject to any stability checks, thus the developers are free to introduce them,
modify their signatures, and as well remove them completely at will. The users
should not use the in-progress APIs without the interactions with its
maintainers, nor base the production code on those APIs. The goal of
"in-progress" APIs to allow rapid iteration and modifications to ensure the API
signature and function is stabilized. These API calls may be used for testing or
experimentation and prototyping.

When the maintainer is satisfied with the quality of the APIs, and ensures that
they are tested as part of the "Make test" runs, they can transition their
status to "Production".

The "Production" APIs can *NOT* be changed in any way that modifies their
representation on the wire and the signature (thus CRC). The only change that
they may incur is to be marked as "Deprecated". These are the APIs that the
downstream users can use for production purposes. They exist to fulfill a core
promise of this process: The "Deprecated" APIs are the "Production" APIs that
are about to be deleted. To ensure the above core promise is maintained, if the
API call was marked as deprecated at any point between RC1 of release N and RC1
of release N+1, it MUST NOT be deleted until the RC1 milestone of the
release N+2. The deprecated API SHOULD specify a replacement API - which MUST
be a Production API, so as not to decrease the level of stability.


The time interval between a commit that marks an API as deprecated and a commit
that deletes that API MUST be at least equal the time between the two subsequent
releases (currently 4 months).


Doing so allows a for a good heads-up to those who are using the
"one free upgrade" property to proactively catch and test the transition from
the deprecated APIs using the master.


Marking an API as deprecated just 1 day before RC1 branch pull and then deleting
that API one day after does *technically* satisfy "one free upgrade" promise,
but is rather hostile to the users that are proactively tracking it.

Semantic API Versioning
~~~~~~~~~~~~~~~~~~~~~~~

VPP APIs use semantic versioning according to semver.org, with the compatibility
logic being applied at the moment the messages are marked as deprecated.

To discuss: i.e. if message_2 is being introduced which deprecates the
message_1, then that same commit should increase the major version of the API.

The 0.x.x API versions, by virtue of being in-progress, are exempt from this
treatment.

Tooling
~~~~~~~

See https://gerrit.fd.io/r/c/vpp/+/26881:

crcchecker.py is a tool to enforce the policy, with a few other bonus uses:

extras/scripts/crcchecker.py --check-patchset # returns -1 if backwards incompatible extras/scripts/crcchecker.py --dump-manifest extras/scripts/crcchecker.py --git-revision v20.01 <files> extras/scripts/crcchecker.py -- diff <oldfile> <newfile>

Notice that you can use this tool to get the list of API changes since a given past release.

The policy:

.. highlight:: none

.. code-block::

  1. Production APIs should never change.
     The definition of a "production API" is if the major version in
     the API file is > 0 that is not marked as "in-progress".
  2. APIs that are experimental / not released are not checked.
     An API message can be individually marked as in progress,
     by adding the following in the API definition:
        option in_progress;
  3. An API can be deprecated in three-to-six steps (the steps
     with letters can be combined or split, depending on situation):
        Step 1a: A new "in-progress" API new_api_2 is added that
           is deemed to be a replacement.
        Step 1b: The existing API is marked as "replaced_by" this new API:
           option replaced_by="new_api_2";
        Step 2a: The new_api_2 is marked as production by deleting its in-progress status,
           provided that this API does have sufficient test coverage to deem it well tested.
        Step 2b: the existing API is marked as "deprecated":
           option deprecated="optional short message to humans reading it";
        Step 3: the deprecated API is deleted.

There is a time constraint that the minimum interval between the steps 2 and 3
must be at least 4 months. The proposal is to have step 2 around a couple of
weeks before the F0 milestone for a release, as triggered by the release manager
(and in the future by an automated means).

Use Cases
~~~~~~~~~

Adding A New Field To A Production API
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The simplest way to add a new field to a Production API message *foo_message* is
to create a new In-Progress message *foo_message_v2*, and add the field to that
one. Typically it will be an extension - so the API message handlers are
trivially chained. If there are changes/adjustments that are needed, this new
message can be freely altered without bothering the users of the Production API.

When the maintainer is happy with the quality of the implementation, and the
foo_message_v2 is tested in "make test" to the same extent as the foo_message,
they can make two commits: one, removing the in-progress status for
foo_message_v2, and the second one - deprecating foo_message and pointing the
foo_message_v2 as the replacement. Technically after the next throttle pull,
they can delete the foo_message - the deprecation and the replacement will be
already in the corresponding branch.

Rapid Experimentation For A New Feature
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Add a message that is in-progress, and keep iterating with this message. This
message is not subject to the change control process.

An In-progress API Accidentally Marked As "production"
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This is expected to mainly apply during the initial period of 20.05->20.09, the
proposal is to have it active for 4 weeks from Jun 17 till July 15th, with the
following process.

If a developer finds that a given API or a set of APIs is not ready for
production due to lack of tests and/or the general API stability, then they:

-   Create a new gerrit change with *just* the marking of the API as
    in_progress, subject being: "api: <feature> api message downgrade" and
    a comment identifying which APIs are being downgraded and why.

-   Add ayourtch@gmail.com or the current Release Manager as a reviewer --
    for help in guiding the process and to ensure that the gerrit change is not
    forgotten.

-   Send an email to vpp-dev mailing list with the subject being the same as the
    one-liner commit message, reference to the gerrit change, and the reasoning.

-   Wait for the timeout period of two weeks for the feedback.

-   If no feedback received, assume the community agreement and commit the
    change to master branch.

This needs to be highlighted that this process is an *exception* - normally the
transition is always in_progress => production => deprecated.

API Change Examples
~~~~~~~~~~~~~~~~~~~

https://gerrit.fd.io/r/q/+is:merged+message:%2522%255Eapi:.*%2524%2522
