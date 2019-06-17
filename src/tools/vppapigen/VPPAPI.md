# VPP API Language    {#api_lang_doc}

The VPP binary API is a message passing API.
The VPP API language is used to define a RPC interface between VPP and its
control plane. The API messages supports shared memory transport and
Unix domain sockets (SOCK_STREAM).

The wire format is essentially that of a packed C struct.

The VPP API compiler is located in *src/tools/vppapigen* and can currently
compile to JSON or C (used by the VPP binary itself).

## Language definition

### Defining a messages

There are 3 types of message exchanges:

* Request/Reply
The client sends a request message and the server replies with a
single reply message. The convention is that the reply message is
named as method_name + \_reply.

* Dump/Detail
The client sends a "bulk" request message to the server, and the
server replies with a set of detail messages. These messages may be of
different type. A dump/detail call must be enclosed in a control ping
block (Otherwise the client will not know the end of the bulk
transmission). The method name must end with method + "\_dump", the
reply message should be named method + "\_details". The exception here
is for the methods that return multiple message types
(e.g. sw_interface_dump). The Dump/Detail methods are typically used
for acquiring bulk information, like the complete FIB table.

* Events
The client can register for getting asynchronous notifications from
the server. This is useful for getting interface state changes, and so
on. The method name for requesting notifications is conventionally
prefixed with "want_". E.g. "want_interface_events". Which
notification types results from an event registration is defined in
the service definition.

A message from a client must include the 'client_index', an opaque
cookie identifying the sender, and a 'context' field to let the client
match request with reply.

An example of a message definition. The client sends the show_version request,
the server replies with the show_version_reply.

The *client_index* and *context* fields are required in all requests.
The *context* is returned by the server and is used by the client to
match up request and reply messages.

```
define show_version
{
  u32 client_index;
  u32 context;
};
define show_version_reply
{
  u32 context;
  i32 retval;
  string program [limit = 32];
  string version [limit = 32];
  string build_date [limit = 32];
  string build_directory [limit = 256];
};

```

The flags are not used by the clients, but have special meaning
for some of the tracing and debugging of the API.
The *autoreply* flag is a shorthand for a reply message with just a
*retval* field.

```
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
```


### Options
The *option* word is used to specify meta information.
The only current use is to specify a semantic version of the .api file itself.

Example:
```
option version = "1.0.0";
```

```

    option : OPTION ID '=' assignee ';'
    assignee : NUM
             | TRUE
             | FALSE
             | STRING_LITERAL
```

### Defining new types

New user defined types are defined just like messages.
A typedef has two forms. It can either define an alias for a
different type (or array).

Example:

```
typedef u8 ip4_address[4];
typedef u8 ip6_address[16];
```

Where the above defines two new types *vl_api_ip4_address_t* and
*vl_api_ip6_address_t*. These are aliases for the underlaying
u8 array.

In the other form, it is used to specify an abstract data type.

```
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
```

Where the new type *vl_api_address_t*

```
    typedef : TYPEDEF ID '{' block_statements_opt '}' ';'
    typedef : TYPEDEF declaration
```


### Importing Definitions
You can use definitions from other .api files by importing them.
To import another .api's definitions, you add an import statement
to the top of your file:

import "vnet/ip/ip_types.api";

By default you can only use definitions from directly imported .api files.

The API compiler searches for imported files in a set of directories
specified on the API compiler command line using the --includedir flag.
```
import : IMPORT STRING_LITERAL ';'
```

### Comments

The API language uses C style comments.
```
/* */
//
```

### Enumerations
Enums are similar to enums in C.

Every enum definition must contain a constant that maps to zero
as its first element. This is because:

There must be a zero value, so that we can use 0 as a numeric default value.
The zero value needs to be the first element.

As in C, enums can be used as flags or just as numbers.
The on-wire, and in memory representation size of an enum can be specified.
Not all language bindings will support that. The default size is 4 (u32).

Example
```
enum ip_neighbor_flags
{
  IP_API_NEIGHBOR_FLAG_NONE = 0,
  IP_API_NEIGHBOR_FLAG_STATIC = 0x1,
  IP_API_NEIGHBOR_FLAG_NO_FIB_ENTRY = 0x2,
};
```

Which generates the vl_api_ip_neighbor_flags_t in the C binding.
In Python that is represented as an IntFlag object
VppEnum.vl_api_ip_neighbor_flags_t.

```
    enum : ENUM ID '{' enum_statements '}' ';'
    enum : ENUM ID ':' enum_size '{' enum_statements '}' ';'
    enum_size : U8
              | U16
              | U32
    enum_statements : enum_statement
                    | enum_statements enum_statement
    enum_statement : ID '=' NUM ','
                   | ID ','
```

### Services
The service statement defines the relationship between messages.
For request/response and dump/details messages it ties the
request with the reply. For events, it specifies which events
that can be received for a given want_* call.

Example:
```
service {
  rpc want_interface_events returns want_interface_events_reply
    events sw_interface_event;
};

```

Which states that the request want_interface_events returns a
want_interface_events_reply and if enabled the client will
receive sw_interface_event messages whenever interface states changes.

```
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
```


## Types
### Scalar Value Types

.api type|size|C type|Python type
---------|----|------------------
i8       |   1|i8    |int
u8       |   1|u8    |int
i16      |   2|i16   |int
u16      |   2|u16   |int
i32      |   4|i32   |int
u32      |   4|u32   |int
i64      |   8|i64   |int
u64      |   8|u64   |int
f64      |   8|f64   |float
bool     |   1|bool  |boolean
string   |variable|vl_api_string_t|str

### User Defined Types
#### vnet/ip/ip_types.api

.api type|size|C type|Python type
---------|----|------|-----------
vl_api_address_t|20|vl_api_address_t|`<class 'ipaddress.IPv4Address'> or <class 'ipaddress.IPv6Address'>`
vl_api_ip4_address_t|4|vl_api_ip4_address_t|`<class 'ipaddress.IPv4Address'>`
vl_api_ip6_address_t|16|vl_api_ip6_address_t|`<class 'ipaddress.IPv6Address'>`
vl_api_prefix_t|21|vl_api_prefix_t|`<class 'ipaddress.IPv4Network'> or <class 'ipaddress.IPv6Network'>`
vl_api_ip4_prefix_t|5|vl_api_ip4_prefix_t|`<class 'ipaddress.IPv4Network'>`
vl_api_ip6_prefix_t|17|vl_api_ip6_prefix_t|`<class 'ipaddress.IPv6Network'>`

#### vnet/ethernet/ethernet_types.api
.api type|size|C type|Python type
---------|----|------|-----------
vl_api_mac_address_t|6|vl_api_mac_address_t|`class 'vpp_papi.MACAddress'>`

#### vnet/interface_types.api
.api type|size|C type|Python type
---------|----|------|-----------
vl_api_interface_index_t|4|vl_api_interface_index_t|int

### New explicit types

#### String versus bytes
A byte string with a maximum length of 64:
```
u8 name[64];
```
Before the "string" type was added, text string were defined like this.
The implications of that was the user would have to know if the field
represented a \0 ended C-string or a fixed length byte string.
The wire format of the 'string' type is a u32 length

An IPv4 or IPv6 address was previously defined like:
```
u8 is_ip6;
u8 address[16];
```

Which made it hard for language bindings to represent the
address as anything but a byte string.
The new explicit address types are shown above.

## Language generators

The VPP API compiler currently has two output modules. One generating JSON
and one generating C header files that are directly used by the VPP
infrastructure and plugins.

The C/C++, Python, Go Lua, and Java language bindings are generated based
on the JSON files.

### Future considerations
- [ ] Generate C/C++ (vapi) client code directly from vppapigen
- [ ] Embed JSON definitions into the API server, so dynamic languages
  can download them directly without going via the filesystem and JSON
  files.
