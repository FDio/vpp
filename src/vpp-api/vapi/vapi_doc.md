# VPP API module    {#vapi_doc}

## Overview

VPP API module allows communicating with VPP over a shared memory interface.
The API consists of 3 parts:

* common code - low-level API
* generated code - high-level API
* code generator - to generate your own high-level API e.g. for custom plugins

### Common code

#### C common code

C common code represents the basic, low-level API, providing functions to
connect/disconnect, perform message discovery and send/receive messages.
The C variant is in vapi.h.

#### C++ common code

C++ is provided by vapi.hpp and contains high-level API templates,
which are specialized by generated code.

### Generated code

Each API file present in the source tree is automatically translated to JSON
file, which the code generator parses and generates either C (`vapi_c_gen.py`)
or C++ (`vapi_cpp_gen.py`) code.

This can then be included in the client application and provides convenient way
to interact with VPP. This includes:

* automatic byte-swapping
* automatic request-response matching based on context
* automatic casts to appropriate types (type-safety) when calling callbacks
* automatic sending of control-pings for dump messages

The API supports two modes of operation:

* blocking
* non-blocking

In blocking mode, whenever an operation is initiated, the code waits until it
can finish. This means that when sending a message, the call blocks until
the message can be written to shared memory. Similarly, receiving a message
blocks until a message becomes available. On higher level, this also means that
when doing a request (e.g. `show_version`), the call blocks until a response
comes back (e.g. `show_version_reply`).

In non-blocking mode, these are decoupled, the API returns VAPI_EAGAIN whenever
an operation cannot be performed and after sending a request, it's up to
the client to wait for and process a response.

### Code generator

Python code generator comes in two flavors - C and C++ and generates high-level
API headers. All the code is stored in the headers.

## Usage

### Low-level API

Refer to inline API documentation in doxygen format in `vapi.h` header
for description of functions. It's recommended to use the safer, high-level
API provided by specialized headers (e.g. `vpe.api.vapi.h`
or `vpe.api.vapi.hpp`).

#### C high-level API

##### Callbacks

The C high-level API is strictly callback-based for maximum efficiency.
Whenever an operation is initiated, a callback with a callback context is part
of that operation. The callback is then invoked when the response (or multiple
responses) arrive which are tied to the request. Also, callbacks are invoked
whenever an event arrives, if such callback is registered. All the pointers
to responses/events point to shared memory and are immediately freed after
callback finishes so the client needs to extract/copy any data in which it
is interested in.

#### Blocking mode

In simple blocking mode, the whole operation (being a simple request or a dump)
is finished and it's callback is called (potentially multiple times for dumps)
during function call.

Example pseudo-code for a simple request in this mode:

`
vapi_show_version(message, callback, callback_context)

1. generate unique internal context and assign it to message.header.context
2. byteswap the message to network byte order
3. send message to vpp (message is now consumed and vpp will free it)
4. create internal "outstanding request context" which stores the callback,
   callback context and the internal context value
5. call dispatch, which in this mode receives and processes responses until
   the internal "outstanding requests" queue is empty. In blocking mode, this
   queue always contains at most one item.
`

**Note**: it's possible for different - unrelated callbacks to be called before
the response callbacks is called in cases where e.g. events are stored
in shared memory queue.

#### Non-blocking mode

In non-blocking mode, all the requests are only byte-swapped and the context
information along with callbacks is stored locally (so in the above example,
only steps 1-4 are executed and step 5 is skipped). Calling dispatch is up to
the client application. This allows to alternate between sending/receiving
messages or have a dedicated thread which calls dispatch.

### C++ high level API

#### Callbacks

In C++ API, the response is automatically tied to the corresponding `Request`,
`Dump` or `Event_registration` object. Optionally a callback might be specified,
which then gets called when the response is received.

**Note**: responses take up shared memory space and should be freed either
manually (in case of result sets) or automatically (by destroying the object
owning them) when no longer needed. Once a Request or Dump object was executed,
it cannot be re-sent, since the request itself (stores in shared memory)
is consumed by vpp and inaccessible (set to nullptr) anymore.

#### Usage

#### Requests & dumps

0. Create on object of `Connection` type and call `connect()` to connect to vpp.
1. Create an object of `Request` or `Dump` type using it's typedef (e.g.
   `Show_version`)
2. Use `get_request()` to obtain and manipulate the underlying request if
   required.
3. Issue `execute()` to send the request.
4. Use either `wait_for_response()` or `dispatch()` to wait for the response.
5. Use `get_response_state()` to get the state and `get_response()` to read
   the response.

#### Events

0. Create a `Connection` and execute the appropriate `Request` to subscribe to
   events (e.g. `Want_stats`)
1. Create an `Event_registration` with a template argument being the type of
   event you are interested in.
2. Call `dispatch()` or `wait_for_response()` to wait for the event. A callback
   will be called when an event occurs (if passed to `Event_registration()`
   constructor). Alternatively, read the result set.

**Note**: events stored in the result set take up space in shared memory
and should be freed regularly (e.g. in the callback, once the event is
processed).
