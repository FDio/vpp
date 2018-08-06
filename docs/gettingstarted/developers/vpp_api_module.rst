.. _vpp_api_module:

.. toctree::

VPP API module
==============

Overview
________

VPP API module allows communicating with VPP over shared memory interface. The API consists of 3 parts:

* common code - low-level API
* generated code - high-level API
* code generator - to generate your own high-level API e.g. for custom plugins

Common code
___________

**C**

C common code represents the basic, low-level API, providing functions to connect/disconnect, perform message discovery and send/receive messages. The C variant is in vapi.h.

**C++**

C++ is provided by vapi.hpp and contains high-level API templates, which are specialized by generated code.

Generated code
______________

Each API file present in the source tree is automatically translated to JSON file, which the code generator parses and generates either C (vapi_c_gen.py) or C++ (vapi_cpp_gen.py) code.

This can then be included in the client application and provides convenient way to interact with VPP. This includes:

* automatic byte-swapping
* automatic request-response matching based on context
* automatic casts to appropriate types (type-safety) when calling callbacks
* automatic sending of control-pings for dump messages

The API supports two modes of operation:

* blocking
* non-blocking

In blocking mode, whenever an operation is initiated, the code waits until it can finish. This means that when sending a message, the call blocks until the message can be written to shared memory. Similarly, receiving a message blocks until a message becomes available. On higher level, this also means that when doing a request (e.g. show_version), the call blocks until a response comes back (e.g. show_version_reply).

In non-blocking mode, these are decoupled, the API returns VAPI_EAGAIN whenever an operation cannot be performed and after sending a request, it's up to the client to wait for and process a response.

Code generator
______________

Python code generator comes in two flavors - C and C++ and generates high-level API headers. All the code is stored in the headers.

C Usage
_______

**Low-level API**

Refer to inline API documentation in doxygen format in vapi.h header for description of functions. It's recommened to use the safer, high-level API provided by specialized headers (e.g. vpe.api.vapi.h or vpe.api.vapi.hpp).

**C high-level API**

*Callbacks*

The C high-level API is strictly callback-based for maximum efficiency. Whenever an operation is initiated a callback with a callback context is part of that operation. The callback is then invoked when the response (or multiple responses) arrive which are tied to the request. Also, callbacks are invoked whenever an event arrives, if such callback is registered. All the pointers to responses/events point to shared memory and are immediately freed after callback finishes so the client needs to extract/copy any data in which it is interested in.

**Blocking mode**

In simple blocking mode, the whole operation (being a simple request or a dump) is finished and it's callback is called (potentially multiple times for dumps) during function call.

Example pseudo-code for a simple request in this mode:

vapi_show_version(message, callback, callback_context)

#. generate unique internal context and assign it to message.header.context 
#. byteswap the message to network byte order 
#. send message to vpp (message is now consumed and vpp will free it) 
#. create internal "outstanding request context" which stores the callback, callback context and the internal context value 
#. call dispatch, which in this mode receives and processes responses until the internal "outstanding requests" queue is empty. In blocking mode, this queue always contains at most one item. 

.. note::

	It's possible for different - unrelated callbacks to be called before the response callbacks is called in cases where e.g. events are stored in shared memory queue.

**Non-blocking mode**
In non-blocking mode, all the requests are only byte-swapped and the context information along with callbacks is stored locally (so in the above example, only steps 1-4 are executed and step 5 is skipped). Calling dispatch is up to the client application. This allows to alternate between sending/receiving messages or have a dedicated thread which calls dispatch.

C++ high level API
__________________

**Callbacks**

In C++ API, the response is automatically tied to the corresponding Request, Dump or Event_registration object. Optionally a callback might be specified, which then gets called when the response is received.

.. note::

	Responses take up shared memory space and should be freed either manually (in case of result sets) or automatically (by destroying the object owning them) when no longer needed. Once a Request or Dump object was executed, it cannot be re-sent, since the request itself (stores in shared memory) is consumed by vpp and inaccessible (set to nullptr) anymore.

C++ Usage
_________

**Requests & dumps**

*Create an object of Connection type and call connect() to connect to vpp.*

#. Create an object of Request or Dump type using it's typedef (e.g. Show_version)
#. Use get_request() to obtain and manipulate the underlying request if required.
#. Issue execute() to send the request.
#. Use either wait_for_response() or dispatch() to wait for the response.
#. Use get_response_state() to get the state and get_response() to read the response.

**Events**

*Create a Connection and execute the appropriate Request to subscribe to events (e.g. Want_stats)*

#. Create an Event_registration with a template argument being the type of event you are insterested in.
#. Call dispatch() or wait_for_response() to wait for the event. A callback will be called when an event occurs (if passed to Event_registration() constructor). Alternatively, read the result set.

.. note::

	Events stored in the result set take up space in shared memory and should be freed regularly (e.g. in the callback, once the event is processed).

