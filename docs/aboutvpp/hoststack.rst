.. _hoststack:

==============
TCP Host Stack
==============

VPP’s host stack leverages VPP’s graph based forwarding model and vectorized packet
processing to ensure high throughput and scale transport protocol termination. It
exposes apis that apart from allowing for efficient user-space app consumption and
generation of data, also enables highly efficient local inter-app communication. 
 
At a high level VPP’s host stack consists of 3 major components: 

* A session layer that facilitates interaction between transport protocols and applications
* Pluggable transport protocols, including TCP, QUIC, TLS, UDP
* VCL (VPPComs library) a set of libraries meant to ease the consumability of the stack from application perspective
 
All of these components were custom built to fit within VPP’s architecture and to
leverage its speed. As a result, a significant amount of effort was invested into:

*  building a transport pluggable session layer that abstracts the interaction between applications and transports using a custom-built shared memory infrastructure. Notably, this also allows for transport protocols that are typically implemented in applications, like QUIC and TLS, to be implemented within VPP. 
* a clean slate TCP implementation that supports vectorized packet processing and follows VPP’s highly scalable threading model. The implementation is RFC compliant, supports a high number of high-speed TCP protocol features and it was validated using Defensic’s Codenomicon 1M+ tests suite. 
* VCL, a library that emulates traditional asynchronous communication functions in user-space, all while allowing for new patterns to be developed, if needed. 
* implementing a high performance “cut-through” communication mode that enables applications attached to vpp to transparently exchange data over shared memory without incurring the extra cost of a traditional transport protocol. Testing has shown this to be much more efficient than traditional inter-container networking.

For developer features press next.
