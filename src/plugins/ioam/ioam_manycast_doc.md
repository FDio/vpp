## IOAM and SRv6 for M-Anycast service selection    {#ioam_manycast_doc}

Anycast is often used to have a client choose one out of multiple servers.
This might be due to performance, scale, or availability reasons.
If a client initiates a TCP connection in an anycast scenario, 
the TCP session is usually established with the server which answers the quickest.

There are cases where it is desirable to:
- allow choosing the destination server not based on "fastest response time",
but based on the delay between server and client (e.g. for a streaming application).
- allow choosing the destination server based on other parameters, 
such as server load information.
- ensure that all TCP connections of a particular client are hooked up to the same 
server, i.e. that all TCP sessions following the first one are connected to the same server as the first session.

M-anycast combines IOAM and Segment Routing v6 (SRv6) to provide for a solution:
- IOAM information is added to the initial TCP SYN packet to understand the transmit delay, as well as to the SYN-ACK packet to understand the return delay.
- SRv6 is used to steer traffic to the set of servers, rather than rely on anycast procedures. 
Client and Servers can be left unchanged. 
SRv6 and iOAM information is added and removed "in transit"

Introduce M-Anycast Server as a solution component to leverage Segment Routing to steer 
traffic, IOAM for optimized service selection.
M-Anycast Server:
- Hosts the Anycast address of the services
- Intercepts TCP-SYN, replicates the SYN and sends to a selected subset of all services using SRv6 spray policy
- Chooses an appropriate SYN-ACK using embedded in-band OAM data and forwards that SYN-ACK to the client with SRv6 header intact. The SRv6 header in the SYN-ACK received by the client is used to reach the selected server for subsequent packet exchange.

VPP can function as an M-Anycast server. VPP can also be used as a IOAM and SRv6 decapsulating node at the application server edge. This allows for caching of IOAM and reattaching it to correlate the path performance across request-response (SYN/SYN-ACK) forwarding path. 

## Configuration
Example: Highly redundant video-caches as micro-services hosted in multiple public clouds. All Services have an IPv6 address allocated from anycast IPv6 prefix (db06::/64).
Here configuration to enable VPP as an M-Anycast server and IOAM caching/reattach node is provided.

### M-Anycast Server
- Enable M-Anycast service selection using:
    

    set ioam ip6 sr-tunnel-select [disable] [oneway|rtt] [wait_for_responses <n|default 3>] sr_localsid <IPv6 address>
    
Example:


    set ioam ip6 sr-tunnel-select oneway sr_localsid db0a::2
    
- Enable IOAM tracing. Override node for selected traffic processing
Example:
To enable M-Anycast service selection with IOAM tracing enabled for db06::/64 prefix and on the return path to process service selection for SRv6 localsid db0a::2:


    classify table acl-miss-next ip6-node ip6-lookup mask hex 000000000000ffffffffffffffff0000 buckets 2 skip 2 match 1
    
    classify session acl-hit-next ip6-node ip6-add-syn-hop-by-hop table-index 0 match hex 0000000000000000000000000000000000000000000000000000000000000000000000000000db060000000000000000 ioam-encap anycast
    
    classify session acl-hit-next ip6-node ip6-lookup table-index 0 match hex 0000000000000000000000000000000000000000000000000000000000000000000000000000db0a0000000000000000 ioam-decap anycast
    
    set int input acl intfc GigabitEthernet0/4/0 ip6-table 0
    set int input acl intfc GigabitEthernet0/5/0 ip6-table 0
    set ioam-trace profile trace-type 0x09 trace-elts 3 trace-tsp 1 node-id 0x1
    set ioam rewrite trace


- Enable SRv6 spray policy for steering traffic towards M-Anycast prefix.
Example:
To steer anycast prefix db06::/64 towards servers with address db07::1, db08::1, db09::1:


    sr policy add bsid db11::2 next db07::1 insert spray
    sr policy mod add sl bsid db11::2 next db08::1  
    sr policy mod add sl bsid db11::2 next db09::1  
    sr steer l3 db06::/64 via sr policy bsid db11::2
    sr localsid address db0a::2 behavior end
    
    
### IOAM Caching/reattach at application service edge
- Enable IOAM data caching


    set ioam ip6 cache sr_localsid <ip6 address> [disable]
    
Example: 
    
    
    set ioam ip6 cache sr_localsid db07::1 

- Enable IOAM decap
Example: To decap IOAM and cache the data towards db06::/64 and reinsert the data towards db04::/64:


    classify table acl-miss-next ip6-node ip6-lookup mask hex     000000000000ffffffffffffffff0000 buckets 2 skip 2 match 1
   
    classify session acl-hit-next ip6-node ip6-lookup table-index 0 match hex 0000000000000000000000000000000000000000000000000000000000000000000000000000db060000000000000000 ioam-decap anycast
    
    classify session acl-hit-next ip6-node ip6-lookup table-index 0 match hex 0000000000000000000000000000000000000000000000000000000000000000000000000000db070000000000000000 ioam-decap anycast
    
    classify session acl-hit-next ip6-node ip6-add-from-cache-hop-by-hop table-index 0 match hex 0000000000000000000000000000000000000000000000000000000000000000000000000000db040000000000000000 ioam-encap anycast-response
    
    set int input acl intfc GigabitEthernet0/4/0 ip6-table 0   
    
    set ioam-trace profile trace-type 0x1f trace-elts 4 trace-tsp 1 node-id 0x3 app-data 0x1234   
    
- Enable SRv6 localsid processing to strip SRv6 header before forwarding towards application service


    sr localsid address db07::1 behavior end psp

