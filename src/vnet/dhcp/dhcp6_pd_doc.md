# DHCPv6 prefix delegation    {#dhcp6_pd_doc}

DHCPv6 prefix delegation client implementation is split between Control Plane and Data Plane.  
Data Plane can also be used alone by external application (external Control Plane) using Data Plane Binary API.  

Number of different IA\_PDs managed by VPP is currently limited to 1 (and corresponding IAID has value 1).  
Client ID is of type DUID-LLT (Link Layer address plus time) and is created on VPP startup from avaliable interfaces (or chosen at random for debugging purposes).  
Server ID is only visible to Data Plane. Control Plane identifies servers by a 32-bit handle (server\_index) mapped to Server ID by Data Plane.  

## Control Plane

DHCPv6 PD clients are configured per interface.  
When configuring a PD client we have to choose a name of a prefix group for that client.  
Each prefix obtained through this client will be flagged as belonging to specified prefix group.  
The prefix groups are used as a filter by prefix consumers.  

To enable client on particular interface call Binary API function dhcp6\_pd\_client\_enable\_disable with param 'sw\_if\_index' set to that interface,
'prefix\_group' set to prefix group name and 'enable' set to true.  
Format of corresponding Debug CLI command is: "dhcp6 pd client <interface> [disable]"  

To add/delete IPv6 address potentially using available prefix from specified prefix group call Binary API command ip6\_add\_del\_address\_using\_prefix with parameters:  
> sw\_if\_index - software interface index of interface to add/delete address to/from
> prefix\_group - name of prefix group, prefix\_group[0] == '\0' means no prefix should be used
> address - address or suffix to be used with a prefix from selected group
> prefix\_length - subnet prefix for the address
> is\_add - 1 for add, 0 for remove
or Debug CLI command with format: "set ip6 addresses <interface> [prefix group <n>] <address> [del]"

When no prefix is avaliable, no address is physically added, but is added once a prefix becomes avaliable.  
Address is removed when all available prefixes are removed.  
When a used prefix is removed and there is other available prefix, the address that used the prefix is reconfigured using the available prefix.  

There are three debug CLI commands (with no parameters) used to show the state of clients, prefixes and addresses:  
  show ip6 pd clients  
  show ip6 prefixes  
  show ip6 addresses  
  
### Example configuration

set int state GigabitEthernet0/8/0 up
dhcp6 pd client GigabitEthernet0/8/0 prefix group my-dhcp6-pd-group
set ip6 address GigabitEthernet0/8/0 prefix group my-dhcp6-pd-group ::7/64

## Data Plane

First API message to be called is dhcp6\_clients\_enable\_disable with enable parameter set to 1.  
It enables DHCPv6 client subsystem to receive UDP messages containing DHCPv6 client port (sets the router to DHCPv6 client mode).  
This is to ensure client subsystem gets the messages instead of DHCPv6 proxy subsystem.  
  
There is one common Binary API call for sending DHCPv6 client messages (dhcp6\_pd\_send\_client\_message) with these fields:  
> msg\_type - message type (e.g. Solicit)
> sw\_if\_index - index of TX interface
> server\_index - used to dentify DHCPv6 server,
                 unique for each DHCPv6 server on the link,
                 value obrtained from dhcp6\_pd\_reply\_event API message,
                 use ~0 to send message to all DHCPv6 servers
> param irt - initial retransmission time
> param mrt - maximum retransmission time
> param mrc - maximum retransmission count
> param mrd - maximum retransmission duration for sending the message
> stop - if non-zero then stop resending the message, otherwise start sending the message
> T1 - value of T1 in IA\_PD option
> T2 - value of T2 in IA\_PD option
> prefixes - list of prefixes in IA\_PD option

The message is automatically resent by Data Plane based on parameters 'irt', 'mrt', 'mrc' and 'mrd'.  
To stop the resending call the same function (same msg\_type is sufficient) with 'stop' set to 1.  

To subscribe for notifications of DHCPv6 messages from server call Binary API function  
want\_dhcp6\_pd\_reply\_events with enable\_disable set to 1  
Notification (dhcp6\_pd\_reply\_event) fileds are:  
> sw\_if\_index - index of RX interface
> server\_index - used to dentify DHCPv6 server, unique for each DHCPv6 server on the link
> msg\_type - message type
> T1 - value of T1 in IA\_PD option
> T2 - value of T2 in IA\_PD option
> inner\_status\_code - value of status code inside IA\_PD option
> status\_code - value of status code
> preference - value of preference option in reply message
> prefixes - list of prefixes in IA\_PD option

Prefix is a struct with with these fields:  
> prefix - prefix bytes
> prefix\_length - prefix length
> valid\_time - valid lifetime
> preferred\_time - preferred lifetime
