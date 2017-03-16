# SR LocalSIDs    {#srv6_localsid_doc}

A local SID is associated to a Segment Routing behavior -or function- on the current node.

The most basic behavior is called END. It simply activates the next SID in the current packet, by decrementing the Segments Left value and updating the IPv6 DA.

A local END SID is instantiated using the following CLI:

    sr localsid (del) address XX::YY behavior end

This creates a new entry in the main FIB for IPv6 address XX::YY. All packets whose IPv6 DA matches this FIB entry are redirected to the sr-localsid node, where they are processed as described above.

Other examples of local SIDs are the following:

    sr localsid (del) address XX::YY behavior end
    sr localsid (del) address XX::YY behavior end.x GE0/1/0 2001::a
    sr localsid (del) address XX::YY behavior end.dx6 GE0/1/0 2001::a
    sr localsid (del) address XX::YY behavior end.dx4 GE0/1/0 10.0.0.1
    sr localsid (del) address XX::YY behavior end.dx2 GigabitE0/11/0
    sr localsid (del) address XX::YY behavior end.dt6 5
    sr localsid (del) address XX::YY behavior end.dt6 5

Note that all of these behaviors match the definitions of the SRv6 architecture (*draft-filsfils-spring-srv6-network-programming*). Please refer to this document for a detailed description of each behavior.

Note also that you can configure the PSP flavor of the End and End.X behaviors by typing:
    
    sr localsid (del) address XX::YY behavior end psp
    sr localsid (del) address XX::YY behavior end.x GE0/1/0 2001::a psp

Help on the available local SID behaviors and their usage can be obtained with:
    
    help sr localsid

Alternatively they can be obtained using.

    show sr localsids behavior

The difference in between those two commands is that the first one will only display the SR LocalSID behaviors that are built-in VPP, while the latter will display those behaviors plus the ones added with the SR LocalSID Development Framework.


VPP keeps a 'My LocalSID Table' where it stores all the SR local SIDs instantiated as well as their parameters. Every time a new local SID is instantiated, a new entry is added to this table. In addition, counters for correctly and incorrectly processed traffic are maintained for each local SID. The counters store both the number of packets and bytes.

The contents of the 'My LocalSID Table' is shown with:

    vpp# show sr localsid
    SRv6 - My LocalSID Table:
    =========================
            Address:        c3::1
            Behavior:       DX6 (Endpoint with decapsulation and IPv6 cross-connect)
            Iface:          GigabitEthernet0/5/0
            Next hop:       b:c3::b
            Good traffic:   [51277 packets : 5332808 bytes]
            Bad traffic:    [0 packets : 0 bytes]
    --------------------

The traffic counters can be reset with:

    vpp# clear sr localsid counters
