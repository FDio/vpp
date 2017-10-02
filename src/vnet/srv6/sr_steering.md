# Steering packets into a SR Policy     {#srv6_steering_doc}

## steer packets uging the sr steering policy

To steer packets in Transit into an SR policy (T.Insert, T.Encaps and T.Encaps.L2 behaviors), the user needs to create an 'sr steering policy'.

    sr steer l3 2001::/64 via sr policy index 1
    sr steer l3 2001::/64 via sr policy bsid cafe::1
    sr steer l3 2001::/64 via sr policy bsid cafe::1 fib-table 3
    sr steer l3 10.0.0.0/16 via sr policy bsid cafe::1
    sr steer l2 TenGE0/1/0 via sr policy bsid cafe::1

Disclaimer: The T.Encaps.L2 will steer L2 frames into an SR Policy. Notice that creating an SR steering policy for L2 frames will actually automatically *put the interface into promiscous mode*.

## steer packets using the classifier

Another way to steer packet is to use the classifier.

First the user need to manually add the source routing node to the list of the
ip6-inacl next nodes.
Using the python api this can be donne with:

    # jsonfiles = get list of json api files
    vpp = VPP(jsonfiles)
    vpp.add_node_next(node_name='ip6-inacl', next_name='sr-pl-rewrite-insert')

Below is a classifier mask filtering all the packets from the interface
TenGigabitEthernet5/0/0 on ip version and moving all ipv6 packets to the
sr-pl-rewrite-insert node (dropping the others) and applying the source routing
index 2.
In essence, this means "apply this sr policy to all the packets from this interface)

    vpp# classify table miss-next 0 current-data-flag 1  mask hex f000000000000000 skip 0
    vpp# classify session acl-hit-next 1 table-index 0 match hex 6000000000000000 action set-sr-policy-index 2
    vpp# set interface input acl intfc TenGigabitEthernet5/0/0 ip6-table 0
