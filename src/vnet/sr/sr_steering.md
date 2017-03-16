# Steering packets into a SR Policy     {#srv6_steering_doc}

To steer packets in Transit into an SR policy (T.Insert, T.Encaps and T.Encaps.L2 behaviors), the user needs to create an 'sr steering policy'.

    sr steer l3 2001::/64 via sr policy index 1
    sr steer l3 2001::/64 via sr policy bsid cafe::1
    sr steer l3 2001::/64 via sr policy bsid cafe::1 fib-table 3
    sr steer l3 10.0.0.0/16 via sr policy bsid cafe::1
    sr steer l2 TenGE0/1/0 via sr policy bsid cafe::1

Disclaimer: The T.Encaps.L2 will steer L2 frames into an SR Policy. Notice that creating an SR steering policy for L2 frames will actually automatically *put the interface into promiscous mode*.
