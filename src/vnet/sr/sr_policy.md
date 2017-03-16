# Creating a SR Policy    {#srv6_policy_doc}

An SR Policy is defined by a Binding SID and a weighted set of Segment Lists.

A new SR policy is created with a first SID list using:

    sr policy add bsid 2001::1 next A1:: next B1:: next C1:: (weight 5) (fib-table 3)

* The weight parameter is only used if more than one SID list is associated with the policy.
* The fib-table parameter specifies in which table (VRF) the Binding SID is to be installed.

An SR policy is deleted with:

    sr policy del bsid 2001::1
    sr policy del index 1

The existing SR policies are listed with:

    show sr policies

## Adding/Removing SID Lists from an SR policy

An additional SID list is associated with an existing SR policy with:

    sr policy mod bsid 2001::1 add sl next A2:: next B2:: next C2:: (weight 3)
    sr policy mod index 3      add sl next A2:: next B2:: next C2:: (weight 3)

Conversely, a SID list can be removed from an SR policy with:

    sr policy mod bsid 2001::1 del sl index 1
    sr policy mod index 3      del sl index 1

Note that this cannot be used to remove the last SID list of a policy.

The weight of a SID list can also be modified with:

    sr policy mod bsid 2001::1 mod sl index 1 weight 4
    sr policy mod index 3      mod sl index 1 weight 4

## SR Policies: Spray policies

Spray policies are a specific type of SR policies where the packet is replicated on all the SID lists, rather than load-balanced among them.

SID list weights are ignored with this type of policies.

A Spray policy is instantiated by appending the keyword **spray** to a regular SR policy command, as in:

    sr policy add bsid 2001::1 next A1:: next B1:: next C1:: spray

Spray policies are used for removing multicast state from a network core domain, and instead send a linear unicast copy to every access node. The last SID in each list accesses the multicast tree within the access node.  

## Encapsulation SR policies

In case the user decides to create an SR policy an IPv6 Source Address must be specified for the encapsulated traffic. In order to do so the user might use the following command:
    
    set sr encaps source addr XXXX::YYYY
