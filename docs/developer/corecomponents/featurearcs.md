Feature Arcs
============

A significant number of vpp features are configurable on a per-interface
or per-system basis. Rather than ask feature coders to manually
construct the required graph arcs, we built a general mechanism to
manage these mechanics.

Specifically, feature arcs comprise ordered sets of graph nodes. Each
feature node in an arc is independently controlled. Feature arc nodes
are generally unaware of each other. Handing a packet to "the next
feature node" is quite inexpensive.

The feature arc implementation solves the problem of creating graph arcs
used for steering.

At the beginning of a feature arc, a bit of setup work is needed, but
only if at least one feature is enabled on the arc.

On a per-arc basis, individual feature definitions create a set of
ordering dependencies. Feature infrastructure performs a topological
sort of the ordering dependencies, to determine the actual feature
order. Missing dependencies **will** lead to runtime disorder. See
<https://gerrit.fd.io/r/#/c/12753> for an example.

If no partial order exists, vpp will refuse to run. Circular dependency
loops of the form "a then b, b then c, c then a" are impossible to
satisfy.

Adding a feature to an existing feature arc
-------------------------------------------

To nobody's great surprise, we set up feature arcs using the typical
"macro -> constructor function -> list of declarations" pattern:

```c
    VNET_FEATURE_INIT (mactime, static) =
    {
      .arc_name = "device-input",
      .node_name = "mactime",
      .runs_before = VNET_FEATURES ("ethernet-input"),
    };  
```

This creates a "mactime" feature on the "device-input" arc.

Once per frame, dig up the vnet\_feature\_config\_main\_t corresponding
to the "device-input" feature arc:

```c
    vnet_main_t *vnm = vnet_get_main ();
    vnet_interface_main_t *im = &vnm->interface_main;
    u8 arc = im->output_feature_arc_index;
    vnet_feature_config_main_t *fcm;

    fcm = vnet_feature_get_config_main (arc);
```

Note that in this case, we've stored the required arc index - assigned
by the feature infrastructure - in the vnet\_interface\_main\_t. Where
to put the arc index is a programmer's decision when creating a feature
arc.

Per packet, set next0 to steer packets to the next node they should
visit:

```c
    vnet_get_config_data (&fcm->config_main,
                          &b0->current_config_index /* value-result */, 
                          &next0, 0 /* # bytes of config data */);
```

Configuration data is per-feature arc, and is often unused. Note that
it's normal to reset next0 to divert packets elsewhere; often, to drop
them for cause:

```c
    next0 = MACTIME_NEXT_DROP;
    b0->error = node->errors[DROP_CAUSE];
```

Creating a feature arc
----------------------

Once again, we create feature arcs using constructor macros:

```c
    VNET_FEATURE_ARC_INIT (ip4_unicast, static) =
    {
      .arc_name = "ip4-unicast",
      .start_nodes = VNET_FEATURES ("ip4-input", "ip4-input-no-checksum"),
      .arc_index_ptr = &ip4_main.lookup_main.ucast_feature_arc_index,
    };  
```

In this case, we configure two arc start nodes to handle the
"hardware-verified ip checksum or not" cases. During initialization,
the feature infrastructure stores the arc index as shown.

In the head-of-arc node, do the following to send packets along the
feature arc:

```c
    ip_lookup_main_t *lm = &im->lookup_main;
    arc = lm->ucast_feature_arc_index;
```

Once per packet, initialize packet metadata to walk the feature arc:

```c
vnet_feature_arc_start (arc, sw_if_index0, &next, b0);
```

Enabling / Disabling features
-----------------------------

Simply call vnet_feature_enable_disable to enable or disable a specific
feature:

```c
    vnet_feature_enable_disable ("device-input", /* arc name */
                                 "mactime",      /* feature name */
           		             sw_if_index,    /* Interface sw_if_index */
                                 enable_disable, /* 1 => enable */
                                 0 /* (void *) feature_configuration */, 
                                 0 /* feature_configuration_nbytes */);
```

The feature_configuration opaque is seldom used. 

If you wish to make a feature a _de facto_ system-level concept, pass
sw_if_index=0 at all times. Sw_if_index 0 is always valid, and
corresponds to the "local" interface.

Related "show" commands
-----------------------

To display the entire set of features, use "show features [verbose]". The
verbose form displays arc indices, and feature indicies within the arcs

```
$ vppctl show features verbose
Available feature paths
<snip>
[14] ip4-unicast:
  [ 0]: nat64-out2in-handoff
  [ 1]: nat64-out2in
  [ 2]: nat44-ed-hairpin-dst
  [ 3]: nat44-hairpin-dst
  [ 4]: ip4-dhcp-client-detect
  [ 5]: nat44-out2in-fast
  [ 6]: nat44-in2out-fast
  [ 7]: nat44-handoff-classify
  [ 8]: nat44-out2in-worker-handoff
  [ 9]: nat44-in2out-worker-handoff
  [10]: nat44-ed-classify
  [11]: nat44-ed-out2in
  [12]: nat44-ed-in2out
  [13]: nat44-det-classify
  [14]: nat44-det-out2in
  [15]: nat44-det-in2out
  [16]: nat44-classify
  [17]: nat44-out2in
  [18]: nat44-in2out
  [19]: ip4-qos-record
  [20]: ip4-vxlan-gpe-bypass
  [21]: ip4-reassembly-feature
  [22]: ip4-not-enabled
  [23]: ip4-source-and-port-range-check-rx
  [24]: ip4-flow-classify
  [25]: ip4-inacl
  [26]: ip4-source-check-via-rx
  [27]: ip4-source-check-via-any
  [28]: ip4-policer-classify
  [29]: ipsec-input-ip4
  [30]: vpath-input-ip4
  [31]: ip4-vxlan-bypass
  [32]: ip4-lookup
<snip>
```

Here, we learn that the ip4-unicast feature arc has index 14, and that
e.g. ip4-inacl is the 25th feature in the generated partial order.

To display the features currently active on a specific interface,
use "show interface <name> features":

```
$ vppctl show interface GigabitEthernet3/0/0 features
Feature paths configured on GigabitEthernet3/0/0...
<snip>
ip4-unicast:
  nat44-out2in
<snip>
```

Table of Feature Arcs
---------------------

Simply search for name-strings to track down the arc definition, location of
the arc index, etc.

```
            |    Arc Name      |
            |------------------|
            | device-input     |
            | ethernet-output  |
            | interface-output |
            | ip4-drop         |
            | ip4-local        |
            | ip4-multicast    |
            | ip4-output       |
            | ip4-punt         |
            | ip4-unicast      |
            | ip6-drop         |
            | ip6-local        |
            | ip6-multicast    |
            | ip6-output       |
            | ip6-punt         |
            | ip6-unicast      |
            | mpls-input       |
            | mpls-output      |
            | nsh-output       |
```
