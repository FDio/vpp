/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * \brief
 * A IP v4/6 independent FIB.
 *
 * The main functions provided by the FIB are as follows;
 *
 *  - source priorities
 *
 *   A route can be added to the FIB by more than entity or source. Sources
 * include, but are not limited to, API, CLI, LISP, MAP, etc (for the full list
 * see fib_entry.h). Each source provides the forwarding information (FI) that
 * is has determined as required for that route. Since each source determines the
 * FI using different best  path and loop prevention algorithms, it is not
 * correct for the FI of multiple sources to be combined. Instead the FIB must
 * choose to use the FI from only one source. This choose is based on a static
 * priority assignment. For example;
 * IF a prefix is added as a result of interface configuration:
 *    set interface address 192.168.1.1/24 GigE0
 * and then it is also added from the CLI
 *    ip route 192.168.1.1/32 via 2.2.2.2/32
 * then the 'interface' source will prevail, and the route will remain as
 * 'local'.
 * The requirement of the FIB is to always install the FI from the winning
 * source and thus to maintain the FI added by losing sources so it can be
 * installed should the winning source be withdrawn.
 *
 *  - adj-fib maintenance
 *
 *   When ARP or ND discover a neighbour on a link an adjacency forms for the
 * address of that neighbour. It is also required to insert a route in the
 * appropriate FIB table, corresponding to the VRF for the link, an entry for
 * that neighbour. This entry is often referred to as an adj-fib. Adj-fibs
 * have a dedicated source; 'ADJ'.
 * The priority of the ADJ source is lower than most. This is so the following
 * config;
 *    set interface address 192.168.1.1/32 GigE0
 *    ip arp 192.168.1.2 GigE0 dead.dead.dead
 *    ip route add 192.168.1.2 via 10.10.10.10 GigE1
 * will forward traffic for 192.168.1.2 via GigE1. That is the route added
 * by the control plane is favoured over the adjacency discovered by ARP.
 * The control plane, with its associated authentication, is considered the
 * authoritative source.
 * To counter the nefarious addition of adj-fib, through the nefarious injection
 * of adjacencies, the FIB is also required to ensure that only adj-fibs whose
 * less specific covering prefix is connected are installed in forwarding. This
 * requires the use of 'cover tracking', where a route maintains a dependency
 * relationship with the route that is its less specific cover. When this cover
 * changes (i.e. there is a new covering route) or the forwarding information
 * of the cover changes, then the covered route is notified.
 *
 * Overlapping sub-nets are not supported, so no adj-fib has multiple paths.
 * The control plane is expected to remove a prefix configured for an interface
 * before the interface changes VRF.
 * So while the following config is accepted:
 *    set interface address 192.168.1.1/32 GigE0
 *    ip arp 192.168.1.2 GigE0 dead.dead.dead
 *    set interface ip table GigE0 2
 * it does not result in the desired behaviour.
 *
 *  - attached export.
 *
 * Further to adj-fib maintenance above consider the following config:
 *    set interface address 192.168.1.1/24 GigE0
 *    ip route add table 2 192.168.1.0/24 GigE0
 * Traffic destined for 192.168.1.2 in table 2 will generate an ARP request
 * on GigE0. However, since GigE0 is in table 0, all adj-fibs will be added in
 * FIB 0. Hence all hosts in the sub-net are unreachable from table 2. To resolve
 * this, all adj-fib and local prefixes are exported (i.e. copied) from the 
 * 'export' table 0, to the 'import' table 2. There can be many import tables
 * for a single export table.
 *
 *  - recursive route resolution
 *
 *   A recursive route is of the form:
 *       1.1.1.1/32 via 10.10.10.10
 * i.e. a route for which no egress interface is provided. In order to forward
 * traffic to 1.1.1.1/32 the FIB must therefore first determine how to forward
 * traffic to 10.10.10.10/32. This is recursive resolution.
 * Recursive resolution, just like normal resolution, proceeds via a longest
 * prefix match for the 'via-address' 10.10.10.10. Note it is only possible
 * to add routes via an address (i.e. a /32 or /128) not via a shorter mask
 * prefix. There is no use case for the latter.
 * Since recursive resolution proceeds via a longest prefix match, the entry
 * in the FIB that will resolve the recursive route, termed the via-entry, may
 * change as other routes are added to the FIB. Consider the recursive
 * route shown above, and this non-recursive route:
 *       10.10.10.0/24 via 192.168.16.1 GigE0
 * The entry for 10.10.10.0/24 is thus the resolving via-entry. If this entry is
 * modified, to say;
 *       10.10.10.0/24 via 192.16.1.3 GigE0
 * Then packet for 1.1.1.1/32 must also be sent to the new next-hop.
 * Now consider the addition of;
 *       10.10.10.0/28 via 192.168.16.2 GigE0
 * The more specific /28 is a better longest prefix match and thus becomes the
 * via-entry. Removal of the /28 means the resolution will revert to the /24.
 * The tracking to the changes in recursive resolution is the requirement of
 * the FIB. When the forwarding information of the via-entry changes a back-walk
 * is used to update dependent recursive routes. When new routes are added to
 * the table the cover tracking feature provides the necessary notifications to
 * the via-entry routes.
 * The adjacency constructed for 1.1.1.1/32 will be a recursive adjacency
 * whose next adjacency will be contributed from the via-entry. Maintaining
 * the validity of this recursive adjacency is a requirement of the FIB.
 *
 *  - recursive loop avoidance
 *
 * Consider this set of routes:
 *     1.1.1.1/32 via 2.2.2.2
 *     2.2.2.2/32 via 3.3.3.3
 *     3.3.3.3/32 via 1.1.1.1
 * this is termed a recursion loop - all of the routes in the loop are
 * unresolved in so far as they do not have a resolving adjacency, but each
 * is resolved because the via-entry is known. It is important here to note
 * the distinction between the control-plane objects and the data-plane objects
 * (more details in the implementation section). The control plane objects must
 * allow the loop to form (i.e. the graph becomes cyclic), however, the
 * data-plane absolutely must not allow the loop to form, otherwise the packet
 * would loop indefinitely and never egress the device - meltdown would follow.
 * The control plane must allow the loop to form, because when the loop breaks,
 * all members of the loop need to be updated. Forming the loop allows the
 * dependencies to be correctly setup to allow this to happen.
 * There is no limit to the depth of recursion supported by VPP so:
 *    9.9.9.100/32 via 9.9.9.99
 *    9.9.9.99/32  via 9.9.9.98
 *    9.9.9.98/32  via 9.9.9.97
 *      ... turtles, turtles, turtles ...
 *    9.9.9.1/32 via 10.10.10.10 Gig0
 * is supported to as many layers of turtles is desired, however, when
 * back-walking a graph (in this case from 9.9.9.1/32 up toward 9.9.9.100/32)
 * a FIB needs to differentiate the case where the recursion is deep versus
 * the case where the recursion is looped. A simple method, employed by VPP FIB,
 * is to limit the number of steps. VPP FIB limit is 16. Typical BGP scenarios
 * in the wild do not exceed 3 (BGP Inter-AS option C).
 * 
 * - Fast Convergence
 * 
 * After a network topology change, the 'convergence' time, is the time taken
 * for the router to complete a transition to forward traffic using the new
 * topology. The convergence time is therefore a summation of the time to;
 *  - detect the failure.
 *  - calculate the new 'best path' information
 *  - download the new best paths to the data-plane.
 *  - install those best best in data-plane forwarding.
 * The last two points are of relevance to VPP architecture. The download API is
 * binary and batch, details are not discussed here. There is no HW component to
 * programme, installation time is bounded by the memory allocation and table
 * lookup and insert access times.
 *
 * 'Fast' convergence refers to a set of technologies that a FIB can employ to
 * completely or partially restore forwarding whilst the convergence actions
 * listed above are ongoing. Fast convergence technologies are further
 * sub-divided into Prefix Independent Convergence (PIC) and Loop Free
 * Alternate path Fast re-route (LFA-FRR or sometimes called IP-FRR) which
 * affect recursive and non-recursive routes respectively.
 *
 * LFA-FRR
 *
 * Consider the network topology below:
 *
 *          C
 *        /   \
 *  X -- A --- B - Y
 *       |     |
 *       D     F
 *        \   /
 *          E
 *
 * all links are equal cost, traffic is passing from X to Y. the best path is
 * X-A-B-Y. There are two alternative paths, one via C and one via E. An
 * alternate path is considered to be loop free if no other router on that path
 * would forward the traffic back to the sender. Consider router C, its best
 * path to Y is via B, so if A were to send traffic destined to Y to C, then C
 * would forward that traffic to B - this is a loop-free alternate path. In
 * contrast consider router D. D's shortest path to Y is via A, so if A were to
 * send traffic destined to Y via D, then D would send it back to A; this is
 * not a loop-free alternate path. There are several points of note;
 *   - we are considering the pre-failure routing topology
 *   - any equal-cost multi-path between A and B is also a LFA path.
 *   - in order for A to calculate LFA paths it must be aware of the best-path
 *     to Y from the perspective of D. These calculations are thus limited to
 *     routing protocols that have a full view of the network topology, i.e.
 *     link-state DB protocols like OSPF or an SDN controller. LFA protected
 *     prefixes are thus non-recursive.
 *
 * LFA is specified as a 1 to 1 redundancy; a primary path has only one LFA
 * (a.k.a. backup) path. To my knowledge this limitation is one of complexity
 * in the calculation of and capacity planning using a 1-n redundancy. 
 *
 * In the event that the link A-B fails, the alternate path via C can be used.
 * In order to provide 'fast' failover in the event of a failure, the control
 * plane will download both the primary and the backup path to the FIB. It is
 * then a requirement of the FIB to perform the failover (a.k.a cutover) from
 * the primary to the backup path as quickly as possible, and particularly
 * without any other control-plane intervention. The expectation is cutover is
 * less than 50 milli-seconds - a value allegedly from the VOIP QoS. Note that
 * cutover time still includes the fault detection time, which in a vitalised
 * environment could be the dominant factor. Failure detection can be either a
 * link down, which will affect multiple paths on a multi-access interface, or
 * via a specific path heartbeat (i.e. BFD). 
 * At this time VPP does not support LFA, that is it does not support the
 * installation of a primary and backup path[s] for a route. However, it does
 * support ECMP, and VPP FIB is designed to quickly remove failed paths from
 * the ECMP set, however, it does not insert shared objects specific to the
 * protected resource into the forwarding object graph, since this would incur
 * a forwarding/performance cost. Failover time is thus route number dependent.
 * Details are provided in the implementation section below.
 *
 * PIC
 *
 * PIC refers to the concept that the converge time should be independent of
 * the number of prefixes/routes that are affected by the failure. PIC is
 * therefore most appropriate when considering networks with large number of
 * prefixes, i.e. BGP networks and thus recursive prefixes. There are several
 * flavours of PIC covering different locations of protection and failure
 * scenarios. An outline is given below, see the literature for more details:
 *
 * Y/16 - CE1 -- PE1---\
 *                | \   P1---\
 *                |  \        PE3 -- CE3 - X/16
 *                |   - P2---/
 * Y/16 - CE2 -- PE2---/
 *
 * CE = customer edge, PE = provider edge. external-BGP runs between customer
 * and provider, internal-BGP runs between provider and provider.
 *
 * 1) iBGP PIC-core: consider traffic from CE1 to X/16 via CE3. On PE1 there is
 *    are routes;
 *       X/16 (and hundreds of thousands of others like it)
 *         via PE3
 *    and
 *      PE3/32 (its loopback address)
 *        via 10.0.0.1 Link0 (this is P1)
 *        via 10.1.1.1 Link1 (this is P2)
 * the failure is the loss of link0 or link1
 * As in all PIC scenarios, in order to provide prefix independent convergence
 * it must be that the route for X/16 (and all other routes via PE3) do not
 * need to be updated in the FIB. The FIB therefore needs to update a single
 * object that is shared by all routes - once this shared object is updated,
 * then all routes using it will be instantly updated to use the new forwarding
 * information. In this case the shared object is the resolving route via PE3.
 * Once the route via PE3 is updated via IGP (OSPF) convergence, then all
 * recursive routes that resolve through it are also updated. VPP FIB
 * implements this scenario via a recursive-adjacency. the X/16 and it sibling
 * routes share a recursive-adjacency that links to/points at/stacks on the
 * normal adjacency contributed by the route for PE3. Once this shared
 * recursive adj is re-linked then all routes are switched to using the new
 * forwarding information. This is shown below;
 *
 * pre-failure;
 *   X/16 --> R-ADJ-1 --> ADJ-1-PE3 (multi-path via P1 and P2)
 *
 * post-failure:
 *   X/16 --> R-ADJ-1 --> ADJ-2-PE3 (single path via P1)
 *
 * note that R-ADJ-1 (the recursive adj) remains in the forwarding graph,
 * therefore X/16 (and all its siblings) is not updated.
 * X/16 and its siblings share the recursive adj since they share the same
 * path-list. It is the path-list object that contributes the recursive-adj
 * (see next section for more details)
 *
 *
 * 2) iBGP PIC-edge; Traffic from CE3 to Y/16. On PE3 there is are routes;
 *      Y/16  (and hundreds of thousands of others like it)
 *        via PE1
 *        via PE2 
 *  and
 *     PE1/32 (PE1's loopback address)
 *       via 10.0.2.2 Link0 (this is P1)
 *     PE2/32 (PE2's loopback address)
 *       via 10.0.3.3 Link1 (this is P2)
 *
 * the failure is the loss of reachability to PE2. this could be either the
 * loss of the link P2-PE2 or the loss of the node PE2. This is detected either
 * by the withdrawal of the PE2's loopback route or by some form of failure
 * detection (i.e. BFD).
 * VPP FIB again provides PIC via the use of the shared recursive-adj. Y/16 and
 * its siblings will again share a path-list for the list {PE1,PE2}, this
 * path-list will contribute a multi-path-recursive-adj, i.e. a multi-path-adj
 * with each choice therein being another adj;
 *
 *  Y/16 -> RM-ADJ --> ADJ1 (for PE1)
 *                 --> ADJ2 (for PE2)
 *
 * when the route for PE1 is withdrawn then the multi-path-recursive-adjacency
 * is updated to be;
 *
 * Y/16 --> RM-ADJ --> ADJ1 (for PE1)
 *                 --> ADJ1 (for PE1)
 *
 * that is both choices in the ECMP set are the same and thus all traffic is
 * forwarded to PE1. Eventually the control plane will download a route update
 * for Y/16 to be via PE1 only. At that time the situation will be:
 *
 * Y/16 -> R-ADJ --> ADJ1 (for PE1)
 *
 * In the scenario above we assumed that PE1 and PE2 are ECMP for Y/16. eBGP
 * PIC core is also specified for the case were one PE is primary and the other
 * backup - VPP FIB does not support that case at this time.
 *
 * 3) eBGP PIC Edge; Traffic from CE3 to Y/16. On PE1 there is are routes;
 *      Y/16 (and hundreds of thousands of others like it)
 *         via CE1 (primary)
 *         via PE2 (backup)
 *   and
 *     CE1 (this is an adj-fib)
 *       via 11.0.0.1 Link0 (this is CE1) << this is an adj-fib
 *     PE2 (PE2's loopback address)
 *       via 10.0.5.5 Link1 (this is link PE1-PE2)
 * the failure is the loss of link0 to CE1. The failure can be detected by FIB
 * either as a link down event or by the control plane withdrawing the connected
 * prefix on the link0 (say 10.0.5.4/30). The latter works because the resolving
 * entry is an adj-fib, so removing the connected will withdraw the adj-fib, and
 * hence the recursive path becomes unresolved. The former is faster,
 * particularly in the case of Inter-AS option A where there are many VLAN
 * sub-interfaces on the PE-CE link, one for each VRF, and so the control plane
 * must remove the connected prefix for each sub-interface to trigger PIC in
 * each VRF. Note though that total PIC cutover time will depend on VRF scale
 * with either trigger.
 * Primary and backup paths in this eBGP PIC-edge scenario are calculated by
 * BGP. Each peer is configured to always advertise its best external path to
 * its iBGP peers. Backup paths therefore send traffic from the PE back into the
 * core to an alternate PE. A PE may have multiple external paths, i.e. multiple
 * directly connected CEs, it may also have multiple backup PEs, however there
 * is no correlation between the two, so unlike LFA-FRR, the redundancy model is
 * N-M; N primary paths are backed-up by M backup paths - only when all primary
 * paths fail, then the cutover is performed onto the M backup paths. Note that
 * PE2 must be suitably configured to forward traffic on its external path that
 * was received from PE1. VPP FIB does not support external-internal-BGP (eiBGP)
 * load-balancing.
 *
 * As with LFA-FRR the use of primary and backup paths is not currently
 * supported, however, the use of a recursive-multi-path-adj, and a suitably
 * constrained hashing algorithm to choose from the primary or backup path sets,
 * would again provide the necessary shared object and hence the prefix scale
 * independent cutover.
 *
 * Astute readers will recognise that both of the eBGP PIC scenarios refer only
 * to a BGP free core.
 *
 * Fast convergence implementation options come in two flavours:
 *  1) Insert switches into the data-path. The switch represents the protected
 *     resource. If the switch is 'on' the primary path is taken, otherwise
 *     the backup path is taken. Testing the switch in the data-path comes with
 *     an associated performance cost. A given packet may encounter more than
 *     one protected resource as it is forwarded. This approach minimises
 *     cutover times as packets will be forwarded on the backup path as soon
 *     as the protected resource is detected to be down and the single switch
 *     is tripped. However, it comes at a performance cost, which increases
 *     with each shared resource a packet encounters in the data-path.
 *     This approach is thus best suited to LFA-FRR where the protected routes
 *     are non-recursive (i.e. encounter few shared resources) and the
 *     expectation on cutover times is more stringent (<50msecs).
 *  2) Update shared objects. Identify objects in the data-path, that are
 *     required to be present whether or not fast convergence is required (i.e.
 *     adjacencies) that can be shared by multiple routes. Create a dependency
 *     between these objects at the protected resource. When the protected
 *     resource fails, each of the shared objects is updated in a way that all
 *     users of it see a consistent change. This approach incurs no performance
 *     penalty as the data-path structure is unchanged, however, the cutover
 *     times are longer as more work is required when the resource fails. This
 *     scheme is thus more appropriate to recursive prefixes (where the packet
 *     will encounter multiple protected resources) and to fast-convergence
 *     technologies where the cutover times are less stringent (i.e. PIC).
 *
 * Implementation:
 * ---------------
 *
 * Due to the requirements outlined above, not all routes known to FIB
 * (e.g. adj-fibs) are installed in forwarding. However, should circumstances
 * change, those routes will need to be added. This adds the requirement that
 * a FIB maintains two tables per-VRF, per-AF (where a 'table' is indexed by
 * prefix); the forwarding and non-forwarding tables.
 *
 * For DP speed in VPP we want the lookup in the forwarding table to directly 
 * result in the ADJ. So the two tables; one contains all the routes (a 
 * lookup therein yields a fib_entry_t), the other contains only the forwarding 
 * routes (a lookup therein yields an ip_adjacency_t). The latter is used by the
 * DP. 
 * This trades memory for forwarding performance. A good trade-off in VPP's
 * expected operating environments.
 *
 * Note these tables are keyed only by the prefix (and since there 2 two
 * per-VRF, implicitly by the VRF too). The key for an adjacency is the
 * tuple:{next-hop, address (and it's AF), interface, link/ether-type}.
 * consider this curious, but allowed, config;
 *
 *   set int ip addr 10.0.0.1/24 Gig0
 *   set ip arp Gig0 10.0.0.2 dead.dead.dead
 *   # a host in that sub-net is routed via a better next hop (say it avoids a
 *   # big L2 domain)
 *   ip route add 10.0.0.2 Gig1 192.168.1.1
 *   # this recursive should go via Gig1
 *   ip route add 1.1.1.1/32 via 10.0.0.2
 *   # this non-recursive should go via Gig0
 *   ip route add 2.2.2.2/32 via Gig0 10.0.0.2
 *
 * for the last route, the lookup for the path (via {Gig0, 10.0.0.2}) in the
 * prefix table would not yield the correct result. To fix this we need a
 * separate table for the adjacencies.
 *
 *  - FIB data structures;
 *
 * fib_entry_t:
 *   - a representation of a route.
 *     - has a prefix.
 *    - it maintains an array of path-lists that have been contributed by the
 *      different sources
 *    - install an adjacency in the forwarding table contributed by the best
 *      source's path-list.
 *
 * fib_path_list_t:
 *   - a list of paths
 *   - path-lists may be shared between FIB entries. The path-lists are thus
 *     kept in a DB. The key is the combined description of the paths. We share
 *     path-lists  when it will aid convergence to do so. Adding path-lists to
 *     this DB that are never shared, or are not shared by prefixes that are
 *     not subject to PIC, will increase the size of the DB unnecessarily and
 *     may lead to increased search times due to hash collisions.
 *   - the path-list contributes the appropriate adj for the entry in the 
 *     forwarding table. The adj can be 'normal', multi-path or recursive,
 *     depending on the number of paths and their types.
 *   - since path-lists are shared there is only one instance of the multi-path 
 *     adj that they [may] create. As such multi-path adjacencies do not need a
 *     separate DB.
 * The path-list with recursive paths and the recursive adjacency that it
 * contributes forms the backbone of the fast convergence architecture (as 
 * described previously). 
 *
 * fib_path_t:
 *   - a description of how to forward the traffic (i.e. via {Gig1, K}).
 *   - the path describes the intent on how to forward. This differs from how 
 *     the path resolves. I.e. it might not be resolved at all (since the
 *     interface is deleted or down).
 *   - paths have different types, most notably recursive or non-recursive.
 *   - a fib_path_t will contribute the appropriate adjacency object. It is from
 *     these contributions that the DP graph/chain for the route is built.
 *   - if the path is recursive and a recursion loop is detected, then the path
 *     will contribute the special DROP adjacency. This way, whilst the control
 *     plane graph is looped, the data-plane graph does not.
 *
 * we build a graph of these objects;
 *
 *  fib_entry_t -> fib_path_list_t -> fib_path_t -> ...
 *
 * for recursive paths:
 *
 *   fib_path_t -> fib_entry_t -> ....
 *
 * for non-recursive paths
 *
 *  fib_path_t -> ip_adjacency_t -> interface
 *
 * These objects, which constitute the 'control plane' part of the FIB are used
 * to represent the resolution of a route. As a whole this is referred to as the
 * control plane graph. There is a separate DP graph to represent the forwarding
 * of a packet. In the DP graph each object represents an action that is applied
 * to a packet as it traverses the graph. For example, a lookup of a IP address
 * in the forwarding table could result in the following graph:
 *
 *    recursive-adj --> multi-path-adj --> interface_A
 *                                     --> interface_B
 *
 * A packet traversing this FIB DP graph would thus also traverse a VPP node
 * graph of:
 *
 *    ipX_recursive --> ipX_rewrite --> interface_A_tx --> etc
 *
 * The taxonomy of objects in a FIB graph is as follows, consider;
 *
 *   A -->  
 *   B --> D
 *   C -->
 *
 * Where A,B and C are (for example) routes that resolve through D. 
 *  parent; D is the parent of A, B, and C.
 *  children: A, B, and C are children of D. 
 *  sibling: A, B and C are siblings of one another.
 *
 * All shared objects in the FIB are reference counted. Users of these objects
 * are thus expected to use the add_lock/unlock semantics (as one would
 * normally use malloc/free).
 *
 * WALKS
 *
 * It is necessary to walk/traverse the graph forwards (entry to interface) to
 * perform a collapse or build a recursive adj and backwards (interface
 * to entry) to perform updates, i.e. when interface state changes or when
 * recursive route resolution updates occur.
 * A forward walk follows simply by navigating an object's parent pointer to
 * access its parent object. For objects with multiple parents (e.g. a 
 * path-list), each parent is walked in turn.
 * To support back-walks direct dependencies are maintained between objects,
 * i.e. in the relationship, {A, B, C} --> D, then object D will maintain a list
 * of 'pointers' to its children {A, B, C}. Bare C-language pointers are not 
 * allowed, so a pointer is described in terms of an object type (i.e. entry,
 * path-list, etc) and index - this allows the object to be retrieved from the
 * appropriate pool. A list is maintained to achieve fast convergence at scale.
 * When there are millions or recursive prefixes, it is very inefficient to
 * blindly walk the tables looking for entries that were affected by a given
 * topology change. The lowest hanging fruit when optimising is to remove
 * actions that are not required, so all back-walks only traverse objects that
 * are directly affected by the change.
 *
 * PIC Core and fast-reroute rely on FIB reacting quickly to an interface
 * state change to update the multi-path-adjacencies that use this interface.
 * An example graph is shown below:
 *
 *    E_a -->
 *    E_b --> PL_2 --> P_a --> Interface_A
 *    ...          --> P_c -\
 *    E_k -->                \
 *                            Interface_K
 *                            /
 *    E_l -->                /
 *    E_m --> PL_1 --> P_d -/ 
 *    ...          --> P_f --> Interface_F
 *    E_z -->
 *
 * E  = fib_entry_t
 * PL = fib_path_list_t
 * P  = fib_path_t 
 * The subscripts are arbitrary and serve only to distinguish object instances.
 * This CP graph result in the following DP graph:
 *
 *     M-ADJ-2 --> Interface_A
 *             \
 *              -> Interface_K
 *             / 
 *     M-ADJ-1 --> Interface_F
 *
 * M-ADJ = multi-path-adjacency.
 *
 * When interface K goes down a back-walk is started over its dependants in the
 * control plane graph. This back-walk will reach PL_1 and PL_2 and result in
 * the calculation of new adjacencies that have interface K removed. The walk
 * will continue to the entry objects and thus the forwarding table is updated
 * for each prefix with the new adjacency. The DP graph then becomes:
 *
 *    ADJ-3 --> Interface_A
 *
 *    ADJ-4 --> Interface_F
 * 
 * The eBGP PIC scenarios described above relied on the update of a path-list's
 * recursive-adjacency to provide the shared point of cutover. This is shown
 * below
 *
 *    E_a -->
 *    E_b --> PL_2 --> P_a --> E_44 --> PL_a --> P_b --> Interface_A
 *    ...          --> P_c -\
 *    E_k -->                \
 *                            \
 *                           E_1 --> PL_k -> P_k --> Interface_K
 *                            /
 *    E_l -->                /
 *    E_m --> PL_1 --> P_d -/ 
 *    ...          --> P_f --> E_55 --> PL_e --> P_e --> Interface_E
 *    E_z -->
 *
 * The failure scenario is the removal of entry E_1 and thus the paths P_c and
 * P_d become unresolved. To achieve PIC the two shared recursive path-lists,
 * PL_1 and PL_2 must be updated to remove E_1 from the recursive-multi-path-
 * adjacencies that they contribute, before any entry E_a to E_z is updated.
 * This means that as the update propagates backwards (right to left) in the
 * graph it must do so breadth first not depth first. Note this approach leads
 * to convergence times that are dependent on the number of path-list and so
 * the number of combinations of egress PEs - this is desirable as this
 * scale is considerably lower than the number of prefixes.
 *
 * If we consider another section of the graph that is similar to the one
 * shown above where there is another prefix E_2 in a similar position to E_1
 * and so also has many dependent children. It is reasonable to expect that a
 * particular network failure may simultaneously render E_1 and E_2 unreachable.
 * This means that the update to withdraw E_2 is download immediately after the
 * update to withdraw E_1. It is a requirement on the FIB to not spend large
 * amounts of time in a back-walk whilst processing the update for E_1, i.e. the
 * back-walk must not reach as far as E_a and its siblings. Therefore, after the
 * back-walk has traversed one generation (breadth first) to update all the
 * path-lists it should be suspended/back-ground and further updates allowed
 * to be handled. Once the update queue is empty, the suspended walks can be
 * resumed. Note that in the case that multiple updates affect the same entry
 * (say E_1) then this will trigger multiple similar walks, these are merged,
 * so each child is updated only once.
 * In the presence of more layers of recursion PIC is still a desirable
 * feature. Consider an extension to the diagram above, where more recursive
 * routes (E_100 -> E_200) are added as children of E_a:
 *
 * E_100 -->
 * E_101 --> PL_3 --> P_j-\
 * ...                     \
 * E_199 -->               E_a -->
 *                         E_b --> PL_2 --> P_a --> E_44 --> ...etc..
 *                         ...          --> P_c -\
 *                         E_k                    \
 *                                                E_1 --> ...etc..
 *                                                 /
 *                         E_l -->                /
 *                         E_m --> PL_1 --> P_d -/ 
 *                         ...          --> P_e --> E_55 --> ...etc..
 *                         E_z -->
 *
 * To achieve PIC for the routes E_100->E_199, PL_3 needs to be updated before
 * E_b -> E_z, a breadth first traversal at each level would not achieve this.
 * Instead the walk must proceed intelligently. Children on PL_2 are sorted so
 * those Entry objects that themselves have children appear first in the list,
 * those without later. When an entry object is walked that has children, a
 * walk of its children is pushed to the front background queue. The back
 * ground queue is a priority queue. As the breadth first traversal proceeds
 * across the dependent entry object E_a to E_k, when the first entry that does
 * not have children is reached (E_b), the walk is suspended and placed at the
 * back of the queue. Following this prioritisation method shared path-list
 * updates are performed before all non-resolving entry objects.
 * The CPU/core/thread that handles the updates is the same thread that handles
 * the back-walks. Handling updates has a higher priority than making walk
 * progress, so a walk is required to be interruptable/suspendable when new
 * updates are available.
 * !!! TODO - this section describes how walks should be not how they are !!!
 *
 * In the diagram above E_100 is an IP route, however, VPP has no restrictions
 * on the type of object that can be a dependent of a FIB entry. Children of
 * a FIB entry can be (and are) GRE & VXLAN tunnels endpoints, L2VPN LSPs etc.
 * By including all object types into the graph and extending the back-walk, we
 * can thus deliver fast convergence to technologies that overlay on an IP
 * network.
 *
 * If having read all the above carefully you are still thinking;  'i don't need
 * all this %&$* i have a route only I know about and I just need to jam it in',
 * then fib_table_entry_special_add() is your only friend.
 */

#ifndef __FIB_H__
#define __FIB_H__

#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry.h>

#endif
