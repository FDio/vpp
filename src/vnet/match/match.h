/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef __MATCH_H__
#define __MATCH_H__

/**
 * Match infrastructure.
 *
 * DEFINITIONS:
 *
 * There are two types of match semantics defined; 'any' and 'first';
 *   any; given a lsit of rules if any one of those rules matches - return true
 *   first; given a list of rules - return the index of the first that matched.
 *
 * A match class/type defines the fields in the packet that are matched. For example
 * an exact IP+MAC or complex masking of many fields (like one would expect of an
 * ACL).

 *
 * BASIC USAGE:
 *
 * We define two entities in packet matching, the match infrastructure (this code)
 * and the client. The match infra provides:
 *  - templates for describing classes of matches. These are rules.
 *  - datastructures (lists and sets) to group rules into composite matches
 *  - functions in the data-plane to perform the matches
 *
 * The client provides:
 *  - instances of the rules, lists, sets, describing the values and fields to
 *    match against.
 *  - An application of the set - This is an instruction to the match infra that
 *    a set will be applied to class of packets
 *  - The action to perform when a match is found or not found.
 *
 *
 * As an example, let's consider a simple ACL implementation that performs exact
 * match on IP and MAC address, that we would like to apply to all packets in
 * a bridge.
 * We begin in the client by defining the rules.
 *  match_rule_t r1 = {
 *     .type = EXACT_IP_AND_MAC,
 *     .rule = {
 *       .ip = "10.10.10.10",
 *       .mac = "00:11:22:33:44:55",
 *     },
 *  };
 *  etc, (the field names and values are representative for explanation purposes)
 *
 * The rules are then grouped into a list:
 *
 *   match_list_t l1 = [r1, r2, r3, ... ];
 *
 * Whilst building the rules, the client also constructs the actions. So for each
 * rule there is one action, in this case a choice between permit and deny;
 *
 *  acl_action_t a1 = [a1, a2, a3, ...]
 *
 * where each entry in a1 corresonds to a rule in l1.
 * this separation of match and action, allows the match infra to remain separate
 * from the application using it, and hence makes the match infra reusable by many
 * clients.
 *
 * The list added to a set:
 *
 *   match_set_t s = match_set_create_and_lock (my_name, my_heap);
 *
 *   hdl = match_set_add_list (s, l1, a1);
 *
 * When adding the list, the client also provides the actions (as an opaque void*).
 * This is so the actions can be amde available to the client in the DP (see later).
 * The heirachy of rules, lists, sets, is desgined this way so the client has the
 * option to simply replace  a list in a set, rather than reconstruct a new list
 * of rules each time a rule changes.
 *
 * The client then 'applies' the set on a packet type. In our case we want to apply
 * the matching in the L2 path, thus the type of packet we will see are ethernet.
 *
 *  app = match_set_apply (s, FIRST, ETHERNET, tag_flags);
 *
 * Where tag_flags describes how many VLAN tags will be present on packets seen
 * in the DP. Since we have an action associated with each rule, and we expect
 * the list to be search in order, we need the 'first' match semantics.
 * If we wanted to apply the ACL to all packets in the bridge we might
 * then create a mapping between the bridge-domain ID and the app, or if we wanted
 * the ACL to apply to a specific interface, we would create an app to sw_if_index
 * mapping. Either way, the app msut be available in the DP, presumably via a
 * mapping of this sort.
 *
 * In the DP the client has its own vlib node, in our case to perform the ACL
 * enforcement, The first pass through the frame of buffers must construct
 * the array of 'apps' in which the match is performed. i.e.
 *
 * for_each_index(i, buffers)
 *   apps[i] = map_table[buffers[i].sw_if_index]
 *
 * Then, to perform the match, the client calls the matcher function
 *
 *   match (buffers, n_buffers, apps, results);
 *
 * the return value is the results array, that  describes which rule in the set
 * matched and appropriate client provided array of actions.
 * The client can then perform the action, i.e.
 *
 * for_each(result, results) {
 *   switch (result.action[result.rule_index]) {
 *     case PERMIT:
 *       next = <next-node>;
 *     case DROP:
 *       next = 'error-drop'
 *   }
 * }
 *
 *
 * MATCH ENGINES
 *
 *
 * For different combinations of class and semantic the best algorithm to
 * perform the match in the DP will be different.
 * For example, the VPP vnet_classifier can always provide 'any' semantics on all
 * classes. Each list can be renderer as a chain of tables, a hit in any table gives
 * the 'return true' samntics required from 'any'. it can also provide 'first'
 * semantics if the class has only one masked field (i.e. if only the IP address
 * is masked) - we do this by ordering the tables in the chain based on longest
 * prefix match. However, once there is more than one masked field, the order
 * cannot be determined.
 * On the other hand a simple liner search (matching against one rule at a time)
 * can always provide 'first' semantics.
 *
 * Engines are the solution to this 'which match algothim to use' problem.
 *
 * VPP provides several engine types (plugins can provide others). An engine
 * registers itself at a particular priority as being able to provide a match
 * algorithm for a particular semantic-class pair. the match infra will choose
 * the best engine to use when the client 'applys' the set.
 * This technique allows the clients to be decoupled from the matching algo
 * and to allow VPP to be easily extensible with more algos, which can in turn
 * beneift multiple clients.
 */

#include <vnet/match/match_types.h>

extern void match_list_free (match_list_t * ml);
extern void match_list_init (match_list_t * ml,
			     const u8 * tag, u32 n_entries);
extern void match_list_copy (match_list_t * dst, const match_list_t * src);
extern void match_list_push_back (match_list_t * ml, const match_rule_t * me);
extern u32 match_list_length (const match_list_t * ml);
extern void match_rule_copy (match_rule_t * dst, const match_rule_t * src);
extern void match_rule_free (match_rule_t * me);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
