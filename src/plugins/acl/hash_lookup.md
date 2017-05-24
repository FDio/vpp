ACL plugin constant-time lookup design
======================================

The initial implementation of ACL plugin performs a trivial for() cycle,
going through the assigned ACLs on a per-packet basis. This is not very
efficient, even if for very short ACLs due to its simplicity it can beat
more advanced methods.

However, to cover the case of longer ACLs with acceptable performance,
we need to have a better way of matching. This write-up proposes
a mechanism to make a lookup from O(M) where M is number of entries
to O(N) where N is number of different mask combinations.

Preparation of ACL(s)
---------------------

The ACL plugin will maintain a global list of "mask types", i.e. the specific
configurations of "do not care" bits within the ACEs.
Upon the creation of a new ACL, a pass will be made through all the
ACEs, to assign and possibly allocate the "mask type number".

Each ACL has a structure *hash_acl_info_t* representing the "hash-based"
parts of information related to that ACL, primarily the array of
*hash_ace_info_t* structures - each of the members of that array
corresponding to one of the rules (ACEs) in the original ACL,
for this they have a pair of *(acl_index, ace_index)* to keep track,
predominantly for the debugging.

Why do we need a whole separate structure, and are not adding new fields
to the existing rile structure ? First, encapsulation, to minimize
the pollution of the main ACL code with the hash-based lookup artifacts.

Second, one rule may correspond to more than one "hash-based" ACE.
In fact, most of the rules do correspond to two of those. Why ?

Consider that the current ACL lookup logic is that if a packet
is not the initial fragment, and there is an L4 entry acting on the packet,
the comparison will be made only on the L4 protocol field value rather
than on the protocol and port values. This beaviour is governed by
*l4_match_nonfirst_fragment* flag in the *acl_main*, and was needed to
maintain the compatibility with the existing software switch implementation.

While for the sequential check in *single_acl_match_5tuple()*
it is very easy to implement by just breaking out at the right moment,
in case of hash-based matching this cost us two checks:
one on full 5-tuple and the flag *pkt.is_nonfirst_fragment* being zero,
the second on 3-tuple and the flag *pkt.is_nonfirst_fragment* being one,
with the second check triggered by the *acl_main.l4_match_nonfirst_fragment*
setting being the default 1. This dictates the necessity of having a "match"
field in a given *hash_ace_info_t* element, which would reflect the value
we are supposed to match after applying the mask.

There can be other circumstances when it might be beneficial to expand
the given rule in the original ACL into multiple - for example, as an
optimization within the port range handling for small port ranges
(this is not done as of the time of writing).

Assigning ACLs to an interface
------------------------------

Once the ACL list is assigned to an interface, or, rather, a new ACL
is added to the list of the existing ACLs applied to the interface,
we need to update the bihash accelerating the lookup.

All the entries for the lookups are stored within a single *48_8* bihash,
which captures the 5-tuple from the packet as well as the miscellaneous
per-packet information flags, e.g. *l4_valid*, *is_non_first_fragment*,
and so on. To facilitate the use of the single bihash by all the interfaces,
the *is_ip6*, *is_input*, *sw_if_index* are part of the key,
as well as *mask_type_index* - the latter being necessary because
there can be entries with the same value but different masks, e.g.:
`permit ::/0, permit::/128`.

At the moment of an ACL being applied to an interface, we need to
walk the list of *hash_ace_info_t* entries corresponding to that ACL,
and update the bihash with the keys corresponding to the match
values in these entries.

The value of the hash match contains the index into a per-*sw_if_index* vector
of *applied_ace_hash_entry_t* elements, as well as a couple of flags:
*shadowed* (optimization: if this flag on a matched entry is zero, means
we can stop the lookup early and declare a match - see below),
and *need_portrange_check* - meaning that what matched was a superset
of the actual match, and we need to perform an extra check.

Also, upon insertion, we must keep in mind there can be
multiple *applied_ace_hash_entry_t* for the same key and must keep
a list of those. This is necessary to incrementally apply/unapply
the ACLs as part of the ACL vector: say, two ACLs have
"permit 2001:db8::1/128 any" - we should be able to retain the entry
for the second ACL even if we have deleted the first one.
Also, in case there are two entries with the same key but
different port ranges, say 0..42 and 142..65535 - we need
to be able to sequentially match on those if we decide not
to expand them into individual port-specific entries.

Per-packet lookup
-----------------

The per-packet lookup is batched in three phases:

1. Prepare the keys in the per-worker vector by doing logical AND of
   original 5-tuple record with the elements of the mask vector.
2. Lookup the keys in the bihash in a batch manner, collecting the
   result with lowest u64 (acl index within vector, ACE index) from
   the hash lookup value.
3. Take the action from the ACL record as defined by (ACL#, ACE#) from the
   resulting lookup winner, or, if no match found, then perform default deny.

Plumbing
--------

All the new routines are located in a separate file,
so we can cleanly experiment with a different approach if this
does not fit all of the use cases.

The constant-time lookup within the data path has the API with
the same signature as:

```
u8
multi_acl_match_5tuple (u32 sw_if_index, fa_5tuple_t * pkt_5tuple, int is_l2,
                       int is_ip6, int is_input, u32 * acl_match_p,
                       u32 * rule_match_p, u32 * trace_bitmap)
```

There should be a new upper-level function with the same signature, which
will make a decision whether to use a linear lookup, or to use the
constant-time lookup implemented by this work, or to add some other
optimizations (e.g. by keeping the cache of the last N lookups).

The calls to the routine doing preparatory work should happen
in `acl_add_list()` after creating the linear-lookup structures, 
and the routine doing the preparatory work populating the hashtable
should be called from `acl_interface_add_del_inout_acl()` or its callees.


