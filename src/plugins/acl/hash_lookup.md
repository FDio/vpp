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
ACEs, and will assign the "mask type number" to it.

Assigning ACLs to an interface
------------------------------

Once the ACL list is assigned to an interface, a new bihash will be created,
and a pass will be made throughout all the entries of all the assigned ACLs,
populating this bihash, with the key being: { mask type number, ACE value },
and the value being { u64 (acl index within vector, ACE index), ACL index,
collision vector index }.

The keys are formed in this way in order to avoid a situation where we have
two ACEs whose values are the same but the masks are different, e.g.:
`permit ::/0, permit ::/128` - so if we did the lookup just on the value
alone, we would have to make secondary logic to try to disambiguate.
By adding the mask type index into the key, we avoid that.

Also, a vector of masks will be prepared, based on the mask type numbers
used within the given vector of ACLs assigned to an interface. Those will
be used during the per-packet lookup. Also, a per-worker vector of
`5-tuple`+`mask_id` to be used as keys will need to be made.
Those will be also used during the packet lookup.

The collision vector is there to allow to incrementally apply/unapply
the ACLs as part of the vector: say, two ACLs have
"permit 2001:db8::1/128 any" - we should be able to retain the entry
for the second ACL even if we have deleted the first one.
The "collision vector" is a vector containing the data (ACL index, ACE index),
such that we can rebuild the main contents of the key when deleting a
preceding ACL with a duplicate match.

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

The constant-time lookup within the data path hash the API with
the same signature as:

```
u8
full_acl_match_5tuple (u32 sw_if_index, fa_5tuple_t * pkt_5tuple, int is_l2,
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


