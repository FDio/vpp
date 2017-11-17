Lookup contexts aka "ACL as a service" {#acl_lookup_context}
======================================

The initial implementation of the ACL plugin had tightly tied the policy (L3-L4) ACLs
to ingress/egress processing on an interface.

However, some uses outside of pure traffic control have appeared, for example,
ACL-based forwarding, etc. Also, improved algorithms of the ACL lookup
could benefit of the more abstract representation, not coupled to the interfaces.

This describes a way to accomodate these use cases by generalizing the ACL
lookups into "ACL lookup contexts", not tied to specific interfaces, usable
by other portions of the code by utilizing the exports.h header file,
which provides the necessary interface.


Why "lookup contexts" and not "match me an ACL#" ?
================================================

The first reason is the logical grouping of multiple ACLs.

The interface matching code currently allows for matching multiple ACLs
in a 'first-match' fashion. Some other use cases also fall into a similar
pattern: they attemt to match a sequence of ACLs, and the first matched ACL
determines what the outcome is, e.g. where to forward traffic. Thus,
a match never happens on an ACL in isolation, but always on a group of
ACLs.

The second reason is potential optimizations in matching.

A naive match on series of ACLs each represented as a vector of ACEs
does not care about the API level - it could be "match one ACL", or
"match the set of ACLs" - there will be just a simple loop iterating over
the ACLs to match, returning the first match. Be it in the ACL code or
in the user code.

However, for more involved lookup methods, providing a more high-level
interface of matching over the entire group of ACLs allows for future
improvements in the algorithms, delivered at once to all the users
of the API.

What is a "lookup context" ?
============================

An ACL lookup context is an entity that groups the set of ACL#s
together for the purposes of a first-match lookup, and may store
additional internal information needed to optimize the lookups
for that particular vector of ACLs.



