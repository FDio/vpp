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

Using ACL contexts in your code
===============================

In order to use the ACL lookup contexts, you need to include
plugins/acl/exports.h into your code. This header includes
all the necessary dependencies required.

As you probably will invoke this code from another plugin,
the non-inline function calls are implemented via function pointers,
which you need to initialize by calling acl_plugin_exports_init(&acl_plugin), which,
if everything succeeds, returns 0 and fills in the acl_plugin structure
with pointers to the exported methods - else it will return clib_error_t with
more information about what went wrong.

When you have initialized the symbols, you also need to register yourself
as a user of the ACL lookups - this allows to track the ACL lookup context
ownership, as well as make the debug show outputs more user friendly.

To do that, call acl_plugin.register_user_module(caller_module_string, val1_label, val2_label) -
and record the returned value. This will bethe first parameter that you pass to create a new
lookup context. The passed strings must be static, and are used as descriptions for the ACL
contexts themselves, as well as labels for up to two user-supplied u32 labels, used to
differentiate the lookup contexts for the debugging purposes.

Creating a new context is done by calling acl_plugin.get_lookup_context_index(user_id, val1, val2).
The first argument is your "user" ID obtained in a registration call earlier, the other two
arguments are u32s with semantics that you designate. They are used purely for debugging purposes
in the "show acl lookup context" command.

To set the vector of ACL numbers to be looked up within the context, use the function
acl_plugin.set_acl_vec_for_context(lc_index, acl_list). The first parameter specifies the context
that you have created, the second parameter is a vector of u32s, each u32 being the index of the ACL
which we should be looking up within this context. The comand is idempotent, i.e.
it unapplies the previously applied list of ACLs, and then sets the new list of ACLs.

Subsequent ACL updates for the already applied ACLs will cause the re-application
on an as-needed basis. Note, that the ACL application is potentially a relatively costly operation,
so it is only expected that these changes will be done in the control plane, NOT in the datapath.

The matching within the context is done using two functions - acl_plugin.fill_5tuple() and
acl_plugin.match_5tuple() and their corresponding inline versions, named acl_plugin_fill_5tuple_inline()
and acl_plugin_match_5tuple_inline(). The inline and non-inline versions have the equivalent functionality,
in that the non-inline version calls the inline version. These two variants are provided
for debugging/maintenance reasons.

When you no longer need a particular context, you can return the allocated resources by calling
acl_plugin.put_lookup_context_index() to mark it as free. The lookup structured associated with
the vector of ACLs set for the lookup are cleaned up automatically. However, the ACLs themselves
are not deleted and are available for subsequent reuse by other lookup contexts if needed.

There is one delicate detail that you might want to be aware of.
When the non-inline functions reference the inline functions,
they are compiled as part of ACL plugin; whereas when you refer to the inline
functions from your code, they are compiled as part of your code.
This makes referring to a single acl_main structure a little trickier.

It is done by having a static p_acl_main within the .h file, 
which points to acl_main of the ACL plugin, and is initialized by a static constructor
function.

This way the multiple includes and inlines will "just work" as one would expect.


Debug CLIs
==========

To see the state of the ACL lookup contexts, you can issue "show acl-plugin lookup user" to see
all of the users which registered for the usage of the ACL plugin lookup contexts,
and "show acl-plugin lookup context" to show the actual contexts created. You will notice
that the latter command uses the values supplied during the module registration in order to
make the output more friendly.

The "show acl-plugin acl" and "show acl-plugin interface" commands have also acquired the
notion of lookup context, but there it is used from the client perspective, since
with this change the interface ACL lookup itself is a user of ACL lookup contexts.

