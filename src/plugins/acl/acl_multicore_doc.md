Multicore support for ACL plugin    {#acl_multicore}
================================

This captures some considerations and design decisions that I have made,
both for my own memory later on ("what the hell was I thinking?!?"),
and for anyone interested to criticize/improve/hack on this code.

One of the factors taken into account while making these decisions,
was the relative emphasis on the multi-thread vs. single-thread
use cases: the latter is the vastly more prevalent. But,
one can not optimize the single-thread performance without
having a functioning code for multi-thread.

stateless ACLs
==============

The stateless trivially parallelizes, and the only potential for the
race between the different threads is during the reconfiguration,
at the time of replacing the old ACL being checked, with
the new ACL.

In case an acl_add_replace is being used to replace the rules
within the existing entry, a reallocation of `am->acls[X].rules`
vector will happen and potentially a change in count.

acl_match_5tuple() has the following code:

```{.c}
  a = am->acls + acl_index;
  for (i = 0; i < a->count; i++)
    {
      r = a->rules + i;
     . . .
```

Ideally we should be immune from a->rules changing,
but the problem arises if the count changes in flight,
and the new ruleset is smaller - then we will attempt
to "match" against the free memory.

This can(?) be solved by replacing the for() with while(),
so the comparison happens at each iteration.

full_acl_match_5tuple(), which iterates over the list
of ACLs, is a bit less immune, since it takes the pointer
to the vector to iterate and keeps a local copy of
that pointer.

This race can be solved by checking the
current pointer to the vector with the source pointer,
and seeing if there is an (unlikely) change, and if
there is, return the "deny" action, or, better,
restart the check.

Since the check reloads the ACL list on a per-packet basis,
there is only a window of opportunity of one packet to
"match" packet against an incorrect rule set.
The workers also do not change anything, only read.
Therefore, it looks like building special structures
to ensure that it does not happen at all might be not
worth it.

At least not until we have a unit-test able to
reliably catch this condition and test that
the measures applied are effective. Adding the code
which is not possible to exercise is worse than
not adding any code at all.

So, I opt for "do-nothing" here for the moment.

reflexive ACLs: single-thread
=============================

Before we talk multi-thread, is worth revisiting the
design of the reflexive ACLs in the plugin, and
the history of their evolution.

The very first version of the ACL plugin, shipped in
1701, mostly did the job using the existing components
and gluing them together. Because it needed to work
in bridged forwarding path only, using L2 classifier
as an insertion point appeared natural, also L2 classifier,
being a table with sessions, seemed like a good place
to hold the sessions.

So, the original design had two conceptual nodes:
one, pointed by the next_miss from the L2 classifier table,
was checking the actual ACL, and inserting session into
the L2 classifier table, and the other one, pointed
to by the next_match within the specific session rule,
was checking the existing session. The timing out
of the existing connections was done in the datapath,
by periodically calling the aging function.

This decision to use the existing components,
with its attrativeness, did bring a few limitations as well:

* L2 classifier is a simple mask-and-value match, with
a fixed mask across the table. So, sanely supporting IPv6
packets with extension headers in that framework was impossible.

* There is no way to get a backpressure from L2 classifier
depending on memory usage. When it runs out of memory,
it simply crashes the box. When it runs out of memory ?
We don't really know. Depends on how it allocates it.

* Since we need to match the *reflected* traffic,
we had to create *two* full session entries
in two different directions, which is quite wasteful memory-wise.

* (showstopper): the L2 classifier runs only in
the bridged data path, so supporting routed data path
would require creating something else entirely different,
which would mean much more headaches support-wise going forward.

Because of that, I have moved to a different model of
creating a session-5-tuple from the packet data - once,
and then doing all the matching just on that 5-tuple.

This has allowed to add support for skipping IPv6 extension headers.

Also, this new version started to store the sessions in a dedicated
bihash-per-interface, with the session key data being
aligned for the ingress packets, and being mirrored for the
egress packets. This allows of significant savings in memory,
because now we need to keep only one copy of the session table per
interface instead of two, and also to only have ONE node for all the lookups,
(L2/L3 path, in/out, IPv4/IPv6) - significantly reducing the code complexity.

Unfortunately, bihash still has the "lack of backpressure" problem,
in a sense that if you try to insert too many entries and run out
of memory in the heap you supplied, you get a crash.

To somewhat workaround against that, there is a "maximum tested number of sessions"
value, which tracks the currently inserted sessions in the bihash,
and if this number is being approached, a more aggressive cleanup
can happen. If this number is reached, two behaviors are possible:

* attempt to do the stateless ACL matching and permit the packet
  if it succeeds

* deny the packet

Currently I have opted for a second one, since it allows for
a better defined behavior, and if you have to permit
the traffic in both directions, why using stateful anyway ?

In order to be able to do the cleanup, we need to discriminate between
the session types, with each session type having its own idle timeout.
In order to do that, we keep three lists, defined in enum acl_timeout_e:
ACL_TIMEOUT_UDP_IDLE, ACL_TIMEOUT_TCP_IDLE, ACL_TIMEOUT_TCP_TRANSIENT.

The first one is hopefully obvious - it is just all UDP connections.
They have an idle timeout of 600 seconds.

The second and third is a bit more subtle. TCP is a complicated protocol,
and we need to tread the fine line between doing too little and doing
too much, and triggering the potential compatibility issues because of
being a "middlebox".

I decided to split the TCP connections into two classes:
established, and everything else. "Established", means we have seen
the SYN and ACK from both sides (with PUSH obviously masked out).
This is the "active" state of any TCP connection and we would like
to ensure we do not screw it up. So, the connections in this state
have the default idle timer of 24 hours.

All the rest of the connections have the idle timeout of 2 minutes,
(inspired by an old value of MSL) and based on the observation
that the states this class represent are usually very short lived.

Once we have these three baskets of connections, it is trivial to
imagine a simple cleanup mechanism to deal with this: take a
TCP transient connection that has been hanging around.

It is debatable whether we want to do discrimination between the
different TCP transient connections. Assuming we do FIFO (and
the lists allow us to do just that), it means a given connection
on the head of the list has been hanging around for longest.
Thus, if we are short on resources, we might just go ahead and
reuse it within the datapath.

This is where we are slowly approaching the question
"Why in the world have not you used timer wheel or such ?"

The answer is simple: within the above constraints, it does
not buy me much.

Also, timer wheel creates a leaky abstraction with a difficult
to manage corner case. Which corner case ?

We have a set of objects (sessions) with an event that may
or may not happen (idle timeout timer firing), and a
necessity to reset the idle timeout when there is
activity on the session.

In the worst case, where we had a 10000 of one-packet
UDP sessions just created 10 minutes ago, we would need
to deal with a spike of 10000 expired timers.

Of course, if we have the active traffic on all
of these 10000 connections, then we will not have
to deal with that ? Right, but we will still have to deal
with canceling and requeueing the timers.

In the best possible case, requeueing a timer is
going to be something along the lines of a linked-list
removal and reinsertion.

However, keep in mind we already need to classify the
connections for reuse, so therefore we already have
the linked lists!

And if we just check these linked lists periodically in
a FIFO fashion, we can get away with a very simple per-packet operation:
writing back the timestamp of "now" into the connection structure.

Then rather than requeueing the list on a per-packet or per-frame
basis, we can defer this action until the time this session
appears on the head of the FIFO list, and the cleaning
routine makes the decision about whether to discard
the session (because the interval since last activity is bigger
than the idle timeout), or to requeue the session back to
the end of the list (because the last activity was less
than idle timeout ago).

So, rather than using the timers, we can simply reuse our classification
FIFOs, with the following heuristic: do not look at the session that was
enqueued at time X until X+session_timeout. If we enqueue the sessions
in the order of their initial activity, then we can simply use enqueue
timestamp of the head session as a decision criterion for when we need
to get back at looking at it for the timeout purposes.

Since the number of FIFOs is small, we get a slightly worse check
performance than with timers, but still O(1).

We seemingly do quite a few "useless" operations of requeueing the items
back to the tail of the list - but, these are the operations we do not
have to do in the active data path, so overall it is a win.

(Diversion: I believe this problem is congruent to poll vs. epoll or
events vs. threads, some reading on this subject:
http://web.archive.org/web/20120225022154/http://sheddingbikes.com/posts/1280829388.html)

We can also can run a TCP-like scheme for adaptively changing
the wait period in the routine that deals with the connection timeouts:
we can attempt to check the connections a couple of times per second
(same as we would advance the timer wheel), and then if we have requeued
close to a max-per-quantum number of connections, we can half the waiting
interval, and if we did not requeue any, we can slowly increment the waiting
interval - which at a steady state should stabilize similar to what the TCP rate
does.

reflexive ACLs: multi-thread
=============================

The single-threaded implementation in 1704 used a separate "cleaner" process
to deal with the timing out of the connections.
It is all good and great when you know that there is only a single core
to run everything on, but the existence of the lists proves to be
a massive difficulty when it comes to operating from multiple threads.

Initial study shows that with a few assumptions (e.g. that the cleaner running in main thread
and the worker have a demarcation point in time where either one or the other one touches
the session in the list) it might be possible to make it work, but the resulting
trickiness of doing it neatly with all the corner cases is quite large.

So, for the multi-threaded scenario, we need to move the connection
aging back to the same CPU as its creation.

Luckily we can do this with the help of the interrupts.

So, the design is as follows: the aging thread (acl_fa_session_cleaner_process)
periodically fires the interrupts to the workers interrupt nodes (acl_fa_worker_session_cleaner_process_node.index),
using vlib_node_set_interrupt_pending(), and
the interrupt node acl_fa_worker_conn_cleaner_process() calls acl_fa_check_idle_sessions()
which does the actual job of advancing the lists. And within the actual datapath the only thing we will be
doing is putting the items onto FIFO, and updating the last active time on the existing connection.

The one "delicate" part is that the worker for one leg of the connection might be different from
the worker of another leg of the connection - but, even if the "owner" tries to free the connection,
nothing terrible can happen - worst case the element of the pool (which is nominally free for a short period)
will get the timestamp updated - same thing about the TCP flags seen.

A slightly trickier issue arises when the packet initially seen by one worker (thus owned by that worker),
and the return packet processed by another worker, and as a result changes the
the class of the connection (e.g. becomes TCP_ESTABLISHED from TCP_TRANSIENT or vice versa).
If the class changes from one with the shorter idle time to the one with the longer idle time,
then unless we are in the starvation mode where the transient connections are recycled,
we can simply do nothing and let the normal requeue mechanism kick in. If the class changes from the longer idle
timer to the shorter idle timer, then we risk keeping the connection around for longer than needed, which
will affect the resource usage.

One solution to that is to have NxN ring buffers (where N is the number of workers), such that the non-owner
can signal to the owner the connection# that needs to be requeued out of order.

A simpler solution though, is to ensure that each FIFO's period is equal to that of a shortest timer.
This way the resource starvation problem is taken care of, at an expense of some additional work.

This all looks sufficiently nice and simple until a skeleton falls out of the closet:
sometimes we want to clean the connections en masse before they expire.

There few potential scenarios:
1) removal of an ACL from the interface
2) removal of an interface
3) manual action of an operator (in the future).

In order to tackle this, we need to modify the logic which decides whether to requeue the
connection on the end of the list, or to delete it due to idle timeout:

We define a point in time, and have each worker thread fast-forward through its FIFO,
in the process looking for sessions that satisfy the criteria, and either keeping them or requeueing them.

To keep the ease of appearance to the outside world, we still process this as an event
within the connection cleaner thread, but this event handler does as follows:
1) it creates the bitmap of the sw_if_index values requested to be cleared
2) for each worker, it waits to ensure there is no cleanup operation in progress (and if there is one,
it waits), and then makes a copy of the bitmap, sets the per-worker flag of a cleanup operation, and sends an interrupt.
3) wait until all cleanup operations have completed.

Within the worker interrupt node, we check if the "cleanup in progress" is set,
and if it is, we check the "fast forward time" value. If unset, we initialize it to value now, and compare the
requested bitmap of sw_if_index values (pending_clear_sw_if_index_bitmap) with the bitmap of sw_if_index that this worker deals with.

(we set the bit in the bitmap every time we enqueue the packet onto a FIFO - serviced_sw_if_index_bitmap in acl_fa_conn_list_add_session).

If the result of this AND operation is zero - then we can clear the flag of cleanup in progress and return.
Else we kick off the quantum of cleanup, and make sure we get another interrupt ASAP if that cleanup operation returns non-zero,
meaning there is more work to do.
When that operation returns zero, everything has been processed, we can clear the "cleanup-in-progress" flag, and
zeroize the bitmap of sw_if_index-es requested to be cleaned.

The interrupt node signals its wish to receive an interrupt ASAP by setting interrupt_is_needed
flag within the per-worker structure. The main thread, while waiting for the
cleanup operation to complete, checks if there is a request for interrupt,
and if there is - it sends one.

This approach gives us a way to mass-clean the connections which is reusing the code of the regular idle
connection cleanup.

One potential inefficiency is the bitmap values set by the session insertion
in the data path - there is nothing to clear them.

So, if one rearranges the interface placement with the workers, then the cleanups will cause some unnecessary work.
For now, we consider it an acceptable limitation. It can be resolved by having another per-worker bitmap, which, when set,
would trigger the cleanup of the bits in the serviced_sw_if_index_bitmap).

=== the end ===

