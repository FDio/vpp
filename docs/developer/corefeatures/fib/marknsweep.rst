.. _marknsweep:

Mark and Sweep
--------------

The mark and sweep procedures, in FIB and in other subsystems, are
built for the purpose of recovering from a control plane crash.

In routing if the control plane (CP) crashes, when it restarts, the network
topology may have changed. This means that some of the routes that
were programmed in the FIB may no longer be needed, and perhaps some
new ones are. If the CP were simply to insert all the new routes it
learned after it restarts, then FIB could be left with old routes that
never get removed, this would be bigly bad.

At a high level the requirement is to delete routes from the old set
that are not present in the new set; 'delete the diff' as it might
be colloquially known.

How should the control plane determine the old set? It could
conceivably read back the FIB from VPP. But this presents two
problems, firstly, it could be a large set of routes, numbering in the
millions, this is not an efficient mechanism and not one one wants to
perform at a point when the router is trying to converge
ASAP. Secondly it represents a 'source of truth' inversion. The
routing plane is the source of truth, not forwarding. Routing should
not receive its 'input' from the layers below. Thirdly, on a practical
note, the reading of VPP data structures to glean this sort of
accurate information, would only happen in this scenario, i.e. it's
not well tested and therefore not particularly reliable (see point 2).

Enter 'mark and sweep' or m-n-s (not to be confused with the retail
giant) as it's affectionately known.

The Mark and Sweep algorithm proceeds in three steps:

- Step 1; the CP declares to VPP that it wants to begin the process
  (i.e. it has just restarted). At this point VPP will iterate through
  all the objects that the CP owns and 'mark' then as being
  stale. This process effectively declares a new 'epoch', a barrier in
  time that separates the old objects from the new.
- Step 2; The CP downloads all of its new objects. If one of these new
  CP objects matches (has the same key as) an existing object, then
  the CP add is considered an update, and the object's stale state is
  removed.
- Step 3: The CP declares it has 'converged'; it has no more updates
  to give (at this time). VPP will then again iterate through all the
  CP's objects and remove those that do not belong to the new epoch,
  i.e. those that are still marked stale.

After step 3, the CP and VPP databases are in sync.

The cost of the process was to download all the new routes again. This
is a highly-tuned and well-tested scenario.

In VPP we use the synonym 'replace' to describe the mark-n-sweep
action in the API. We use this term because it refers to the goals of
the algorithm at a high level - the CP wants to replace the old DB
with a new one - but it does not specify the algorithm by which that
is achieved. One could equally perform this task by constructing a
brand new DB in VPP, and then swapping them when the CP
converges. Other subsystems may employ that approach, but FIB does
not. Updates are typically faster than adds, since the update is
likely a no-op, whereas a separate add would require the memory
allocator, which is the long pole in FIB additions. Additionally, it requires
twice the memory for a moment in time, which could be prohibitive when
the FIB is large.

