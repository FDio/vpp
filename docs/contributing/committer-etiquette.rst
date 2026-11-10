.. _committer_etiquette:

*******************************
Committer Etiquette
*******************************

**Role split:** Maintainers review code. Committers merge it. Being a
committer doesn't make you the reviewer.

#. **Merge only with a maintainer's approval.**

   - Check ``MAINTAINERS`` for the component the change touches.
   - A component may have several maintainers. **One is enough** to +1 (or +2).
   - If you are a maintainer of the component, you can +2 and merge directly.
   - A change that touches several components needs one maintainer's +1 from
     each affected component, unless item 2 applies.

#. **Exception: small, mechanical, cross-cutting changes.**

   - Examples are a function or macro rename, a header move, or a trivial
     signature update across the codebase.
   - A +1 from one maintainer of the most affected component is enough.
   - The change must be purely mechanical, with no behaviour change and no
     design decisions. Say so in the commit message.
   - If any maintainer objects, normal rules resume.

#. **Exception: trivial changes.** A committer may merge these without
   maintainer review. Examples:

   - Typo fixes in comments, docs and log messages.
   - Coverity or other static-analysis annotations and false-positive markers.
   - Whitespace and ``make checkstyle`` fixes.
   - Removing dead or obsolete comments.
   - Broken links or formatting in docs.
   - Fixing a build break, or reverting a change that broke master.
   - Adding a missing ``const``, ``static`` or ``__clib_unused`` that doesn't
     change behaviour.

   Conditions:

   - The change has no behaviour change and touches no API, ABI or CLI output.
   - It is a handful of lines, not a sweep.
   - If in doubt, treat it as non-trivial and ask a maintainer.
   - Mention a maintainer on the change if the area is theirs. They may ask
     for a revert.
   - Don't use a series of "trivial" commits to slip in a bigger change.

#. **No maintainer response, no merge.** If the maintainers of a component are
   silent on a non-trivial change, ping them on the change or on vpp-dev.
   Don't merge on your own judgment, and don't treat silence as consent.

#. **Don't merge your own change** unless it is trivial under item 3 or you are
   a maintainer of the component. A maintainer author may merge their own
   change, but for non-trivial changes should get another maintainer's or
   committer's eyes on it when one is available.

#. **Check the state before merging.**

   - Verified +1.
   - No unresolved -1 from anyone, including other maintainers of the component.
   - No open "please wait" request.
   - No unaddressed design discussion on the change or in vpp-dev.

#. **Don't merge a change you think is wrong.** If you disagree with a
   maintainer's +1, say so on the change or take it to vpp-dev. Don't merge
   quietly, and don't veto silently.

#. **Mind the release calendar.** Don't merge risky changes close to a freeze,
   and don't merge features after freeze without the release manager's
   agreement.

#. **Merge with no company bias.** Don't prioritize your employer's changes
   over others in the queue.
