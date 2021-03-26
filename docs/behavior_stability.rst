
..
    TODO: Move into proper place in doc hierarchy.

VPP Behavior Stability
======================

Preable
-------

In the early days, VPP was prone to sudden changes in API,
CLI, startup.conf and other ways which cause a newer VPP build
to behave differently on old inputs.

Since then, we have tightened the process of evolving API,
and vpp-csit-verify-device-* jobs can vote -1
on any change that affects a small seletion of CSIT tests.
But we want even stronger guarantees.

VPP Usage
---------

Different users consume VPP in different ways,
three main types will be discussed.

In any case, there is VPP itself, and there is bunch of other
software and hardware components, creating a complete "solution".
In this document, all the other components will be grouped together
and called "environment".

For VPP, it is assumed to be an official build downloaded from Packagecloud,
so any patch+build usage is out of scope.
Packagecloud contains both release VPP builds and "snaphot" builds
(both for master branch or for stable/* branches).
Either way, VPP packages are versioned, so it is easy to say which VPP version
is older and which is more recent.

The user environment probably does not have regular enough versioning scheme,
but it is assumed the user can still distinguish older and younger environments.

Releases
________

In this usage type, only official VPP releases are used, including dot releases.
When migrating to new major VPP version, users expect many behavior changes,
and they are ready to investigate them and update the environment to match.

In this case, VPP behavior stability is not that important,
as long as the behavior changes are well documented,
including suggestions on how to update the environment behavior.

The risk of the new deployment (new VPP with new environment) failing
is quite low, but users pay for that in time and effort needed
to update and test the new environment.

Cutting Edge
____________

In this usage type, users try to update VPP as frequently as reasonably possible,
many times focusing on master branch builds.
Ideally, the VPP update is handled by an automated CI/CD process.
Users also update the environment, but those updates are supposed to be
independent from VPP upgrades.

In this case, VPP behavior stability is very important,
as each VPP behavior change can halt the automated VPP upgrade process,
and user needs to investigate and compensate in the environment.

Here is where the current API process
(CRC verifying production messages never change)
is useful, and we want more check in VPP CI/CD to prevent downstream breakages.

CSIT
____

CSIT is an example of downstream user that attempts to handle both releases
and cutting edge.

Cutting edge is obvious, we have daily trending which tests latest VPP builds,
so CSIT code must be able to run its test with them.

Reeases are consumed in a less obvious way.
CSIT is not sensitive to latest release VPP version, as it also uses branches,
and the CSIT release branch is created from CSIT master branch at the time
VPP stable branch is created from VPP master branch.

But the part of CSIT release report is comparison of latest VPP release
with the previous VPP release, so ideally the same CSIT code
should be able to test bost VPP releases.
Also, if any regression (or surprising progression) needs Root Cause Analysis (RCA),
ideally the same CSIT code should be able to test all snapshot VPP builds
between the releases, so we can bisect for the offending VPP change.

Here the rules for deprecating API messages are useful.
This way, new CSIT code can keep using production messages available
on previous VPP release, without them vanishing before new VPP release.
Once RCA is over, CSIT can migrate to newest production messages of the new VPP release
and keep using them the whole next cycle.

Of course, any tests aimed at features not present in the previous VPP release
are free to use as recent (but still production) API messages as possible
(because those tests will not be included in release comparison tables).

TODO: Rolling upgrades
______________________

Imagine a hardware-based (or otherwise stable) load balancer
and three VPP machines behind it.

In default mode, each machine gets a third of the traffic.
But user can reconfigure the load balances to (gracefully) start directing
the traffic only to two VPP machines, so the third one can be stopped,
reinstalled with newer VPP version, started, and load-balancer swithed back
to third-each distribution. Ideally, such "inhomogeneous cluster"
would still work within expectation, so the process can be repeated
two more times to upgrade the other two VPP machines.
This would be a way to upgrade a VPP-based solution
without significant downtime.

This assumes the environment can already handle two VPP versions
(in worse case by a big "if" that call different "VPP handler" sub-components
based on the VPP version deployed on the machine in question).

I feel this use case may have more strict requirements
than the three previously mentioned usage types.
But I am not sure, hence a TODO.

TODO: Downgrades
----------------

For most types, when an issue (e.g. security) is detected late,
the usual procedure is to redeploy with the latest good environment+VPP combo.

For "rolling upgrades" usage type this usually means "rolling downgrade".
TODO in the title mark my feeling there can be some implications
both for "downgrade" and for "rolling".

One common implication of downgrades is in limiting the features available.
Usually, as both VPP and environment are upgraded, users get access
to more and more features / services / other good stuff.
If a feature needs new enough VPP version, it will stop working
if big enough VPP downgrade is applied.
Even if a feature is entirely handled by the environment (VPP version having no effect),
the need of environment to match VPP behavior in other cases
may require big enough environment downgrade to make the feature unavailable.

One again, the existing API procedure helps.
Production API messages stay constant for a long time,
and even for relatively new messages it is possible
they were present in older VPP versions, perhaps marked as in-progress,
but perhaps already compatible with the later behavior.

The effect of downgrades on VPP usage is similar than in CSIT.
We can expect users sticking with non-latest messages for some time,
so when they finally migrate, they have large enough buffer
of older VPP versions to fall back into, without immediate need
to downgrate the rest of the environment.

The "large enough" part can vary wildly between users.
Some want to get latest and greatest features and fixes,
some want to stick to LTS releases.

VPP CI/CD Gating
----------------

This is another privilege of CSIT project.
It is the only user with jobs able to vote -1 on VPP changes
while running code outside VPP project
(though still inside the same fd.io Jenkins and Gerrit).

All other users have to rely on VPP "make test"
and the CSIT voting jobs to cover their articular requirements.

For some users, it may be hard to upstream their solution checks.
For example, the above-mentioned "load balancer and 3 VPPs" setup
is hard to replicate in LFN lab.
Not to mention some solutions may be trade secrets,
with the environment code not being publicly available.

Still, it may be useful to ask downstream users about stories
of how an apparently innocent VPP change broge their CI/CD
and needed a costly upgrade of their environment.
Or maybe just ask for ideas on additional tests
that would make their life easier in general.

Unofficial usage
----------------

The usual example is VPP CLI. It is advertised as "no guarantees",
but some users still use it.
Not sure what to recommend in this case,
aside of prioritizing fixes for any API misbehavior
that incentivises users to look at CLI.

Stable tests
------------

When downstream users suggest some additional tests,
some of them end up implemented as "make test".
The downside of having such tests in VPP repository
is the ease with which a VPP developer contributing
a user-breaking change can "fix" the tests in the same Gerrit change.

Ideally, VPP committers should spot that,
and insist on explanation. Of course, sometimes it is quite hard
to introduce a new and improved VPP behavior
while allowing users to employ the previous less-than-stellar
VPP implementation of almost the same feature.
Especially when the improvement is actually in the way
the feature is to be configured.

So VPP process should allow occasional user-breaking changes
(when discussed and deemed a good tradeoff overall),
while initially refusing all of them (to prevent accidents
and contributors overly eager to remove previous PVP behavior).

I see three major ways to achieve this.

CSIT tests
__________

CSIT uses a different git repository. So if the behavior-guarding test
is implemented in CSIT (and running in one of voting vpp-csit jobs),
the VPP developer would need to pass also CSIT review when editing the test.
CSIT already has a process (mainly intended for API CRC related stuff),
which can be used for any other test failures.

This makes sense for end-to-end behavior, when CSIT test emulates
pats of real user environment.
Not sure if this makes sense if the behavior change
is limited to some small sub-component of VPP already well-covered by "make test".

Test Status
-----------

API messages already have a "status": in-progress, production, deprecated, or non-existent.

The tests executed by make could have the same status flags.
Tests important from user point of view would be marked as Production,
and vpp verify job will vote -1 if it detects any edits affecting such tests.

If a breaking change is deemed worth it,
the affected tests can be quickly marked as deprecated and then deleted.

The hurdle is probably in how an automated verify job detects which tests are affected.
For VPP APIs, we have at least CRC computation that detects formal changes.
Not sure how could we compute a CRC for a test, so it allows inconsequential edits
(e.g. fixing typos in code comments) from consequential ones
(e.g. test superclass changing how is VPP configured).

Test fallback version
---------------------

Once again related to make test.
Instead of tracking status, some tests will have a specified VPP version,
preferably a released one, signifying when a particular VPP behavior
tested here has been "codified".

There will be additional jobs that download the specified VPP version
and run the current tests matching that. This way,
benign test edits will pass, verify job does not need to think
whether a particular Change affects any tests,
and over-eager developers will get -1 if their edit makes the test
expect a different behavior.

Here, VPP committers will have an easier time detecting dangerous edits
(imagine contributor removing an assert to make the edited test pass).
Also, if a contributor moves the fallback VPP version too much forward,
there will be reviewer questions.

Compatibility
=============

Somehow, the text above rarely mentioned behavior compatibility,
but we may want to formalize it and start using it (instead mentioning
user-breaking changes).

The compatibility will be expressed from VPP point of view,
unless secified otherwise.

Backward compatibility
----------------------

A VPP change is backward compatible (with respect to a particular user solution)
if plugging newer VPP build into older user environment
still leads to a solution working within user expectation.

Here, plugging means minimal edits in the environment,
just to ensure a different VPP version is downloaded and installed.
If any additional edits (e.g. startup.conf tweaks) are needed,
the VPP change is no longer backward compatible.

We want to have as much VPP compatibility as reasonably possible,
so that users are not afraid (or otherwise discouraged) to upgrade their VPP
as frequently as they want.

In semantic versioning, any backward incompatible change
means the major version of the software in question (here VPP) has to be bumped.

Forward compatibility
---------------------

A VPP change is forward compatible, if after upgrading VPP
and also upgrading the environment to make use of any new VPP behavior,
the user can downgrade VPP to just before the change, while keeping
new environment (and the resulting solution still works).

Currently, no part of VPP process guards (or warns) against forward incompatible
(but backward compatible) changes.
Obviously, users will benefit if VPP avoids forward incompatible changes,
but of course adding new useful features is a bigger benefit.

TODO: I feel I should give some recommendation, but nothing comes to mind.

In semantic versioning, VPP would bump minor version on (backward compatible but)
forward incompatible change.

Worthy use cases
----------------

Both definitions are relative to a particular user solution,
including plans and processes for environment improvements.

VPP should be signalling which use cases are supported
by the selection of tests with voting power.

Environment changes
-------------------

Just to keep vocabulary complete, changes to user environment can also be
backward or forward compatible with respect to a currently paired VPP version.
But keeping compatibility here is usually not an issue,
as the user (downstream project) has access to the upstream artifact (VPP build),
so it can test compatibility directly, without the need for any surrogate tests.
