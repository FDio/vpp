VPP tests: philosophy and expectations {#test_policy}
=======================================================

The VPP tests coexist in the same repository as VPP itself, and exist
to define and enforce the basic *expectations* of VPP *behaviors*,
which are verified before merging each new commit.

These expectations are verified by manipulating the running VPP process (UUT)
by a Test Class, running within the process model defined
by the test framework - which takes care of the common tasks like
starting the VPP, collecting the crash dumps, dispatching tests
in case of parallel testing, etc.

There are two highlighted words above that will need further clarification:

Expectation
-----------

"Expected" means "as explicitly expected by the developers/maintainers,
or by the consensus that emerged as a result of a discussion of the
previously uncertain behavior".

Some of the "expected" behaviors are very obvious - it is "expected"
that VPP will not crash during the operation, and this enforced in
all the test runs as a basic premise.

Some of the other "expected" behaviors are a bit less obvious:
it is expected that each test case completes within a reasonable
time. How long this time is ? The shorter - the better, of course.
And, probably running for 2 minutes with no user feedback is not
acceptable. But we are still in progress of figuring the boundary
here - which is why each test case prints its elapsed runtime
after completion.

And of course the majority of "expected" behaviors are encoded
into the tests themselves. Most of the testcases follow the same
pattern:

- do something with the API (and verify the replies are as expected)
- build a few PCAP files and inject them into VPP using pg packet generator
- capture the results and verify that the results are as per expected behavior.


Behaviors
---------

"Behavior" in this context is the functional side of the VPP.
None of the tests should be construed as performance or scale.
There can be correctness tests of in the style of iterating over
the range of the style "1, 10x, 100x", and ensuring the results
make sense.

The behavior can be either mostly cause-and-effect ("sent an API message,
got the expected response"), or time-dependent ("sent an API message,
verified FOO was created, verified FOO was deleted after N time").

This brings us to the discussion of time dependencies.


Time dependencies in tests and their variations
-----------------------------------------------

There are two time dependencies that can be observed in tests:

1) asynchronous

"as soon as it is possible", or causal time dependency.
The classic example is an API call. We care that the API result returns 
as soon as possiblei *as a result of our call*, but we may
not be guaranteed the exact time - it will depend on the characteristics
of the environment which executes the tests - number of other tasks,
 CPU speed, etc.

Example: you have an intensive memory shuffle test triggered by an cli inband,
that shuffles memory for 10^6 iterations and verifies afterwards that 
the content is correct, it may run 1s on one machine and 10s on another machine,
and 3s on the first machine under high load. As soon as the result is that memory did not get
corrupted, the test passes, even if it took an hour instead of a second.

It's obvious that there is some cap on how long this takes, but usually we can
easily derive a ballpark value that is a safe "unreasonable" value, and use it
as an absolute maximum timeout. If you expect it to take 0.01s normally, then setting
the cap as 300s will give plenty of space for the "unreasonable" cases that are caused by
some outlier circumstances, to still be caught. But we use this limit just as an upper
bound of how long we are prepared to wait for the test result, even if it is correct.
These deadlines define not the criterions for correctness of VPP, but the criteria for
the correctness of the test environment - anything outside of them is "Error", as 
opposed to "Pass" or "Fail".


2) synchronous

"exact, in line with the spec, or not later than, or no earlier than".

This is a different class of time dependency - it is much stricter and well defined.
it If the VPP is supposed to send the packet every 0.1s, the verification of the correct behavior
also implies the verification of the timing of the behavior.

In the extremely simplified form the model for this behavior is "stimulus - delay - action", with
the requirement to measure the timing of action with respect to the stimulus.

Testing these kinds of behavior in a simple fashion is hard - because there are multiple notions of "time"
at play:

- wall time. This is the time in "real world" as seen by external observer.
- VPP time. This is the time as seen by the code in the VPP
- test runner time. This is the time as seen by the code in test runner

The second and third items are subject to the variable externalities like system load,
and scheduling behavior of the system. 

In other words, if a test runner process gets the value of wall time, 
performs sleep(30), takes the wall time again and checks the difference,
the value is likely to be larger than exact 30.

Similar scenario is there in the VPP case.

The tests that deal with sensitive timings need to take that into account.


What to do with synchronous dependencies ?
==========================================

One can argue that if we want to measure the "precise" timing, then such tests
need to be punted into the realm of the device tests, which are done with the dedicated
UUT running VPP as well as the external process driving the test.

However, one can still perform a fair bit of testing by inserting triggers and probes
into the interconnections between the parts of the "stumulus - delay - action" chain.
The logic needs to be adjusted accordingly if the process model is different.

This does *not* 100% replace the original test, but allows to verify the functioning
of the separate components, that already gives some confidence.

One other approach is to flag these tests specially and execute them serially in the series
of single test jobs, which *probably* will get enough CPU resources, however, it does not solve
the problem itself and merely makes it manifest less likely.

The third approach is to create "maintainer-only" class of tests, that are declared as manually run.
It was the de-facto status quo for "extended" tests, however, this does not solve the problem of ongoing
test coverage for day to day maintenance within the CI.


CLI scraping in the tests - yay or nay ?
========================================

TBD





