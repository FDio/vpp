.. _lcov_code_coverage:

Code coverage with lcov
=======================

Prerequisites
-------------

You’ll need to install the following additional packages:

::

    $ sudo apt-get install gcovr ggcov lcov

The Linux gcov and lcov tools can be fussy about gcc / g++ compiler
versions. As of this writing, Ubuntu 20.04 gcov / lcov should work
the latest gcc version (``9.3.0``)

Generate coverage for a test case
---------------------------------

As a first run, in order to generate the coverage report of
a specific plugin or test, run for example

::

    $ make test-cov TEST=fib CC=gcc

Then point a browser at ``./test/coverage/html/index.html``

Improving test coverage
-----------------------

When doing modifications on the test cases, you can run

::

    # This will run the test & report the result in the coverage data
    $ make test-cov-build TEST=fib

    # This will generate the html report with the current coverage data
    $ make test-cov-post

    # To reset the coverage data use
    $ make test-cov-prep

