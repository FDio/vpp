.. _lcov_code_coverage:

Code coverage with lcov
=======================

Prerequisites
-------------

Ensure required packages are installed:

::

    $ make install-deps

The Linux gcov and lcov tools can be fussy about gcc / g++ compiler
versions. As of this writing, Ubuntu 22.04 gcov / lcov works with
the latest gcc version (``11.3.0``).

Generate coverage for a test case
---------------------------------

As a first run, in order to generate the coverage report of
a specific plugin or test, run for example

::

    $ make test-cov TEST=fib

Then open the file ``.build-root/test-coverage/html/index.html`` in a Chrome browser.

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
