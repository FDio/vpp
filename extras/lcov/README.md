## Prerequisites

The Linux gcov and lcov tools are fussy about gcc / g++ compiler
versions. As of this writing, Ubuntu 18.04 gcov / lcov work with
these toolchain versions:

  $ gcc --version
  gcc (Ubuntu 7.4.0-1ubuntu1~18.04.1) 7.4.0
  $ g++ --version
  g++ (Ubuntu 8.3.0-6ubuntu1~18.04.1) 8.3.0

Refer to
https://askubuntu.com/questions/26498/how-to-choose-the-default-gcc-and-g-version for information on how to install multiple gcc / g++ versions, and
switch between them.

You'll need to install the following additional packages:

  $ sudo apt-get install gcovr ggcov lcov

## Compile an instrumented vpp image

Two ways:

  $ cd <workspace-root>
  $ make test-gcov
  $ ## interrupt compilation after building the image

or
  $ cd <workspace-root>/build-root
  $ make PLATFORM=vpp TAG=vpp_gcov vpp-install

## Initialize the lcov database

  $ cd <workspace-root>
  $ ./extras/lcov/lcov_prep
  $ make test-gcov or make TEST=my_test test-gcov
  $ # repeat or vary as desired to increase reported coverage
  $ # Generate the report:
  $ ./extras/lcov/lcov_post

You can run vpp manually, do anything you like. Results are cumulative
until you re-run the "prep" script.

## Look at the results

Point a browser at file:///<workspace-root>/build-root/html/index.html
