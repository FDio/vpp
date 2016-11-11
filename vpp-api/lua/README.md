This is the experimental version of Lua API, aimed for the luajit use.

Please take a look and send the feedback to ayourtch@gmail.com.

To run the examples here:

1) install luajit - "sudo apt-get install luajit" on ubuntu

2) make build-vpp-api in the top directory

3) "make" in this directory to build libcough.so

4) "make run" in a separate terminal window

5) sudo luajit examples/example-cli.lua

This will result in something like this:

libcough detected

Version:        17.01-rc0~37-g8b3191e
00000000  31 37 2E 30 31 2D 72 63  30 7E 33 37 2D 67 38 62  17.01-rc0~37-g8b
00000010  33 31 39 31 65 00 00 00  00 00 00 00 00 00 00 00  3191e...........

{ [1] = { ["luaapi_message_name"] = show_version_reply,["program"] = vpe,["version"] = 17.01-rc0~37-g8b3191e,["build_date"] = Fri Nov 11 15:30:21 UTC 2016,["retval"] = 0,["build_directory"] = /home/ubuntu/vpp,["_vl_msg_id"] = 166,["context"] = 0,} ,}
---
{ [1] = { ["luaapi_message_name"] = cli_inband_reply,["_vl_msg_id"] = 90,["length"] = 94,["reply"] = vpp v17.01-rc0~37-g8b3191e built by ubuntu on vpp-lapi-commit at Fri Nov 11 15:30:21 UTC 2016
,["retval"] = 0,["context"] = 0,} ,}
---

6) You can also run the performance test bench:

$ sudo luajit bench.lua
libcough detected

10001 iterations, average speed 4108LL per second
10001 iterations, average speed 4660LL per second
10001 iterations, average speed 4095LL per second
10001 iterations, average speed 4542LL per second
10001 iterations, average speed 8048LL per second
10001 iterations, average speed 6805LL per second
10001 iterations, average speed 5170LL per second
10001 iterations, average speed 6585LL per second
10001 iterations, average speed 6714LL per second
10001 iterations, average speed 6942LL per second
Average tps across the tests: 5766LL

Note: the above is run in an lxd container running inside 2-core
xhyve VM on a Macbook Pro, so I would not take the performance numbers for granted :)

The "examples" directory contains a few naive examples, as well as a couple of more 
advanced ones - a tab-completing CLI for VPP that can call both the APIs and CLI,
and also a small test utility which I use for automating some small tests using
VPP.

