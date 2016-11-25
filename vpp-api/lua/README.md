This is the experimental version of Lua API, aimed for the luajit use.

Please take a look and send the feedback to ayourtch@gmail.com.

To run the examples here:

1) install luajit - "sudo apt-get install luajit" on ubuntu

2) "make build-vpp-api" in the top VPP directory

3) "make run" in a separate terminal window
   This ensures you have an instance of VPP running

4) sudo luajit examples/example-cli.lua

This will result in something like this:

Version:
00000000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000010  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................

{ [1] = { ["luaapi_message_name"] = show_version_reply,["program"] = vpe,["version"] = ,["build_date"] = Fri Nov 25 10:58:48 UTC 2016,["retval"] = 0,["build_directory"] = /home/ubuntu/vpp,["_vl_msg_id"] = 170,["context"] = 0,} ,}
---
{ [1] = { ["luaapi_message_name"] = cli_inband_reply,["_vl_msg_id"] = 94,["length"] = 66,["reply"] = vpp v built by ubuntu on vpp-toys at Fri Nov 25 10:58:48 UTC 2016
,["retval"] = 0,["context"] = 0,} ,}
---

5) You can also run the performance test bench:

$ sudo luajit bench.lua
10001 iterations, average speed 5624LL per second
10001 iterations, average speed 6650LL per second
10001 iterations, average speed 6053LL per second
10001 iterations, average speed 7056LL per second
10001 iterations, average speed 6388LL per second
10001 iterations, average speed 5849LL per second
10001 iterations, average speed 6321LL per second
10001 iterations, average speed 6368LL per second
10001 iterations, average speed 5958LL per second
10001 iterations, average speed 6482LL per second
Average tps across the tests: 6274LL

Note: the above is run in an lxd container running inside 2-core
xhyve VM on a Macbook Pro, so I would not take the performance numbers for granted :)

The "examples" directory contains a few naive examples, as well as a couple of more 
advanced ones - a tab-completing CLI for VPP that can call both the APIs and CLI,
and also a small test utility which I use for automating some small tests using
VPP.

