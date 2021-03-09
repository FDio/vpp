# Buffers monitoring plugin {#bufmon_doc}

This plugin enables to track buffer utilization in the VPP graph nodes. The
main use is to detect buffer leakage.
It works by keeping track of number of buffer allocations and free in graph
nodes and also of number of buffers received in input frames and in output
frames.
The formula to compute the number of "buffered" buffers in a node is simply:
        #buffered = #alloc + #input - #free - #output
Note: monitoring will impact performances.

## Basic usage
1. Turn buffer traces on:
```
~# vppctl set buffer traces on
```
2. Monitor buffer usage:
```
~# vppctl show buffer traces verbose
```
3. Turn buffer traces off:
```
~# vppctl set buffer traces off
```
