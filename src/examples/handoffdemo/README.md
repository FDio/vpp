# Handoff queue demo plugin {#handoff_queue_demo_plugin}

This plugin provides a simplified example of how to hand off
packets between threads. I used it to debug packet-tracer handoff
tracing support.

# Packet generator input script

```
 packet-generator new {
    name x
    limit 5
    size 128-128
    interface local0
    node handoffdemo-1
    data {
        incrementing 30
    }
 }
```
# Start vpp with 2 worker threads

The demo plugin hands packets from worker 1 to worker 2.

# Enable tracing, and start the packet generator

```
  trace add pg-input 100
  packet-generator enable
```

# Sample Run

```
  DBGvpp# ex /tmp/pg_input_script
  DBGvpp# pa en
  DBGvpp# sh err
   Count                    Node                  Reason
         5              handoffdemo-1             packets handed off processed
         5              handoffdemo-2             completed packets
  DBGvpp# show run
  Thread 1 vpp_wk_0 (lcore 0)
  Time 133.9, average vectors/node 5.00, last 128 main loops 0.00 per node 0.00
    vector rates in 3.7331e-2, out 0.0000e0, drop 0.0000e0, punt 0.0000e0
               Name                 State         Calls          Vectors        Suspends         Clocks       Vectors/Call
  handoffdemo-1                    active                  1               5               0          4.76e3            5.00
  pg-input                        disabled                 2               5               0          5.58e4            2.50
  unix-epoll-input                 polling             22760               0               0          2.14e7            0.00
  ---------------
  Thread 2 vpp_wk_1 (lcore 2)
  Time 133.9, average vectors/node 5.00, last 128 main loops 0.00 per node 0.00
    vector rates in 0.0000e0, out 0.0000e0, drop 3.7331e-2, punt 0.0000e0
               Name                 State         Calls          Vectors        Suspends         Clocks       Vectors/Call
  drop                             active                  1               5               0          1.35e4            5.00
  error-drop                       active                  1               5               0          2.52e4            5.00
  handoffdemo-2                    active                  1               5               0          2.56e4            5.00
  unix-epoll-input                 polling             22406               0               0          2.18e7            0.00
```

Enable the packet tracer and run it again...

```
  DBGvpp# trace add pg-input 100
  DBGvpp# pa en
  DBGvpp# sh trace
  sh trace
  ------------------- Start of thread 0 vpp_main -------------------
  No packets in trace buffer
  ------------------- Start of thread 1 vpp_wk_0 -------------------
  Packet 1

  00:06:50:520688: pg-input
    stream x, 128 bytes, 0 sw_if_index
    current data 0, length 128, buffer-pool 0, ref-count 1, trace handle 0x1000000
    00000000: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d0000
    00000020: 0000000000000000000000000000000000000000000000000000000000000000
    00000040: 0000000000000000000000000000000000000000000000000000000000000000
    00000060: 0000000000000000000000000000000000000000000000000000000000000000
  00:06:50:520762: handoffdemo-1
    HANDOFFDEMO: current thread 1

  Packet 2

  00:06:50:520688: pg-input
    stream x, 128 bytes, 0 sw_if_index
    current data 0, length 128, buffer-pool 0, ref-count 1, trace handle 0x1000001
    00000000: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d0000
    00000020: 0000000000000000000000000000000000000000000000000000000000000000
    00000040: 0000000000000000000000000000000000000000000000000000000000000000
    00000060: 0000000000000000000000000000000000000000000000000000000000000000
  00:06:50:520762: handoffdemo-1
    HANDOFFDEMO: current thread 1

  Packet 3

  00:06:50:520688: pg-input
    stream x, 128 bytes, 0 sw_if_index
    current data 0, length 128, buffer-pool 0, ref-count 1, trace handle 0x1000002
    00000000: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d0000
    00000020: 0000000000000000000000000000000000000000000000000000000000000000
    00000040: 0000000000000000000000000000000000000000000000000000000000000000
    00000060: 0000000000000000000000000000000000000000000000000000000000000000
  00:06:50:520762: handoffdemo-1
    HANDOFFDEMO: current thread 1

  Packet 4

  00:06:50:520688: pg-input
    stream x, 128 bytes, 0 sw_if_index
    current data 0, length 128, buffer-pool 0, ref-count 1, trace handle 0x1000003
    00000000: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d0000
    00000020: 0000000000000000000000000000000000000000000000000000000000000000
    00000040: 0000000000000000000000000000000000000000000000000000000000000000
    00000060: 0000000000000000000000000000000000000000000000000000000000000000
  00:06:50:520762: handoffdemo-1
    HANDOFFDEMO: current thread 1

  Packet 5

  00:06:50:520688: pg-input
    stream x, 128 bytes, 0 sw_if_index
    current data 0, length 128, buffer-pool 0, ref-count 1, trace handle 0x1000004
    00000000: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d0000
    00000020: 0000000000000000000000000000000000000000000000000000000000000000
    00000040: 0000000000000000000000000000000000000000000000000000000000000000
    00000060: 0000000000000000000000000000000000000000000000000000000000000000
  00:06:50:520762: handoffdemo-1
    HANDOFFDEMO: current thread 1

  ------------------- Start of thread 2 vpp_wk_1 -------------------
  Packet 1

  00:06:50:520796: handoff_trace
    HANDED-OFF: from thread 1 trace index 0
  00:06:50:520796: handoffdemo-2
    HANDOFFDEMO: current thread 2
  00:06:50:520867: error-drop
    rx:local0
  00:06:50:520914: drop
    handoffdemo-2: completed packets

  Packet 2

  00:06:50:520796: handoff_trace
    HANDED-OFF: from thread 1 trace index 1
  00:06:50:520796: handoffdemo-2
    HANDOFFDEMO: current thread 2
  00:06:50:520867: error-drop
    rx:local0
  00:06:50:520914: drop
    handoffdemo-2: completed packets

  Packet 3

  00:06:50:520796: handoff_trace
    HANDED-OFF: from thread 1 trace index 2
  00:06:50:520796: handoffdemo-2
    HANDOFFDEMO: current thread 2
  00:06:50:520867: error-drop
    rx:local0
  00:06:50:520914: drop
    handoffdemo-2: completed packets

  Packet 4

  00:06:50:520796: handoff_trace
    HANDED-OFF: from thread 1 trace index 3
  00:06:50:520796: handoffdemo-2
    HANDOFFDEMO: current thread 2
  00:06:50:520867: error-drop
    rx:local0
  00:06:50:520914: drop
    handoffdemo-2: completed packets

  Packet 5

  00:06:50:520796: handoff_trace
    HANDED-OFF: from thread 1 trace index 4
  00:06:50:520796: handoffdemo-2
    HANDOFFDEMO: current thread 2
  00:06:50:520867: error-drop
    rx:local0
  00:06:50:520914: drop
    handoffdemo-2: completed packets
 DBGvpp#
```
