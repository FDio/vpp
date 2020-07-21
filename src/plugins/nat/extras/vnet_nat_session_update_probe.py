#!/usr/bin/python

from __future__ import print_function
from bcc import BPF, USDT
from datetime import datetime
import ipaddress
import sys

# define BPF program
bpf_prog = """
struct data_t
{
    u32  operation;
    u32  thread_index;
    u32  fib_index;
    u32  protocol;
    u32  in2out_addr;
    u32  in2out_port;
    u32  out2in_addr;
    u32  out2in_port;
};
BPF_PERF_OUTPUT(nat_events);

int vpp_nat_session_updates(struct pt_regs *ctx) {
    struct data_t data = { 0 };

    bpf_usdt_readarg(1, ctx, &data.operation);
    bpf_usdt_readarg(2, ctx, &data.thread_index);
    bpf_usdt_readarg(3, ctx, &data.fib_index);
    bpf_usdt_readarg(4, ctx, &data.protocol);
    bpf_usdt_readarg(5, ctx, &data.in2out_addr);
    bpf_usdt_readarg(6, ctx, &data.in2out_port);
    bpf_usdt_readarg(7, ctx, &data.out2in_addr);
    bpf_usdt_readarg(8, ctx, &data.out2in_port);

    nat_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
};
"""

if len(sys.argv) < 2:
    print("USAGE: vnet_nat_session_update_probe PID")
    exit()
pid = sys.argv[1]
nat_op_s = { 0: 'CRE', 1: 'UPD', 2: 'DEL' }

# header
print ("{:6} | {:3} | {:3} | {:5} | {:>15}:{:<5} | {:>15}:{:<5} |". \
    format("ThrdID", "Opr", "FIB", "Proto", "SourcIP", "SPort", "DestinationIP", "DPort"))
print ("=" * 76)
# event data
def print_event(cpu, data, size):
    event = b["nat_events"].event(data)
    print ("{:6} | {:3} | {:3} | {:5} | {:>15}:{:>5} | {:>15}:{:>5} |". \
        format(event.thread_index, \
            nat_op_s[event.operation], \
            event.fib_index, event.protocol, \
            ipaddress.ip_address(event.in2out_addr), event.in2out_port, \
            ipaddress.ip_address(event.out2in_addr), event.out2in_port))

# enable USDT probe from given PID
usdt_nat = USDT(pid=int(pid))
usdt_nat.enable_probe(probe="vnet_nat_session_update_probe", fn_name="vpp_nat_session_updates")

# initialize BPF
b = BPF(text=bpf_prog, usdt_contexts=[usdt_nat])

# trace probe ...
b["nat_events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll(1)
    except KeyboardInterrupt:
        exit()