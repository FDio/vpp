#!/usr/bin/env python3
import socket
import struct
import time

iface = "enp4s0f1np1"
src_mac = bytes.fromhex("507c6f6c76ab")

frames = [
    ("broadcast", "ff:ff:ff:ff:ff:ff"),
    ("unicast-own", "c4:93:00:68:b3:5e"),
    ("unicast-unknown", "02:11:22:33:44:55"),
    ("multicast-known", "01:00:5e:00:00:01"),
    ("multicast-unknown", "01:02:03:04:05:06"),
]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((iface, 0))

payload = b"\x00" * 20
ethertype = 0x1000

for round_num in range(1, 4):
    for name, dst_mac_hex in frames:
        dst = bytes.fromhex(dst_mac_hex.replace(":", ""))
        frame = dst + src_mac + struct.pack("!H", ethertype) + payload
        if len(frame) < 60:
            frame += b"\x00" * (60 - len(frame))
        s.send(frame)
        print(f"round {round_num}: sent {name} dst={dst_mac_hex} ethertype=0x{ethertype:04x} len={len(frame)}")
        ethertype += 1
        time.sleep(0.05)

s.close()
