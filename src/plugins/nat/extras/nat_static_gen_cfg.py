#!/usr/bin/env python3
import argparse
import ipaddress

parser = argparse.ArgumentParser(description='Generate NAT plugin config.')
parser.add_argument('static_map_num', metavar='N', type=int, nargs=1,
                    help='number of static mappings')
args = parser.parse_args()

file_name = 'nat_static_%s' % (args.static_map_num[0])
outfile = open(file_name, 'w')

outfile.write('set int ip address TenGigabitEthernet4/0/0 172.16.2.1/24\n')
outfile.write('set int ip address TenGigabitEthernet4/0/1 173.16.1.1/24\n')
outfile.write('set int state TenGigabitEthernet4/0/0 up\n')
outfile.write('set int state TenGigabitEthernet4/0/1 up\n')
outfile.write('ip route add 2.2.0.0/16 via 173.16.1.2 TenGigabitEthernet4/0/1\n')
outfile.write('ip route add 10.0.0.0/24 via 172.16.2.2 TenGigabitEthernet4/0/0\n')
outfile.write('set int nat44 in TenGigabitEthernet4/0/0 out TenGigabitEthernet4/0/1\n')

for i in range (0, args.static_map_num[0]):
    local = str(ipaddress.IPv4Address(u'10.0.0.3') + i)
    external = str(ipaddress.IPv4Address(u'173.16.1.3') + i)
    outfile.write('nat44 add static mapping local %s external %s\n' % (local, external))
