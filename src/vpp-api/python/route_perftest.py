#!/usr/bin/env python3

# Performance options
# 1. Rewrite packers in C
# 2. Pack once and use as 'template'
#    Need some sort of user friendly way to update fields. Size cannot change.
# 3. Async mode
#
'''
typedef fib_path_nh
{
  /* proto = IP[46] */
  vl_api_address_union_t address;
  /* proto = MPLS */
  u32 via_label;
  /* proto = ANY, determined by path type */
  u32 obj_id;
  /* path-type = CLASSIFY */
  u32 classify_table_index;
};
typedef fib_path
{
  u32 sw_if_index;
  u32 table_id;
  u32 rpf_id;
  u8 weight;
  u8 preference;

  vl_api_fib_path_type_t type;
  vl_api_fib_path_flags_t flags;
  vl_api_fib_path_nh_proto_t proto;
  vl_api_fib_path_nh_t nh;
  u8 n_labels;
  vl_api_fib_mpls_label_t label_stack[16];
};

typedef ip_route_v2
{
  u32 table_id;
  u32 stats_index;
  vl_api_prefix_t prefix;
  u8 n_paths;
  u8 src;
  vl_api_fib_path_t paths[n_paths];
};

define ip_route_add_del_v2
{
  option in_progress;
  u32 client_index;
  u32 context;
  bool is_add [default=true];
  bool is_multipath;
  vl_api_ip_route_v2_t route;
};
'''

from vpp_papi import VPPApiClient
from vpp_papi import VppEnum

import ipaddress
import time

import cProfile
from pstats import Stats

def vpp_papi_message_field_update(msg, data, offset, new):
    data[offset:offset+msg.size] = msg.pack(new)
    return data

def vpp_papi_message_field_get_offset(msg, fields):
    # find field

    m = msg
    offset = 0
    for f in fields:
        i = m.fields.index(f)
        for j in range(i):
            offset += m.packers[j].size
        m = m.packers[i]
    return offset, m

def callback(msgname, msg):
    if msgname == 'ip_route_add_del_v2_reply':
        assert msg.retval == 0

vpp = VPPApiClient(use_socket=True)
vpp.register_event_callback(callback)
vpp.connect(name='foo', chroot_prefix='foo', do_async=True)

nexthop = {'address': {'ip4': ipaddress.IPv4Address('1.1.1.1')},
           'via_label': 0,
           'obj_id': 0,
           'classify_table_index': 0}

path = [{'sw_if_index': 0,
         'table_id': 0,
         'rpf_id': 0,
         'weight': 0,
         'preference': 0,
         'type': VppEnum.vl_api_fib_path_type_t.FIB_API_PATH_TYPE_NORMAL,
         'flags': VppEnum.vl_api_fib_path_flags_t.FIB_API_PATH_FLAG_NONE,
         'proto': VppEnum.vl_api_fib_path_nh_proto_t.FIB_API_PATH_NH_PROTO_IP4,
         'nh': nexthop,
         'n_labels': 0,
         'label_stack': [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        }]
prefix = ipaddress.IPv4Network('10.0.0.0/24')

route = {'table_id': 0,
         'stats_index': 0xFFFFFFFF,
         'prefix': prefix,
         'n_paths': 1,
         'src': 0,
         'paths': path}

route_add = vpp.messages['ip_route_add_del_v2']
b = route_add.pack({'_vl_msg_id': route_add.get_msgid(), 'client_index': vpp.transport.socket_index, 'is_add': True,
                    'is_multipath': False, 'route': route})
b2 = bytearray(b)
offset, m = vpp_papi_message_field_get_offset(route_add, ['route', 'prefix'])

start = time.time()

no_routes = 0
for pfx in ipaddress.ip_network('11.0.0.0/20').subnets(new_prefix=32):
    vpp_papi_message_field_update(m, b2, offset, pfx)
    vpp.transport.write(b2)
    no_routes += 1
end = time.time()

# wait for replies
time.sleep(0.1)
vpp.disconnect()
time.sleep(0.1)
# wait for replies

ms = (end-start) * 1000
print('{} routes programmed in {:.0f} ms. Routes/s: {:.0f}'.format(no_routes, ms, no_routes/ms * 1000))
