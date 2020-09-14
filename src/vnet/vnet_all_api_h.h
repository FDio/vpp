/*
 * ------------------------------------------------------------------
 * vl_memory_api_h.h - memory API headers, in a specific order.
 *
 * Copyright (c) 2009-2010 Cisco and/or its affiliates. Licensed under the
 * Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the
 * License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 * ------------------------------------------------------------------
 */

/*
 * Add to the bottom of the #include list, or elves will steal your keyboard
 * in the middle of the night!
 *
 * Include current layer (2) last, or an artistic disagreement about message
 * numbering will occur
 */

#ifndef included_from_layer_3
#include <vlibmemory/vl_memory_api_h.h>
#endif /* included_from_layer_3 */

#ifdef vl_printfun
#include <vnet/format_fns.h>
#endif

#include <vnet/bonding/bond.api.h>
#include <vnet/devices/af_packet/af_packet.api.h>
#include <vnet/devices/virtio/vhost_user.api.h>
#include <vnet/devices/tap/tapv2.api.h>
#include <vnet/interface.api.h>
#include <vnet/l2/l2.api.h>
#include <vnet/span/span.api.h>
#include <vnet/ip/ip.api.h>
#include <vnet/vxlan/vxlan.api.h>
#include <vnet/vxlan-gpe/vxlan_gpe.api.h>
#include <vnet/bfd/bfd.api.h>
#include <vnet/ipsec/ipsec.api.h>
#include <vnet/session/session.api.h>
#include <vnet/mpls/mpls.api.h>
#include <vnet/srv6/sr.api.h>
#include <vnet/srmpls/sr_mpls.api.h>
#include <vnet/classify/classify.api.h>
#include <vnet/ipfix-export/ipfix_export.api.h>
#include <vnet/cop/cop.api.h>
#include <vnet/policer/policer.api.h>
#include <vnet/ethernet/p2p_ethernet.api.h>
#include <vnet/tcp/tcp.api.h>
#include <vnet/udp/udp.api.h>
#include <vnet/bier/bier.api.h>
#include <vnet/ip/punt.api.h>
#include <vnet/pg/pg.api.h>
#include <vnet/feature/feature.api.h>
#include <vnet/qos/qos.api.h>
#include <vnet/devices/pipe/pipe.api.h>
#include <vnet/syslog/syslog.api.h>
#include <vnet/devices/virtio/virtio.api.h>
#include <vnet/gso/gso.api.h>
#include <vnet/flow/flow.api.h>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
