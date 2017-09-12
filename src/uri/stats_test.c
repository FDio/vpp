/*
 *------------------------------------------------------------------
 * api.c - message handler registration
 *
 * Copyright (c) 2010 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <vppinfra/clib.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/fifo.h>
#include <vppinfra/time.h>
#include <vppinfra/mheap.h>
#include <vppinfra/heap.h>
#include <vppinfra/pool.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>
#include <vpp/stats/stats.h>
#include <vnet/vnet.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vpp/api/vpe_msg_enum.h>

#include <vnet/ip/ip.h>
#include <vnet/interface.h>

#define f64_endian(a)
#define f64_print(a,b)

#define vl_typedefs		/* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <vpp/api/vpe_all_api_h.h>
#undef vl_printfun

vl_shmem_hdr_t *shmem_hdr;

typedef struct
{
  int link_events_on;
  int stats_on;
  int oam_events_on;

  /* convenience */
  unix_shared_memory_queue_t *vl_input_queue;
  u32 my_client_index;
} test_main_t;

test_main_t test_main;

/*
 * Satisfy external references when -lvlib is not available.
 */
vlib_main_t vlib_global_main;
vlib_main_t **vlib_mains;

void
tod_now()
{
  time_t t = time(NULL);
  struct tm tm = *localtime(&t);

  fformat(stdout, "now: %d-%d-%d %d:%d:%d\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}


void
vlib_cli_output (struct vlib_main_t *vm, char *fmt, ...)
{
  clib_warning ("vlib_cli_output callled...");
}

u8 *
format_ethernet_address (u8 * s, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);

  return format (s, "%02x:%02x:%02x:%02x:%02x:%02x",
		 a[0], a[1], a[2], a[3], a[4], a[5]);
}

static void
vl_api_sw_interface_details_t_handler (vl_api_sw_interface_details_t * mp)
{
  char *duplex, *speed;

  switch (mp->link_duplex << VNET_HW_INTERFACE_FLAG_DUPLEX_SHIFT)
    {
    case VNET_HW_INTERFACE_FLAG_HALF_DUPLEX:
      duplex = "half";
      break;
    case VNET_HW_INTERFACE_FLAG_FULL_DUPLEX:
      duplex = "full";
      break;
    default:
      duplex = "bogus";
      break;
    }
  switch (mp->link_speed << VNET_HW_INTERFACE_FLAG_SPEED_SHIFT)
    {
    case VNET_HW_INTERFACE_FLAG_SPEED_10M:
      speed = "10Mbps";
      break;
    case VNET_HW_INTERFACE_FLAG_SPEED_100M:
      speed = "100Mbps";
      break;
    case VNET_HW_INTERFACE_FLAG_SPEED_1G:
      speed = "1Gbps";
      break;
    case VNET_HW_INTERFACE_FLAG_SPEED_10G:
      speed = "10Gbps";
      break;
    case VNET_HW_INTERFACE_FLAG_SPEED_40G:
      speed = "40Gbps";
      break;
    case VNET_HW_INTERFACE_FLAG_SPEED_100G:
      speed = "100Gbps";
      break;
    default:
      speed = "bogus";
      break;
    }
  fformat (stdout, "details: %s sw_if_index %d sup_sw_if_index %d "
	   "link_duplex %s link_speed %s",
	   mp->interface_name, ntohl (mp->sw_if_index),
	   ntohl (mp->sup_sw_if_index), duplex, speed);

  if (mp->l2_address_length)
    fformat (stdout, "  l2 address: %U\n",
	     format_ethernet_address, mp->l2_address);
  else
    fformat (stdout, "\n");
}

static void
  vl_api_want_interface_events_reply_t_handler
  (vl_api_want_interface_events_reply_t * mp)
{
}

static void
vl_api_want_stats_reply_t_handler (vl_api_want_stats_reply_t * mp)
{
  fformat (stdout, "want stats reply %d\n", mp->retval);
}

static void
vl_api_want_interface_simple_stats_reply_t_handler (vl_api_want_interface_simple_stats_reply_t * mp)
{
  fformat (stdout, "want interface simple stats reply %d\n", mp->retval);
}

static void
vl_api_want_per_interface_simple_stats_reply_t_handler (vl_api_want_per_interface_simple_stats_reply_t * mp)
{
  fformat (stdout, "want per interface simple stats reply %d\n", mp->retval);
}

static void
vl_api_want_interface_combined_stats_reply_t_handler (vl_api_want_interface_combined_stats_reply_t * mp)
{
  fformat (stdout, "want interface combined stats reply %d\n", mp->retval);
}

static void
vl_api_want_per_interface_combined_stats_reply_t_handler (vl_api_want_per_interface_combined_stats_reply_t * mp)
{
  fformat (stdout, "want per interface combined stats reply %d\n", mp->retval);
}


static void
vl_api_want_ip4_fib_stats_reply_t_handler (vl_api_want_ip4_fib_stats_reply_t * mp)
{
  fformat (stdout, "want ip4 fib stats reply %d\n", ntohl (mp->retval));
}

static void
vl_api_want_ip4_nbr_stats_reply_t_handler (vl_api_want_ip4_nbr_stats_reply_t * mp)
{
  fformat (stdout, "want ip4 nbr stats reply %d\n", ntohl (mp->retval));
}

static void
vl_api_want_ip6_fib_stats_reply_t_handler (vl_api_want_ip6_fib_stats_reply_t * mp)
{
  fformat (stdout, "want ip6 fib stats reply %d\n", ntohl (mp->retval));
}

static void
vl_api_want_ip6_nbr_stats_reply_t_handler (vl_api_want_ip6_nbr_stats_reply_t * mp)
{
  fformat (stdout, "want ip6 nbr stats reply %d\n", ntohl (mp->retval));
}

static void
vl_api_want_oam_events_reply_t_handler (vl_api_want_oam_events_reply_t * mp)
{
  fformat (stdout, "want oam reply %d\n", ntohl (mp->retval));
}

static void
vl_api_ip_add_del_route_reply_t_handler (vl_api_ip_add_del_route_reply_t * mp)
{
  fformat (stdout, "add_route reply %d\n", ntohl (mp->retval));
}

static void
  vl_api_sw_interface_add_del_address_reply_t_handler
  (vl_api_sw_interface_add_del_address_reply_t * mp)
{
  fformat (stdout, "add_del_address reply %d\n", ntohl (mp->retval));
}

static void
  vl_api_sw_interface_set_table_reply_t_handler
  (vl_api_sw_interface_set_table_reply_t * mp)
{
  fformat (stdout, "set_table reply %d\n", ntohl (mp->retval));
}

static void
vl_api_tap_connect_reply_t_handler (vl_api_tap_connect_reply_t * mp)
{
  fformat (stdout, "tap connect reply %d, sw_if_index %d\n",
	   ntohl (mp->retval), ntohl (mp->sw_if_index));
}

static void
vl_api_create_vlan_subif_reply_t_handler (vl_api_create_vlan_subif_reply_t *
					  mp)
{
  fformat (stdout, "create vlan subif reply %d, sw_if_index %d\n",
	   ntohl (mp->retval), ntohl (mp->sw_if_index));
}

static void vl_api_proxy_arp_add_del_reply_t_handler
  (vl_api_proxy_arp_add_del_reply_t * mp)
{
  fformat (stdout, "add del proxy arp reply %d\n", ntohl (mp->retval));
}

static void vl_api_proxy_arp_intfc_enable_disable_reply_t_handler
  (vl_api_proxy_arp_intfc_enable_disable_reply_t * mp)
{
  fformat (stdout, "proxy arp intfc ena/dis reply %d\n", ntohl (mp->retval));
}

static void vl_api_ip_neighbor_add_del_reply_t_handler
  (vl_api_ip_neighbor_add_del_reply_t * mp)
{
  fformat (stdout, "ip neighbor add del reply %d\n", ntohl (mp->retval));
}

/* Format an IP4 address. */
u8 *
format_ip4_address (u8 * s, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  return format (s, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
}

/* Format an IP4 route destination and length. */
u8 *
format_ip4_address_and_length (u8 * s, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  u8 l = va_arg (*args, u32);
  return format (s, "%U/%d", format_ip4_address, a, l);
}

static void
vl_api_vnet_ip4_fib_counters_t_handler (vl_api_vnet_ip4_fib_counters_t * mp)
{
  int i;
  vl_api_ip4_fib_counter_t *ctrp;
  u32 count;

  count = ntohl (mp->count);

  tod_now();

  fformat (stdout, "fib id %d, count this msg %d\n",
	   ntohl (mp->vrf_id), count);

  ctrp = mp->c;
  for (i = 0; i < count; i++)
    {
      fformat (stdout, "%U: %lld packets, %lld bytes\n",
	       format_ip4_address_and_length, &ctrp->address,
	       (u32) ctrp->address_length,
	       clib_net_to_host_u64 (ctrp->packets),
	       clib_net_to_host_u64 (ctrp->bytes));
      ctrp++;
    }
}

static void
vl_api_vnet_ip4_nbr_counters_t_handler (vl_api_vnet_ip4_nbr_counters_t * mp)
{
  tod_now();

  fformat (stdout, "nbr counters arrived \n");

}

/* Format an IP6 address. */
u8 *
format_ip6_address (u8 * s, va_list * args)
{
  ip6_address_t *a = va_arg (*args, ip6_address_t *);
  u32 i, i_max_n_zero, max_n_zeros, i_first_zero, n_zeros, last_double_colon;

  i_max_n_zero = ARRAY_LEN (a->as_u16);
  max_n_zeros = 0;
  i_first_zero = i_max_n_zero;
  n_zeros = 0;
  for (i = 0; i < ARRAY_LEN (a->as_u16); i++)
    {
      u32 is_zero = a->as_u16[i] == 0;
      if (is_zero && i_first_zero >= ARRAY_LEN (a->as_u16))
	{
	  i_first_zero = i;
	  n_zeros = 0;
	}
      n_zeros += is_zero;
      if ((!is_zero && n_zeros > max_n_zeros)
	  || (i + 1 >= ARRAY_LEN (a->as_u16) && n_zeros > max_n_zeros))
	{
	  i_max_n_zero = i_first_zero;
	  max_n_zeros = n_zeros;
	  i_first_zero = ARRAY_LEN (a->as_u16);
	  n_zeros = 0;
	}
    }

  last_double_colon = 0;
  for (i = 0; i < ARRAY_LEN (a->as_u16); i++)
    {
      if (i == i_max_n_zero && max_n_zeros > 1)
	{
	  s = format (s, "::");
	  i += max_n_zeros - 1;
	  last_double_colon = 1;
	}
      else
	{
	  s = format (s, "%s%x",
		      (last_double_colon || i == 0) ? "" : ":",
		      clib_net_to_host_u16 (a->as_u16[i]));
	  last_double_colon = 0;
	}
    }

  return s;
}

/* Format an IP6 route destination and length. */
u8 *
format_ip6_address_and_length (u8 * s, va_list * args)
{
  ip6_address_t *a = va_arg (*args, ip6_address_t *);
  u8 l = va_arg (*args, u32);
  return format (s, "%U/%d", format_ip6_address, a, l);
}

static void
vl_api_vnet_ip6_fib_counters_t_handler (vl_api_vnet_ip6_fib_counters_t * mp)
{
  int i;
  vl_api_ip6_fib_counter_t *ctrp;
  u32 count;

  count = ntohl (mp->count);

  tod_now();

  fformat (stdout, "fib id %d, count this msg %d\n",
	   ntohl (mp->vrf_id), count);

  ctrp = mp->c;
  for (i = 0; i < count; i++)
    {
      fformat (stdout, "%U: %lld packets, %lld bytes\n",
	       format_ip6_address_and_length, &ctrp->address,
	       (u32) ctrp->address_length,
	       clib_net_to_host_u64 (ctrp->packets),
	       clib_net_to_host_u64 (ctrp->bytes));
      ctrp++;
    }
}

static void
vl_api_vnet_ip6_nbr_counters_t_handler (vl_api_vnet_ip6_nbr_counters_t * mp)
{
  tod_now();
  fformat (stdout, "nbr counters arrived \n");
}

static void
vl_api_oam_event_t_handler (vl_api_oam_event_t * mp)
{
  fformat (stdout, "OAM: %U now %s\n",
	   format_ip4_address, &mp->dst_address,
	   mp->state == 1 ? "alive" : "dead");
}

static void
vl_api_oam_add_del_reply_t_handler (vl_api_oam_add_del_reply_t * mp)
{
  fformat (stdout, "oam add del reply %d\n", ntohl (mp->retval));
}

static void
vl_api_reset_fib_reply_t_handler (vl_api_reset_fib_reply_t * mp)
{
  fformat (stdout, "fib reset reply %d\n", ntohl (mp->retval));
}

static void
vl_api_dhcp_proxy_set_vss_reply_t_handler (vl_api_dhcp_proxy_set_vss_reply_t *
					   mp)
{
  fformat (stdout, "dhcp proxy set vss reply %d\n", ntohl (mp->retval));
}

static void
vl_api_dhcp_proxy_config_reply_t_handler (vl_api_dhcp_proxy_config_reply_t *
					  mp)
{
  fformat (stdout, "dhcp proxy config reply %d\n", ntohl (mp->retval));
}

static void
vl_api_set_ip_flow_hash_reply_t_handler (vl_api_set_ip_flow_hash_reply_t * mp)
{
  fformat (stdout, "set ip flow hash reply %d\n", ntohl (mp->retval));
}

static void
  vl_api_sw_interface_ip6nd_ra_config_reply_t_handler
  (vl_api_sw_interface_ip6nd_ra_config_reply_t * mp)
{
  fformat (stdout, "ip6 nd ra-config  reply %d\n", ntohl (mp->retval));
}

static void
  vl_api_sw_interface_ip6nd_ra_prefix_reply_t_handler
  (vl_api_sw_interface_ip6nd_ra_prefix_reply_t * mp)
{
  fformat (stdout, "ip6 nd ra-prefix  reply %d\n", ntohl (mp->retval));
}

static void
  vl_api_sw_interface_ip6_enable_disable_reply_t_handler
  (vl_api_sw_interface_ip6_enable_disable_reply_t * mp)
{
  fformat (stdout, "ip6 enable/disable reply %d\n", ntohl (mp->retval));
}

static void
  vl_api_sw_interface_ip6_set_link_local_address_reply_t_handler
  (vl_api_sw_interface_ip6_set_link_local_address_reply_t * mp)
{
  fformat (stdout, "ip6 set link-local address reply %d\n",
	   ntohl (mp->retval));
}

static void vl_api_create_loopback_reply_t_handler
  (vl_api_create_loopback_reply_t * mp)
{
  fformat (stdout, "create loopback status %d, sw_if_index %d\n",
	   ntohl (mp->retval), ntohl (mp->sw_if_index));
}

static void vl_api_create_loopback_instance_reply_t_handler
  (vl_api_create_loopback_instance_reply_t * mp)
{
  fformat (stdout, "create loopback status %d, sw_if_index %d\n",
	   ntohl (mp->retval), ntohl (mp->sw_if_index));
}

static void vl_api_l2_patch_add_del_reply_t_handler
  (vl_api_l2_patch_add_del_reply_t * mp)
{
  fformat (stdout, "l2 patch reply %d\n", ntohl (mp->retval));
}

static void vl_api_sw_interface_set_l2_xconnect_reply_t_handler
  (vl_api_sw_interface_set_l2_xconnect_reply_t * mp)
{
  fformat (stdout, "l2_xconnect reply %d\n", ntohl (mp->retval));
}

static void vl_api_sw_interface_set_l2_bridge_reply_t_handler
  (vl_api_sw_interface_set_l2_bridge_reply_t * mp)
{
  fformat (stdout, "l2_bridge reply %d\n", ntohl (mp->retval));
}

static void vl_api_vnet_interface_simple_counters_t_handler(vl_api_vnet_interface_simple_counters_t *mp)
{
  tod_now();
  fformat (stdout, "simple counters\n", ntohl (mp->vnet_counter_type));
  char *counter_name;
  u32 count, sw_if_index;
  int i;

  count = ntohl (mp->count);
  sw_if_index = ntohl (mp->first_sw_if_index);
  u64 *vp, v;
  vp = (u64 *) mp->data;

  switch (mp->vnet_counter_type)
    {
    case VNET_INTERFACE_COUNTER_DROP:
      counter_name = "drop";
      break;
    case VNET_INTERFACE_COUNTER_PUNT:
      counter_name = "punt";
      break;
    case VNET_INTERFACE_COUNTER_IP4:
      counter_name = "ip4";
      break;
    case VNET_INTERFACE_COUNTER_IP6:
      counter_name = "ip6";
      break;
    case VNET_INTERFACE_COUNTER_RX_NO_BUF:
      counter_name = "rx-no-buf";
      break;
    case VNET_INTERFACE_COUNTER_RX_MISS:
      counter_name = "rx-miss";
      break;
    case VNET_INTERFACE_COUNTER_RX_ERROR:
      counter_name = "rx-error";
      break;
    case VNET_INTERFACE_COUNTER_TX_ERROR:
      counter_name = "tx-error (fifo-full)";
      break;
    default:
      counter_name = "bogus";
      break;
    }

  for (i = 0; i < count; i++)
    {
      v = clib_mem_unaligned (vp, u64);
      v = clib_net_to_host_u64 (v);
      vp++;
      fformat (stdout, "sw_if_index: %d.%s %lld\n", sw_if_index, counter_name, v);
      sw_if_index++;
    }

}

void
print_simple_interface (u32 swif, u64 stat, char * name)
{
  u64 v;
  if (stat)
    {
      v = clib_mem_unaligned (&stat, u64);
      v = clib_net_to_host_u64 (v);
      fformat (stdout, "swf: %d %s:%lld\n", swif, name, v);
    }
}


static void vl_api_vnet_per_interface_simple_counters_t_handler(vl_api_vnet_per_interface_simple_counters_t *mp)
{

  u32 timestamp = mp->timestamp;
  vnet_simple_counter_t *vp = (vnet_simple_counter_t *) mp->data;

  tod_now();
  fformat (stdout, "per interface simple counters\n");
  fformat (stdout, "timestamp: %lld\n", timestamp);

  int i, total;

  total = mp->count;

  for (i = 0; i < total; i++)
    {

      print_simple_interface( htonl(vp->sw_if_index), vp->drop, "drop");
      print_simple_interface( htonl(vp->sw_if_index), vp->punt, "punt");
      print_simple_interface( htonl(vp->sw_if_index), vp->rx_ip4, "rx_ip4");
      print_simple_interface( htonl(vp->sw_if_index), vp->rx_ip6, "rx_ip6");
      print_simple_interface( htonl(vp->sw_if_index), vp->rx_no_buffer, "rx_no_buffer");
      print_simple_interface( htonl(vp->sw_if_index), vp->rx_miss, "rx_miss");
      print_simple_interface( htonl(vp->sw_if_index), vp->rx_error, "rx_error");
      print_simple_interface( htonl(vp->sw_if_index), vp->tx_error, "tx_error");
      print_simple_interface( htonl(vp->sw_if_index), vp->rx_mpls, "rx_mpls");
      vp++;
    }
}

static void vl_api_vnet_interface_combined_counters_t_handler(vl_api_vnet_interface_combined_counters_t *mp)
{
  tod_now();
  fformat (stdout, "combined counters\n", ntohl (mp->vnet_counter_type));
  char *counter_name;
  u32 count, sw_if_index;
  int i;
  vlib_counter_t *vp;
  u64 packets, bytes;
  vp = (vlib_counter_t *) mp->data;

  count = ntohl (mp->count);
  sw_if_index = ntohl (mp->first_sw_if_index);

  switch (mp->vnet_counter_type)
    {
    case VNET_INTERFACE_COUNTER_RX:
      counter_name = "rx";
      break;
    case VNET_INTERFACE_COUNTER_TX:
      counter_name = "tx";
      break;
    default:
      counter_name = "bogus";
      break;
    }
  for (i = 0; i < count; i++)
    {
      packets = clib_mem_unaligned (&vp->packets, u64);
      packets = clib_net_to_host_u64 (packets);
      bytes = clib_mem_unaligned (&vp->bytes, u64);
      bytes = clib_net_to_host_u64 (bytes);
      vp++;
      fformat (stdout, "sw_if_index: %d.%s.packets %lld\n",
               sw_if_index, counter_name, packets);
      fformat (stdout, "sw_if_index: %d.%s.bytes %lld\n",
               sw_if_index, counter_name, bytes);
      sw_if_index++;
    }

}

static void vl_api_vnet_per_interface_combined_counters_t_handler(vl_api_vnet_per_interface_combined_counters_t *mp)
{
  tod_now();
  fformat (stdout, "combined counters\n");
  vnet_combined_counter_t *vp = (vnet_combined_counter_t *) mp->data;
  u64 packets, bytes;

  int i, total;

  total = mp->count;

  for (i = 0; i < total; i++)
    {

      packets = clib_mem_unaligned (&vp->tx_packets, u64);
      packets = clib_net_to_host_u64 (packets);
      bytes = clib_mem_unaligned (&vp->tx_bytes, u64);
      bytes = clib_net_to_host_u64 (bytes);

      fformat (stdout, "sw_if_index: %d.tx.packets %lld\n",
               htonl(vp->sw_if_index), packets);
      fformat (stdout, "sw_if_index: %d.tx.bytes %lld\n",
               htonl(vp->sw_if_index), bytes);

      packets = clib_mem_unaligned (&vp->rx_packets, u64);
      packets = clib_net_to_host_u64 (packets);
      bytes = clib_mem_unaligned (&vp->rx_bytes, u64);
      bytes = clib_net_to_host_u64 (bytes);

      fformat (stdout, "sw_if_index: %d.rx.packets %lld\n",
               htonl(vp->sw_if_index), packets);
      fformat (stdout, "sw_if_index: %d.rx.bytes %lld\n",
               htonl(vp->sw_if_index), bytes);
      vp++;

    }
}

static void
noop_handler (void *notused)
{
}

#define vl_api_vnet_ip4_fib_counters_t_endian noop_handler
#define vl_api_vnet_ip4_fib_counters_t_print noop_handler
#define vl_api_vnet_ip6_fib_counters_t_endian noop_handler
#define vl_api_vnet_ip6_fib_counters_t_print noop_handler

#define vl_api_vnet_ip4_nbr_counters_t_endian noop_handler
#define vl_api_vnet_ip4_nbr_counters_t_print noop_handler
#define vl_api_vnet_ip6_nbr_counters_t_endian noop_handler
#define vl_api_vnet_ip6_nbr_counters_t_print noop_handler

#define vl_api_vnet_interface_simple_counters_t_endian noop_handler
#define vl_api_vnet_interface_simple_counters_t_print noop_handler

#define vl_api_vnet_interface_combined_counters_t_endian noop_handler
#define vl_api_vnet_interface_combined_counters_t_print noop_handler

#define vl_api_vnet_per_interface_combined_counters_t_endian noop_handler
#define vl_api_vnet_per_interface_combined_counters_t_print noop_handler

#define vl_api_vnet_per_interface_simple_counters_t_endian noop_handler
#define vl_api_vnet_per_interface_simple_counters_t_print noop_handler

#define foreach_api_msg                                                 \
_(SW_INTERFACE_DETAILS, sw_interface_details)                           \
_(WANT_INTERFACE_EVENTS_REPLY, want_interface_events_reply)             \
_(WANT_STATS_REPLY, want_stats_reply)                                   \
_(WANT_INTERFACE_SIMPLE_STATS_REPLY, want_interface_simple_stats_reply) \
_(VNET_INTERFACE_SIMPLE_COUNTERS, vnet_interface_simple_counters)       \
_(WANT_INTERFACE_COMBINED_STATS_REPLY, want_interface_combined_stats_reply)  \
_(VNET_INTERFACE_COMBINED_COUNTERS, vnet_interface_combined_counters)   \
_(WANT_PER_INTERFACE_COMBINED_STATS_REPLY, want_per_interface_combined_stats_reply) \
_(VNET_PER_INTERFACE_COMBINED_COUNTERS, vnet_per_interface_combined_counters)  \
_(WANT_PER_INTERFACE_SIMPLE_STATS_REPLY, want_per_interface_simple_stats_reply) \
_(VNET_PER_INTERFACE_SIMPLE_COUNTERS, vnet_per_interface_simple_counters) \
_(VNET_IP4_FIB_COUNTERS, vnet_ip4_fib_counters)                         \
_(VNET_IP4_NBR_COUNTERS, vnet_ip4_nbr_counters)                         \
_(VNET_IP6_FIB_COUNTERS, vnet_ip6_fib_counters)                         \
_(VNET_IP6_NBR_COUNTERS, vnet_ip6_nbr_counters)                         \
_(WANT_IP4_FIB_STATS_REPLY, want_ip4_fib_stats_reply)             \
_(WANT_IP4_NBR_STATS_REPLY, want_ip4_nbr_stats_reply)             \
_(WANT_IP6_FIB_STATS_REPLY, want_ip6_fib_stats_reply)             \
_(WANT_IP6_NBR_STATS_REPLY, want_ip6_nbr_stats_reply)             \
_(WANT_OAM_EVENTS_REPLY, want_oam_events_reply)                         \
_(OAM_EVENT, oam_event)                                                 \
_(OAM_ADD_DEL_REPLY, oam_add_del_reply)				                    \
_(VNET_IP4_FIB_COUNTERS, vnet_ip4_fib_counters)                         \
_(VNET_IP6_FIB_COUNTERS, vnet_ip6_fib_counters)                         \
_(IP_ADD_DEL_ROUTE_REPLY, ip_add_del_route_reply)                       \
_(SW_INTERFACE_ADD_DEL_ADDRESS_REPLY, sw_interface_add_del_address_reply) \
_(SW_INTERFACE_SET_TABLE_REPLY, sw_interface_set_table_reply)           \
_(TAP_CONNECT_REPLY, tap_connect_reply)                                 \
_(CREATE_VLAN_SUBIF_REPLY, create_vlan_subif_reply)                     \
_(PROXY_ARP_ADD_DEL_REPLY, proxy_arp_add_del_reply)			\
_(PROXY_ARP_INTFC_ENABLE_DISABLE_REPLY, proxy_arp_intfc_enable_disable_reply) \
_(IP_NEIGHBOR_ADD_DEL_REPLY, ip_neighbor_add_del_reply)                 \
_(RESET_FIB_REPLY, reset_fib_reply)                                     \
_(DHCP_PROXY_CONFIG_REPLY, dhcp_proxy_config_reply)                     \
_(DHCP_PROXY_SET_VSS_REPLY, dhcp_proxy_set_vss_reply)                   \
_(SET_IP_FLOW_HASH_REPLY, set_ip_flow_hash_reply)                       \
_(SW_INTERFACE_IP6ND_RA_CONFIG_REPLY, sw_interface_ip6nd_ra_config_reply) \
_(SW_INTERFACE_IP6ND_RA_PREFIX_REPLY, sw_interface_ip6nd_ra_prefix_reply) \
_(SW_INTERFACE_IP6_ENABLE_DISABLE_REPLY, sw_interface_ip6_enable_disable_reply) \
_(SW_INTERFACE_IP6_SET_LINK_LOCAL_ADDRESS_REPLY, sw_interface_ip6_set_link_local_address_reply) \
 _(CREATE_LOOPBACK_REPLY, create_loopback_reply)			\
 _(CREATE_LOOPBACK_INSTANCE_REPLY, create_loopback_instance_reply)	\
_(L2_PATCH_ADD_DEL_REPLY, l2_patch_add_del_reply)			\
_(SW_INTERFACE_SET_L2_XCONNECT_REPLY, sw_interface_set_l2_xconnect_reply) \
_(SW_INTERFACE_SET_L2_BRIDGE_REPLY, sw_interface_set_l2_bridge_reply)

int
connect_to_vpe (char *name)
{
  int rv = 0;

  rv = vl_client_connect_to_vlib ("/vpe-api", name, 32);

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           noop_handler,                        \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_api_msg;
#undef _

  shmem_hdr = api_main.shmem_hdr;

  return rv;
}

int
disconnect_from_vpe (void)
{
  vl_client_disconnect_from_vlib ();
  return 0;
}

void
link_up_down_enable_disable (test_main_t * tm, int enable)
{
  vl_api_want_interface_events_t *mp;

  /* Request admin / link up down messages */
  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_WANT_INTERFACE_EVENTS);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->enable_disable = enable;
  mp->pid = getpid ();
  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
  tm->link_events_on = enable;
}

void
want_stats_enable_disable (test_main_t * tm, int enable)
{
  vl_api_want_stats_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_WANT_STATS);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->enable_disable = enable;
  mp->pid = getpid ();
  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
  tm->stats_on = enable;
}

void
want_interface_simple_stats_enable_disable (test_main_t * tm, int enable)
{
  vl_api_want_interface_simple_stats_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_WANT_INTERFACE_SIMPLE_STATS);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->enable_disable = enable;
  mp->pid = getpid ();
  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
  tm->stats_on = enable;
}

void
want_interface_combined_stats_enable_disable (test_main_t * tm, int enable)
{
  vl_api_want_interface_simple_stats_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_WANT_INTERFACE_COMBINED_STATS);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->enable_disable = enable;
  mp->pid = getpid ();
  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
  tm->stats_on = enable;
}

void
want_per_interface_combined_stats_enable_disable (test_main_t * tm, u32 swif, int enable)
{
  vl_api_want_per_interface_combined_stats_t *mp;

  u32 *ifs = 0;
  int size;


  size = (sizeof (*mp) + ((sizeof(*ifs))));
  mp = vl_msg_api_alloc (size);
  memset (mp, 0, size);
  mp->_vl_msg_id = ntohs (VL_API_WANT_PER_INTERFACE_COMBINED_STATS);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->enable_disable = enable;
  mp->pid = getpid ();
  mp->num = 1;
  clib_memcpy (mp->sw_ifs, &swif, sizeof(u32));
  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
  tm->stats_on = enable;
  vec_free(ifs);
}

void
want_per_interface_simple_stats_enable_disable (test_main_t * tm, u32 swif, int enable)
{
  vl_api_want_per_interface_simple_stats_t *mp;

  u32 *ifs = 0;
  int size;


  size = (sizeof (*mp) + ((sizeof(*ifs))));
  mp = vl_msg_api_alloc (size);
  memset (mp, 0, size);
  mp->_vl_msg_id = ntohs (VL_API_WANT_PER_INTERFACE_SIMPLE_STATS);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->enable_disable = enable;
  mp->pid = getpid ();
  mp->num = 1;
  clib_memcpy (mp->sw_ifs, &swif, sizeof(u32));
  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
  tm->stats_on = enable;
  vec_free(ifs);
}

void
want_ip4_fib_stats_enable_disable (test_main_t * tm, int enable)
{
  vl_api_want_ip4_fib_stats_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_WANT_IP4_FIB_STATS);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->enable_disable = enable;
  mp->pid = getpid ();
  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
  tm->stats_on = enable;
}

void
want_ip4_nbr_stats_enable_disable (test_main_t * tm, int enable)
{
  vl_api_want_ip4_nbr_stats_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_WANT_IP4_NBR_STATS);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->enable_disable = enable;
  mp->pid = getpid ();
  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
  tm->stats_on = enable;
}

void
want_ip6_fib_stats_enable_disable (test_main_t * tm, int enable)
{
  vl_api_want_ip6_fib_stats_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_WANT_IP6_FIB_STATS);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->enable_disable = enable;
  mp->pid = getpid ();
  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
  tm->stats_on = enable;
}

void
want_ip6_nbr_stats_enable_disable (test_main_t * tm, int enable)
{
  vl_api_want_ip6_nbr_stats_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_WANT_IP6_NBR_STATS);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->enable_disable = enable;
  mp->pid = getpid ();
  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
  tm->stats_on = enable;
}

void
stats_enable_disable (test_main_t * tm, int enable)
{
  want_interface_simple_stats_enable_disable(tm, enable);
  want_interface_combined_stats_enable_disable(tm, enable);
}

void
oam_events_enable_disable (test_main_t * tm, int enable)
{
  vl_api_want_oam_events_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_WANT_OAM_EVENTS);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->enable_disable = enable;
  mp->pid = getpid ();
  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
  tm->oam_events_on = enable;
}

void
oam_add_del (test_main_t * tm, int is_add)
{
  vl_api_oam_add_del_t *mp;
  ip4_address_t tmp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_OAM_ADD_DEL);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->is_add = is_add;

  tmp.as_u32 = ntohl (0xc0a80101);	/* 192.168.1.1 */
  clib_memcpy (mp->src_address, tmp.as_u8, 4);

  tmp.as_u32 = ntohl (0xc0a80103);	/* 192.168.1.3 */
  clib_memcpy (mp->dst_address, tmp.as_u8, 4);

  mp->vrf_id = 0;
  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}

void
dump (test_main_t * tm)
{
  vl_api_sw_interface_dump_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_SW_INTERFACE_DUMP);
  mp->client_index = tm->my_client_index;
  mp->name_filter_valid = 1;
  strncpy ((char *) mp->name_filter, "eth", sizeof (mp->name_filter) - 1);

  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}

void
add_del_ip4_route (test_main_t * tm, int enable_disable)
{
  vl_api_ip_add_del_route_t *mp;
  u32 tmp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IP_ADD_DEL_ROUTE);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->table_id = ntohl (0);
  mp->create_vrf_if_needed = 1;

  mp->next_hop_sw_if_index = ntohl (5);
  mp->is_add = enable_disable;
  mp->next_hop_weight = 1;

  /* Next hop: 6.0.0.1 */
  tmp = ntohl (0x06000001);
  clib_memcpy (mp->next_hop_address, &tmp, sizeof (tmp));

  /* Destination: 10.0.0.1/32 */
  tmp = ntohl (0x0);
  clib_memcpy (mp->dst_address, &tmp, sizeof (tmp));
  mp->dst_address_length = 0;

  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}

void
add_del_ip6_route (test_main_t * tm, int enable_disable)
{
  vl_api_ip_add_del_route_t *mp;
  u64 tmp[2];

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IP_ADD_DEL_ROUTE);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->next_hop_sw_if_index = ntohl (5);
  mp->is_add = enable_disable;
  mp->is_ipv6 = 1;
  mp->next_hop_weight = 1;
  mp->dst_address_length = 64;

  /* add/del dabe::/64 via db01::11 */

  tmp[0] = clib_host_to_net_u64 (0xdabe000000000000ULL);
  tmp[1] = clib_host_to_net_u64 (0x0ULL);
  clib_memcpy (mp->dst_address, &tmp[0], 8);
  clib_memcpy (&mp->dst_address[8], &tmp[1], 8);

  tmp[0] = clib_host_to_net_u64 (0xdb01000000000000ULL);
  tmp[1] = clib_host_to_net_u64 (0x11ULL);
  clib_memcpy (mp->next_hop_address, &tmp[0], 8);
  clib_memcpy (&mp->next_hop_address[8], &tmp[1], 8);

  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}

void
add_del_interface_address (test_main_t * tm, int enable_disable)
{
  vl_api_sw_interface_add_del_address_t *mp;
  u32 tmp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_SW_INTERFACE_ADD_DEL_ADDRESS);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->sw_if_index = ntohl (5);
  mp->is_add = enable_disable;
  mp->address_length = 8;

  tmp = ntohl (0x01020304);
  clib_memcpy (mp->address, &tmp, 4);

  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}

void
add_del_v6_interface_address (test_main_t * tm, int enable_disable)
{
  vl_api_sw_interface_add_del_address_t *mp;
  u64 tmp[2];

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_SW_INTERFACE_ADD_DEL_ADDRESS);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->is_ipv6 = 1;
  mp->sw_if_index = ntohl (5);
  mp->is_add = enable_disable;
  mp->address_length = 64;

  tmp[0] = clib_host_to_net_u64 (0xdb01000000000000ULL);
  tmp[1] = clib_host_to_net_u64 (0x11ULL);

  clib_memcpy (mp->address, &tmp[0], 8);
  clib_memcpy (&mp->address[8], &tmp[1], 8);

  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}

void
del_all_interface_addresses (test_main_t * tm)
{
  vl_api_sw_interface_add_del_address_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_SW_INTERFACE_ADD_DEL_ADDRESS);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->sw_if_index = ntohl (5);
  mp->del_all = 1;

  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}

void
set_interface_table (test_main_t * tm, int is_ipv6, u32 vrf_id)
{
  vl_api_sw_interface_set_table_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_SW_INTERFACE_SET_TABLE);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->sw_if_index = ntohl (5);
  mp->is_ipv6 = is_ipv6;
  mp->vrf_id = ntohl (vrf_id);

  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}

void
connect_unix_tap (test_main_t * tm, char *name)
{
  vl_api_tap_connect_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_TAP_CONNECT);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  strncpy ((char *) mp->tap_name, name, sizeof (mp->tap_name) - 1);
  mp->use_random_mac = 1;
  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}

void
create_vlan_subif (test_main_t * tm, u32 vlan_id)
{
  vl_api_create_vlan_subif_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_CREATE_VLAN_SUBIF);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->sw_if_index = ntohl (5);
  mp->vlan_id = ntohl (vlan_id);

  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}

void
add_del_proxy_arp (test_main_t * tm, int is_add)
{
  vl_api_proxy_arp_add_del_t *mp;
  u32 tmp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_PROXY_ARP_ADD_DEL);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->vrf_id = ntohl (11);
  mp->is_add = is_add;

  /* proxy fib 11, 1.1.1.1 -> 1.1.1.10 */
  tmp = ntohl (0x01010101);
  clib_memcpy (mp->low_address, &tmp, 4);

  tmp = ntohl (0x0101010a);
  clib_memcpy (mp->hi_address, &tmp, 4);

  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}

void
proxy_arp_intfc_enable_disable (test_main_t * tm, int enable_disable)
{
  vl_api_proxy_arp_intfc_enable_disable_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_PROXY_ARP_INTFC_ENABLE_DISABLE);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->sw_if_index = ntohl (6);
  mp->enable_disable = enable_disable;

  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}

void
add_ip4_neighbor (test_main_t * tm, int add_del)
{
  vl_api_ip_neighbor_add_del_t *mp;
  u32 tmp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IP_NEIGHBOR_ADD_DEL);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->sw_if_index = ntohl (6);
  mp->is_add = add_del;

  memset (mp->mac_address, 0xbe, sizeof (mp->mac_address));

  tmp = ntohl (0x0101010a);
  clib_memcpy (mp->dst_address, &tmp, 4);

  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}

void
add_ip6_neighbor (test_main_t * tm, int add_del)
{
  vl_api_ip_neighbor_add_del_t *mp;
  u64 tmp[2];

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IP_NEIGHBOR_ADD_DEL);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->sw_if_index = ntohl (6);
  mp->is_add = add_del;
  mp->is_ipv6 = 1;

  memset (mp->mac_address, 0xbe, sizeof (mp->mac_address));

  tmp[0] = clib_host_to_net_u64 (0xdb01000000000000ULL);
  tmp[1] = clib_host_to_net_u64 (0x11ULL);

  clib_memcpy (mp->dst_address, &tmp[0], 8);
  clib_memcpy (&mp->dst_address[8], &tmp[1], 8);

  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}

void
reset_fib (test_main_t * tm, u8 is_ip6)
{
  vl_api_reset_fib_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_RESET_FIB);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->vrf_id = ntohl (11);
  mp->is_ipv6 = is_ip6;

  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}

void
dhcpv6_set_vss (test_main_t * tm)
{
  vl_api_dhcp_proxy_set_vss_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_DHCP_PROXY_SET_VSS);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->oui = ntohl (6);
  mp->fib_id = ntohl (60);
  mp->is_add = 1;
  mp->is_ipv6 = 1;
  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}

void
dhcpv4_set_vss (test_main_t * tm)
{
  vl_api_dhcp_proxy_set_vss_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_DHCP_PROXY_SET_VSS);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->oui = ntohl (4);
  mp->fib_id = ntohl (40);
  mp->is_add = 1;
  mp->is_ipv6 = 0;
  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}

void
dhcp_set_vss (test_main_t * tm)
{
  dhcpv4_set_vss (tm);
  dhcpv6_set_vss (tm);
}

void
dhcp_set_proxy (test_main_t * tm, int ipv6)
{
  vl_api_dhcp_proxy_config_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_DHCP_PROXY_CONFIG);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->is_ipv6 = ipv6;
  mp->is_add = 1;
  mp->dhcp_server[0] = 0x20;
  mp->dhcp_server[1] = 0x01;
  mp->dhcp_server[2] = 0xab;
  mp->dhcp_server[3] = 0xcd;
  mp->dhcp_server[4] = 0x12;
  mp->dhcp_server[5] = 0x34;
  mp->dhcp_server[6] = 0xfe;
  mp->dhcp_server[7] = 0xdc;
  mp->dhcp_server[14] = 0;
  mp->dhcp_server[15] = 0x2;

  mp->dhcp_src_address[0] = 0x20;
  mp->dhcp_src_address[1] = 0x01;
  mp->dhcp_src_address[2] = 0xab;
  mp->dhcp_src_address[3] = 0xcd;
  mp->dhcp_src_address[4] = 0x12;
  mp->dhcp_src_address[5] = 0x34;
  mp->dhcp_src_address[6] = 0x56;
  mp->dhcp_src_address[7] = 0x78;
  mp->dhcp_src_address[14] = 0;
  mp->dhcp_src_address[15] = 0x2;

  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}

void
set_ip_flow_hash (test_main_t * tm, u8 is_ip6)
{
  vl_api_set_ip_flow_hash_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_SET_IP_FLOW_HASH);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->vrf_id = 0;
  mp->is_ipv6 = is_ip6;
  mp->dst = 1;
  mp->reverse = 1;

  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}

void
ip6nd_ra_config (test_main_t * tm, int is_no)
{
  vl_api_sw_interface_ip6nd_ra_config_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));

  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->sw_if_index = ntohl (5);
  mp->is_no = is_no;

  mp->suppress = 1;


  mp->_vl_msg_id = ntohs (VL_API_SW_INTERFACE_IP6ND_RA_CONFIG);
  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}

void
ip6nd_ra_prefix (test_main_t * tm, int is_no)
{
  vl_api_sw_interface_ip6nd_ra_prefix_t *mp;
  u64 tmp[2];

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));

  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->sw_if_index = ntohl (5);
  mp->is_no = is_no;

  mp->use_default = 1;


  tmp[0] = clib_host_to_net_u64 (0xdb01000000000000ULL);
  tmp[1] = clib_host_to_net_u64 (0x11ULL);


  clib_memcpy (mp->address, &tmp[0], 8);
  clib_memcpy (&mp->address[8], &tmp[1], 8);

  mp->address_length = 64;


  mp->_vl_msg_id = ntohs (VL_API_SW_INTERFACE_IP6ND_RA_PREFIX);
  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}

void
ip6_enable_disable (test_main_t * tm, int enable)
{
  vl_api_sw_interface_ip6_enable_disable_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));

  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->sw_if_index = ntohl (5);
  mp->enable = (enable == 1);;

  mp->_vl_msg_id = ntohs (VL_API_SW_INTERFACE_IP6_ENABLE_DISABLE);
  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}

void
loop_create (test_main_t * tm)
{
  vl_api_create_loopback_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = ntohs (VL_API_CREATE_LOOPBACK);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}

void
ip6_set_link_local_address (test_main_t * tm)
{
  vl_api_sw_interface_ip6_set_link_local_address_t *mp;
  u64 tmp[2];

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));

  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->sw_if_index = ntohl (5);

  tmp[0] = clib_host_to_net_u64 (0xfe80000000000000ULL);
  tmp[1] = clib_host_to_net_u64 (0x11ULL);

  clib_memcpy (mp->address, &tmp[0], 8);
  clib_memcpy (&mp->address[8], &tmp[1], 8);

  mp->_vl_msg_id = ntohs (VL_API_SW_INTERFACE_IP6_SET_LINK_LOCAL_ADDRESS);

  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}


void
set_flags (test_main_t * tm, int up_down)
{
  vl_api_sw_interface_set_flags_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = ntohs (VL_API_SW_INTERFACE_SET_FLAGS);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->sw_if_index = ntohl (5);
  mp->admin_up_down = up_down;
  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);

}

void
l2_patch_add_del (test_main_t * tm, int is_add)
{
  vl_api_l2_patch_add_del_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_L2_PATCH_ADD_DEL);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->is_add = is_add;
  mp->rx_sw_if_index = ntohl (1);
  mp->tx_sw_if_index = ntohl (2);

  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}

void
l2_xconnect (test_main_t * tm)
{
  vl_api_sw_interface_set_l2_xconnect_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_SW_INTERFACE_SET_L2_XCONNECT);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->rx_sw_if_index = ntohl (5);
  mp->tx_sw_if_index = ntohl (6);
  mp->enable = 1;

  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}

void
l2_bridge (test_main_t * tm)
{
  vl_api_sw_interface_set_l2_bridge_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_SW_INTERFACE_SET_L2_BRIDGE);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->rx_sw_if_index = ntohl (5);
  mp->bd_id = ntohl (6);
  mp->bvi = ntohl (1);
  mp->shg = ntohl (0);
  mp->enable = 1;

  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}

int
main (int argc, char **argv)
{
  api_main_t *am = &api_main;
  test_main_t *tm = &test_main;
  int ch;
  int pid = getpid();
  char prefix[] = "tc_";
  char name[0];
  sprintf(name, "%s%d\n", prefix, pid);
  connect_to_vpe (name);

  int sw_if_index;
  if (sscanf (argv[1], "%i", &sw_if_index) != 1) {
      fprintf(stderr, "error - not an integer");
  }

  tm->vl_input_queue = shmem_hdr->vl_input_queue;
  tm->my_client_index = am->my_client_index;

  fformat (stdout, "Type 'h' for help, 'q' to quit...\n");

  while (1)
    {
      ch = getchar ();
      switch (ch)
	{
	case 'q':
	  goto done;
	case 'd':
	  dump (tm);
	  break;
	case 'A':
	  want_stats_enable_disable (tm, 1 /* enable_disable */ );
	  break;
	case 'a':
	  want_stats_enable_disable (tm, 0 /* enable_disable */ );
	  break;
	case '3':
	  want_ip4_fib_stats_enable_disable (tm, 0 /* disable */ );
	  break;
	case '4':
	  want_ip4_fib_stats_enable_disable (tm, 1 /* enable */ );
	  break;
	case '5':
	  want_ip6_fib_stats_enable_disable (tm, 0 /* disable */ );
	  break;
	case '6':
	  want_ip6_fib_stats_enable_disable (tm, 1 /* enable */ );
	  break;
	case 'S':
	  want_interface_simple_stats_enable_disable (tm, 1 /* enable_disable */ );
	  break;
	case 's':
	  want_interface_simple_stats_enable_disable (tm, 0 /* enable_disable */ );
	  break;

    case 'C':
	  want_interface_combined_stats_enable_disable (tm, 1 /* enable_disable */ );
	  break;
	case 'c':
	  want_interface_combined_stats_enable_disable (tm, 0 /* enable_disable */ );
	  break;

    case 'X':
	  want_per_interface_simple_stats_enable_disable (tm, sw_if_index, 1 /* enable_disable */ );
	  break;
	case 'x':
	  want_per_interface_simple_stats_enable_disable (tm, sw_if_index , 0 /* enable_disable */ );
	  break;

    case 'Y':
	  want_per_interface_combined_stats_enable_disable (tm, sw_if_index, 1 /* enable_disable */ );
	  break;
	case 'y':
	  want_per_interface_combined_stats_enable_disable (tm, sw_if_index , 0 /* enable_disable */ );
	  break;

	case 'O':
	  oam_events_enable_disable (tm, 0 /* enable */ );
	  break;

	case 'o':
	  oam_events_enable_disable (tm, 1 /* enable */ );
	  break;


	case 'h':
	  fformat (stdout, "q=quit,d=dump,L=link evts on,l=link evts off\n");
	  fformat (stdout, "A=all stats on,a=off\n");
	  fformat (stdout, "4=ip4 fib stats on, 3=off\n");
	  fformat (stdout, "6=ip6 fib stats on, 5=off\n");
	  fformat (stdout, "S=interface simple stats on, s=off\n");
	  fformat (stdout, "C=combined simple stats on, s=off\n");
	default:
	  break;
	}

    }

done:

  if (tm->link_events_on)
    link_up_down_enable_disable (tm, 0 /* enable */ );
  if (tm->stats_on)
    stats_enable_disable (tm, 0 /* enable */ );
  if (tm->oam_events_on)
    oam_events_enable_disable (tm, 0 /* enable */ );

  disconnect_from_vpe ();
  exit (0);
}

#undef vl_api_version
#define vl_api_version(n,v) static u32 vpe_api_version = v;
#include <vpp/api/vpe.api.h>
#undef vl_api_version

void
vl_client_add_api_signatures (vl_api_memclnt_create_t * mp)
{
  /*
   * Send the main API signature in slot 0. This bit of code must
   * match the checks in ../vpe/api/api.c: vl_msg_api_version_check().
   */
  mp->api_versions[0] = clib_host_to_net_u32 (vpe_api_version);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
