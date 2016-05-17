
/*
 * netcp.c - skeleton vpp engine plug-in 
 *
 * Copyright (c) <current-year> <your-organization>
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
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <netcp/netcp.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>

clib_error_t * 
vlib_plugin_register (vlib_main_t * vm, vnet_plugin_handoff_t * h,
                      int from_early_init)
{
  netcp_main_t * nm = &netcp_main;
  clib_error_t * error = 0;

  sm->vlib_main = vm;
  sm->vnet_main = h->vnet_main;
  sm->ethernet_main = h->ethernet_main;

  return error;
}

static uword
netcp_send_process (vlib_main_t * vm,
                    vlib_node_runtime_t * rt,
                    vlib_frame_t * f)
{
  netcp_main_t * nm = &netcp_main;
  f64 poll_time_remaining;
  uword event_type, * event_data = 0;

  poll_time_remaining = nm->sleep_timer;

  while (1) 
    {
      int i;

      poll_time_remaining = 
        vlib_process_wait_for_event_or_clock (vm, poll_time_remaining);
        
      event_type = vlib_process_get_events (vm, &event_data);
      switch (event_type) {
      case ~0:                /* no events => timeout */
        break;

        /* 
         * $$$$ FIXME: add cases / handlers for each event type 
         */
      case EVENT1:
        for (i = 0; i < vec_len (event_data); i++) 
          handle_event1 (mm, event_data[i]);
        break;

      case EVENT2:
        for (i = 0; i < vec_len (event_data); i++) 
          handle_event2 (vm, event_data[i]);
        break;

        /* ... and so forth for each event type */

      default:
        /* This should never happen... */
        clib_warning ("BUG: unhandled event type %d", event_type);
        break;
      }
      vec_reset_length (event_data);

      /* Timer expired, call periodic function */
      if (vlib_process_suspend_time_is_zero (poll_time_remaining)) {
        netcp_send_process_periodic (vm);
        poll_time_remaining = NETCP_SEND_PROCESS_POLL_PERIOD;
      }
    }

    return 0;
}

VLIB_REGISTER_NODE (netcp_send_process_node,static) = {
    .function = netcp_send_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "netcp-send-process",
};

static clib_error_t *
netcp_init (vlib_main_t * vm)
{
  netcp_main_t * nm = &netcp_main;

  ip4_register_protocol (IP_PROTOCOL_NETCP, udp4_input_node.index);

  /* nothing doing to begin with */
  nm->sleep_timer = 1000.0;
  nm->vlib_main = vm;
  nm->vnet_main = vnet_get_main();
  nm->random_seed = 0xdeaddabe;
  nm->session_by_id = hash_create (0, sizeof (uword));

  return 0;
}

VLIB_INIT_FUNCTION (netcp_init);

static inline int netcp_send_ip4 (netcp_main_t * nm, ip4_address_t * to_addr, 
                                  ip4_address_t * from_addr, 
                                  u8 * src_file, u8 * dst_file)
{
  netcp_session_t *s;
  ip4_and_netcp_header_t *ipn;
  ip4_header_t * ip;
  netcp_header_t * nh;
  pool_get (nm->sessions, s);
  memset (s, 0, sizeof (*s));

  /* $$$$ mmap file */

  s->to.ip4.as_u32 = to_addr->as_u32;
  s->from.ip4.as_u32 = from_addr->as_u32;
  s->src_file = src_file;
  s->dst_file = dst_file;
  s->session_id = random_u32 (&nm->random_seed);

  /* Set up a rewrite string */
  vec_validate (s->rewrite, sizeof (ip4_and_netcp_header_t) -1);

  ipn = (ip4_and_netcp_header_t *) s->rewrite;
  
  ip = &ipn->ip;
  nh = &ipn->netcp;

  /* Fixed portion ip4 header */
  ip = &h0->ip4;
  ip->ip_version_and_header_length = 0x45;
  ip->ttl = 254;
  ip->protocol = IP_PROTOCOL_NETCP;
  ip->src_address.as_u32 = s->from.ip4_as_u32;
  ip->dst_address.as_u32 = s->to.ip4_as_u32;
  ip->checksum = ip4_header_checksum (ip);
  nh->netcp_version = NETCP_VERSION;
  nh->type = 0;
  nh->session_id = clib_host_to_net_u32(s->session_id);

  hash_set (nm->session_by_id, s->session_id, s - nm->sessions);

  send_send_file (s);
  
  return 0;
}

static inline int netcp_send_ip6 (netcp_main_t * nm, ip6_address_t * to_addr, 
                                  ip6_address_t * from_addr, 
                                  u8 * src_file, u8 * dst_file)
{
  clib_warning ("ip6 not yet implemented");
  return -1;
}

static int netcp_send (netcp_main_t * nm, void * to_addr, void * from_addr,
                       u8 * src_file, u8 * dst_file, int is_ip4)
{
  if (is_ip4)
    return netcp_send_ip4 (nm, (ip4_address_t *)to_addr, 
                           (ip4_address_t *)from_addr,
                           src_file, dst_file);
  else
    return netcp_send_ip6 (nm, (ip6_address_t *)to_addr, 
                           (ip6_address_t *)from_addr,
                           src_file, dst_file);
}

static clib_error_t *
netcp_send_command_fn (vlib_main_t * vm,
		 unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{
  netcp_main_t * nm = &netcp_main;
  ip4_address_t addr4_to, addr4_from;
  u8 addr4_to_set = 0, addr4_from_set = 0;
  ip6_address_t addr6_to, addr6_from;
  u8 addr6_to_set = 0, addr6_from_set = 0;
  u8 * src_file = 0;
  u8 * dst_file = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) 
    {
      if (unformat (input, "to %U", unformat_ip4_address, &addr4_to))
        addr4_to_set = 1;
      if (unformat (input, "from %U", unformat_ip4_address, &addr4_from))
        addr4_from set = 1;
      else if (unformat (input, "to %U", unformat_ip6_address, &addr6_to))
        addr6_to_set = 1;
      else if (unformat (input, "from %U", unformat_ip6_address, &addr6_from))
        addr6_from_set = 1;
      else if (unformat (input, "src %s", &src_file))
        ;
      else if (unformat (input, "dst %s", &dst_file))
        ;
      else
        break;
    }

  if (addr4_to_set == 0 && addr6_to_set == 0)
    return clib_error_return (0, "to <ip-address> missing");

  if (addr4_from_set == 0 && addr6_from == 0)
    return clib_error_return (0, "from <ip-address> missing");

  if ((addr4_to_set && addr6_to_set) ||
      (addr4_from_set && addr6_from_set) ||
      (addr4_to_set && addr6_from_set) ||
      (addr6_to_set && addr4_from_set))
    return clib_error_return (0, "mixed ip4/ip6 addresses");

  if (src_file == 0)
    return clib_error_return (0, "source filename missing");
  if (dst_file == 0)
    dst_file = vec_dup (src_file);
  
  if (addr4_to_set)
    rv = netcp_send (nm, (void *) &addr4_to, (void *)&addr4_from, 
                     src_file, dst_file, 1 /* is_ip4 */);
  else
    rv = netcp_send (nm, (void *) &addr6_to, (void *) &addr6_from, 
                     src_file, dst_file, 0 /* is_ip4 */);
  
  switch (rv)
    {
    case 0:
      break;
    default:
      return clib_error_return (0, "netcp_send returned %d", rv);
    }
  return 0;
}

VLIB_CLI_COMMAND (netcp_send_command, static) = {
    .path = "netcp send",
    .short_help = "netcp send to <ip> from <ip> src <fn> dst <fn>",
    .function = netcp_send_command_fn,
};

