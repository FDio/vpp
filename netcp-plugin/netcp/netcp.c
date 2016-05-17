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

  nm->vlib_main = vm;
  nm->vnet_main = h->vnet_main;
  nm->ethernet_main = h->ethernet_main;

  return error;
}

static void send_window (netcp_main_t * nm, netcp_session_t *s)
{
  vlib_main_t * vm = nm->vlib_main;
  vlib_frame_t * f;
  vlib_buffer_t * b0;
  static u32 *buffers;
  u32 bi0;
  u32 nalloc;
  vlib_buffer_free_list_t * fl;
  ip4_and_netcp_header_t *ipn;
  netcp_data_header_t * dh;
  u32 *to_next;
  ip4_header_t * ip;
  netcp_header_t * nh;
  int i;
  u32 send_count;
  u64 total_segments, current_segment;
  u32 * buffers_tmp;
  u32 this_alloc_request, total_alloc;
  
  ASSERT(s->window_size);

  s->retry_timer = vlib_time_now(vm) + 10.0;

  total_segments = (s->size_in_bytes + (nm->segment_size-1)) 
    / nm->segment_size;
  current_segment = s->my_current_offset / nm->segment_size;

  send_count = clib_min (s->window_size, total_segments - current_segment);

  vec_validate (buffers, send_count-1);

  buffers_tmp = buffers;
  this_alloc_request = send_count;
  total_alloc = 0;
  do {
      nalloc = vlib_buffer_alloc_from_free_list 
          (vm, buffers_tmp, this_alloc_request, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
      this_alloc_request -= nalloc;
      buffers_tmp += nalloc;
      total_alloc += nalloc;
  } while (nalloc > 0 && this_alloc_request > 0);
      
  /* Timer-based retry if out of buffers... */
  if (total_alloc != send_count)
    {
      clib_warning ("short buffer alloc: %d instead of %d", total_alloc, 
                    send_count);
      vlib_buffer_free (vm, buffers, total_alloc);
      return;
    }

  f = vlib_get_frame_to_node (vm, 
                              s->is_ip4 ? nm->ip4_lookup_index 
                              : nm->ip6_lookup_index);
  
  fl = vlib_buffer_get_free_list (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);

  to_next = vlib_frame_vector_args(f);
  f->n_vectors = send_count;

  CW ("send count %d", send_count);

  for (i = 0; i < send_count; i++)
    {
      /* buffer init */
      bi0 = buffers[i];
      to_next[0] = bi0;
      to_next++;
      b0 = vlib_get_buffer (vm, bi0);
      vlib_buffer_init_for_free_list (b0, fl);
      b0->clone_count = 0;
      b0->current_data = 0;
      /* Default FIB, fake rx on local interface */
      vnet_buffer(b0)->sw_if_index[VLIB_TX] =
          vnet_buffer(b0)->sw_if_index[VLIB_RX] = 0;

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT(b0);

      /* Paint header into rewrite space */
      vlib_buffer_advance(b0, -(word)(vec_len(s->rewrite)));
      ipn = vlib_buffer_get_current(b0);
      ip = &ipn->ip;
      nh = &ipn->netcp;
      clib_memcpy (ipn, s->rewrite, vec_len(s->rewrite));
      
      nh->type = NETCP_TYPE_DATA;
      dh = (netcp_data_header_t *)(nh+1);
      b0->current_length += nm->segment_size + (sizeof(*dh));
      dh->offset = clib_host_to_net_u64 (s->my_current_offset);
      clib_memcpy (dh->data, s->map_addr + s->my_current_offset, 
                   nm->segment_size);
      ip->length = clib_host_to_net_u16(b0->current_length);
      ip->checksum = ip4_header_checksum (ip);
      CW ("send: offset %lld", s->my_current_offset);

      s->my_current_offset += nm->segment_size;
    }

  vlib_put_frame_to_node (vm, s->is_ip4 ? nm->ip4_lookup_index 
                          : nm->ip6_lookup_index, f);
}

f64 netcp_send_process_periodic (netcp_main_t * nm)
{
  netcp_session_t * s;
  f64 poll_time_remaining = 1000.0;
  vlib_main_t * vm = nm->vlib_main;
  f64 now = vlib_time_now (vm);
  f64 time_remaining_this_session;
  static u32 * dead_session_indices;
  int i;

  vec_reset_length(dead_session_indices);

  if (pool_elts(nm->sessions) > 0)
      poll_time_remaining = 10.0;

  pool_foreach (s, nm->sessions,
  ({
    time_remaining_this_session = (s->retry_timer - now);
    if (time_remaining_this_session <= 0.0)
      {
        s->my_current_offset = s->their_current_offset + nm->segment_size;
        s->retry_count++;

        if (s->retry_count < 5)
          send_window (nm, s);
        else
          vec_add1 (dead_session_indices, s - nm->sessions);
      }
  }));

  for (i = 0; i < vec_len(dead_session_indices); i++)
    {
      s = pool_elt_at_index (nm->sessions, i);
      clib_warning ("session from %U to %U src-file %s timeout...",
                    format_ip4_address, &s->from.ip4, 
                    format_ip4_address, &s->to.ip4, 
                    s->src_file);

      unmap_file (s->dst_file, s->map_addr, s->size_in_bytes, 
                  0 /* truncate*/);
      hash_unset (nm->session_by_id, s->session_id);
      vec_free (s->src_file);
      vec_free (s->dst_file);
      vec_free (s->rewrite);
      pool_put (nm->sessions, s);
    }

  return poll_time_remaining;
}


static uword
netcp_send_process (vlib_main_t * vm,
                    vlib_node_runtime_t * rt,
                    vlib_frame_t * f)
{
  netcp_main_t * nm = &netcp_main;
  f64 poll_time_remaining;
  f64 now;
  netcp_session_t *s;
  uword event_type, * event_data = 0;

  poll_time_remaining = nm->process_sleep_timer;

  ip4_register_protocol (IP_PROTOCOL_NETCP, netcp_node.index);


  while (1) 
    {
      int i;

      CW ("sleep for %.2f seconds", poll_time_remaining);
      poll_time_remaining = 
        vlib_process_wait_for_event_or_clock (vm, poll_time_remaining);
        
      event_type = vlib_process_get_events (vm, &event_data);
      CW ("awake");
      now = vlib_time_now (vm);
      switch (event_type) {
      case ~0:                /* no events => timeout */
        break;

      case NETCP_PROCESS_EVENT_SET_TIMER:
        for (i = 0; i < vec_len (event_data); i++) 
          {
            if (pool_is_free_index (nm->sessions, event_data[i]))
              continue;

            s = pool_elt_at_index (nm->sessions, event_data[i]);

            CW ("retry %.2f now %.2f delta %.2f",
                s->retry_timer, now, s->retry_timer - now);
            poll_time_remaining = clib_min (poll_time_remaining,
                                            s->retry_timer - now);
          }
        break;

      default:
        /* This should never happen... */
        clib_warning ("BUG: unhandled event type %d", event_type);
        break;
      }
      vec_reset_length (event_data);

      /* Timer expired, call periodic function */
      if (vlib_process_suspend_time_is_zero (poll_time_remaining)) 
        {
          poll_time_remaining = netcp_send_process_periodic (nm);
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
  vlib_node_t * n;
  clib_error_t * error; 

  /* Otherwise, the protocol decode table entry will vanish */
  error = vlib_call_init_function (vm, udp_init);
  if (error)
      clib_error_report (error);

  /* nothing doing to begin with */
  nm->process_sleep_timer = 1000.0;
  nm->vlib_main = vm;
  nm->vnet_main = vnet_get_main();
  nm->random_seed = 0xdeaddabe;
  nm->session_by_id = hash_create (0, sizeof (uword));

  n = vlib_get_node_by_name (vm, (u8 *) "ip4-lookup");
  ASSERT(n);
  nm->ip4_lookup_index = n->index;

  n = vlib_get_node_by_name (vm, (u8 *) "ip6-lookup");
  ASSERT(n);
  nm->ip6_lookup_index = n->index;
  nm->segment_size = 1500 
      - (sizeof (ip4_header_t) + sizeof (netcp_header_t) 
         + sizeof (netcp_data_header_t));
  return 0;
}

VLIB_INIT_FUNCTION (netcp_init);

static void send_send_file (netcp_main_t * nm, netcp_session_t *s)
{
  vlib_main_t * vm = nm->vlib_main;
  vlib_frame_t * f;
  vlib_buffer_t * b0;
  u32 bi0;
  u32 nalloc;
  vlib_buffer_free_list_t * fl;
  ip4_and_netcp_header_t *ipn;
  netcp_send_file_header_t * sf;
  u32 *to_next;
  
  s->retry_timer = vlib_time_now(vm) + 10.0;

  nalloc = vlib_buffer_alloc_from_free_list 
    (vm, &bi0, 1, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);

  /* Timer-based retry if out of buffers... */
  if (nalloc != 1)
    return;

  f = vlib_get_frame_to_node (vm, 
                              s->is_ip4 ? nm->ip4_lookup_index 
                              : nm->ip6_lookup_index);
  
  fl = vlib_buffer_get_free_list (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);

  b0 = vlib_get_buffer (vm, bi0);
  vlib_buffer_init_for_free_list (b0, fl);
  b0->clone_count = 0;
  b0->current_data = 0;
  b0->current_length = sizeof (*ipn) + sizeof (netcp_send_file_header_t);
  vnet_buffer(b0)->sw_if_index[VLIB_TX] =
      vnet_buffer(b0)->sw_if_index[VLIB_RX] = 0;
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT(b0);

  ipn = vlib_buffer_get_current (b0);
  clib_memcpy (ipn, s->rewrite, vec_len(s->rewrite));
  
  sf = (netcp_send_file_header_t *)(ipn+1);
  clib_memcpy (sf->dst_file, s->dst_file, vec_len(s->dst_file));
  sf->segment_size = clib_host_to_net_u16 (nm->segment_size);
  sf->size_in_bytes = clib_host_to_net_u64 (s->size_in_bytes);
  sf->window_size = s->window_size;

  if (1 /* is_ip4 */)
    {
      ip_csum_t sum0;
      u16 new_l0, old_l0;
      
      sum0 = ipn->ip.checksum;
      old_l0 = 0;
      
      /* old_l0 always 0, see the rewrite setup */
      new_l0 = 
        clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
      sum0 = ip_csum_update (sum0, old_l0, new_l0, ip4_header_t,
                             length /* changed member */);
      ipn->ip.checksum = ip_csum_fold (sum0);
      ipn->ip.length = new_l0;
    }
  else
    {
      /* patch ip6 next-protocol */
    }
  to_next = vlib_frame_vector_args(f);
  to_next[0] = bi0;
  f->n_vectors = 1;

  vlib_put_frame_to_node (vm, 
                          s->is_ip4 ? nm->ip4_lookup_index 
                          : nm->ip6_lookup_index, f);

  vlib_process_signal_event 
    (vm, netcp_send_process_node.index,
     NETCP_PROCESS_EVENT_SET_TIMER, s - nm->sessions);
}

static inline int netcp_send_ip4 (netcp_main_t * nm, ip4_address_t * to_addr, 
                                  ip4_address_t * from_addr, 
                                  u8 * src_file, u8 * dst_file, 
                                  u32 window_size)
{
  netcp_session_t *s;
  ip4_and_netcp_header_t *ipn;
  ip4_header_t * ip;
  netcp_header_t * nh;

  if (window_size > 0xff)
    return -2;

  pool_get (nm->sessions, s);
  memset (s, 0, sizeof (*s));

  s->to.ip4.as_u32 = to_addr->as_u32;
  s->from.ip4.as_u32 = from_addr->as_u32;
  s->src_file = src_file;
  s->dst_file = dst_file;
  s->session_id = random_u32 (&nm->random_seed);
  s->is_ip4 = 1;
  s->is_sender = 1;
  s->segment_size = nm->segment_size;
  s->window_size = window_size;

  s->map_addr = map_file (src_file, &s->size_in_bytes, 0 /* is_write */);
  if (s->map_addr == 0)
    {
      pool_put (nm->sessions, s);
      return -1;
    }

  /* Set up a rewrite string */
  vec_validate (s->rewrite, sizeof (ip4_and_netcp_header_t) -1);

  ipn = (ip4_and_netcp_header_t *) s->rewrite;
  
  ip = &ipn->ip;
  nh = &ipn->netcp;

  /* Fixed portion ip4 header */
  ip->ip_version_and_header_length = 0x45;
  ip->ttl = 254;
  ip->protocol = IP_PROTOCOL_NETCP;
  ip->src_address.as_u32 = s->from.ip4.as_u32;
  ip->dst_address.as_u32 = s->to.ip4.as_u32;
  ip->checksum = ip4_header_checksum (ip);
  nh->netcp_version = NETCP_VERSION;
  nh->type = 0;
  nh->session_id = clib_host_to_net_u32(s->session_id);

  hash_set (nm->session_by_id, s->session_id, s - nm->sessions);

  send_send_file (nm, s);
  send_window (nm, s);
  s->start_time = vlib_time_now(nm->vlib_main);
  
  return 0;
}

static inline int netcp_send_ip6 (netcp_main_t * nm, ip6_address_t * to_addr, 
                                  ip6_address_t * from_addr, 
                                  u8 * src_file, u8 * dst_file, u32 window_size)
{
  clib_warning ("ip6 not yet implemented");
  return -1;
}

static int netcp_send (netcp_main_t * nm, void * to_addr, void * from_addr,
                       u8 * src_file, u8 * dst_file, u32 window_size, 
                       int is_ip4)
{
  if (is_ip4)
    return netcp_send_ip4 (nm, (ip4_address_t *)to_addr, 
                           (ip4_address_t *)from_addr,
                           src_file, dst_file, window_size);
  else
    return netcp_send_ip6 (nm, (ip6_address_t *)to_addr, 
                           (ip6_address_t *)from_addr,
                           src_file, dst_file, window_size);
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
  u32 window_size = 10;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) 
    {
      if (unformat (input, "to %U", unformat_ip4_address, &addr4_to))
        addr4_to_set = 1;
      else if (unformat (input, "from %U", unformat_ip4_address, &addr4_from))
        addr4_from_set = 1;
      else if (unformat (input, "to %U", unformat_ip6_address, &addr6_to))
        addr6_to_set = 1;
      else if (unformat (input, "from %U", unformat_ip6_address, &addr6_from))
        addr6_from_set = 1;
      else if (unformat (input, "src %s", &src_file))
        ;
      else if (unformat (input, "dst %s", &dst_file))
        ;
      else if (unformat (input, "window %d", &window_size))
        ;
      else
        break;
    }

  if (addr4_to_set == 0 && addr6_to_set == 0)
    return clib_error_return (0, "to <ip-address> missing");

  if (addr4_from_set == 0 && addr6_from_set == 0)
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
                     src_file, dst_file, window_size, 1 /* is_ip4 */);
  else
    rv = netcp_send (nm, (void *) &addr6_to, (void *) &addr6_from, 
                     src_file, dst_file, window_size, 0 /* is_ip4 */);
  
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

