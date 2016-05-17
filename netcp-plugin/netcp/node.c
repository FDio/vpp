
/*
 * node.c - skeleton vpp engine plug-in dual-loop node skeleton
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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <netcp/netcp.h>

typedef struct {
  u32 next_index;
} netcp_trace_t;

/* packet trace format function */
static u8 * format_netcp_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  netcp_trace_t * t = va_arg (*args, netcp_trace_t *);
  
  s = format (s, "NETCP: next index %d", t->next_index);
  return s;
}

vlib_node_registration_t netcp_node;

#define foreach_netcp_error                     \
_(BAD_VERSION, "Bad version")                   \
_(BAD_TYPE, "Bad message type")                 \
_(BAD_OFFSET, "Bad offset")                     \
_(LOST_DATA, "Lost data pkts")                  \
_(NO_SESSION, "Unknown session")                \
_(FILES_CREATED, "Files created")               \
_(BOTCH, "Protocol botch")			\
_(FINAL_WINDOW_DRAIN, "Window drain acks")      \
_(COMPLETE, "Transfers completed")		

typedef enum {
#define _(sym,str) NETCP_ERROR_##sym,
  foreach_netcp_error
#undef _
  NETCP_N_ERROR,
} netcp_error_t;

static char * netcp_error_strings[] = {
#define _(sym,string) string,
  foreach_netcp_error
#undef _
};

typedef enum {
  NETCP_NEXT_IP4_LOOKUP,
  NETCP_NEXT_DROP,
  NETCP_N_NEXT,
} netcp_next_t;

static u32 ack_handler (netcp_main_t * nm, vlib_node_runtime_t * node, 
                        vlib_buffer_t * b0)
{
  vlib_main_t * vm = nm->vlib_main;
  netcp_session_t *s = 0;
  uword * p;
  ip4_header_t * ip0;
  netcp_header_t * nh0 = vlib_buffer_get_current (b0);
  netcp_data_header_t *d0;
  netcp_ack_header_t *ack0;
  u32 session_id = clib_net_to_host_u32 (nh0->session_id);
  u32 tmp;
  u64 new_offset;

  p = hash_get (nm->session_by_id, session_id);
  if (p == 0) 
    {
      b0->error = node->errors[NETCP_ERROR_NO_SESSION];
      return NETCP_NEXT_DROP;
    }

  s = pool_elt_at_index (nm->sessions, p[0]);

  if (!s->is_sender)
    {
      b0->error = node->errors[NETCP_ERROR_BOTCH];
      return NETCP_NEXT_DROP;
    }

  ip0 = vlib_buffer_get_current (b0);
  ip0--;

  ack0 = (netcp_ack_header_t *)(nh0+1);
  new_offset = clib_host_to_net_u64(ack0->offset);
  
  s->their_current_offset = new_offset;
  s->retry_count = 0;
  s->retry_timer = vlib_time_now(vm) + 2.0;
  
  /* 
   * Count and drop successful opens, otherwise 
   * window_size > 1 wont work
   */
  if (PREDICT_FALSE(ack0->offset == (u64) ~0))
    {
      s->my_current_offset = 0;
      s->state = NETCP_STATE_DATA;
      b0->error = node->errors[NETCP_ERROR_FILES_CREATED];
      return NETCP_NEXT_DROP;
    }
    
  /* Send next data segment, or quit if we're done. */

  if (s->their_current_offset >= s->size_in_bytes)
    {
      unmap_file (s->dst_file, s->map_addr, s->size_in_bytes, 0 /* truncate*/);
      hash_unset (nm->session_by_id, s->session_id);
      vec_free (s->src_file);
      vec_free (s->dst_file);
      vec_free (s->rewrite);
      pool_put (nm->sessions, s);
      b0->error = node->errors[NETCP_ERROR_COMPLETE];
      return NETCP_NEXT_DROP;
    }

  if (s->my_current_offset < s->size_in_bytes)
    {

      d0 = (netcp_data_header_t *)(nh0+1);
      b0->current_length = sizeof (*ip0) + sizeof (*nh0) + sizeof (*d0) +
        nm->segment_size;
      
      tmp = ip0->src_address.as_u32;
      ip0->ip_version_and_header_length = 0x45;
      ip0->ttl = 254;
      ip0->src_address.as_u32 = ip0->dst_address.as_u32;
      ip0->dst_address.as_u32 = tmp;
      ip0->length = clib_host_to_net_u16(b0->current_length);
      ip0->checksum = ip4_header_checksum (ip0);
      
      nh0->type = NETCP_TYPE_DATA;
      
      d0->offset = clib_host_to_net_u64 (s->my_current_offset);
      memcpy (d0->data, s->map_addr + s->my_current_offset, nm->segment_size);
      s->my_current_offset += nm->segment_size;
      
      return NETCP_NEXT_IP4_LOOKUP;
    }
  else
    {
      b0->error = node->errors[NETCP_ERROR_FINAL_WINDOW_DRAIN];
      return NETCP_NEXT_DROP;
    }
  
}

static u32 data_handler (netcp_main_t * nm, vlib_node_runtime_t * node, 
                         vlib_buffer_t * b0)
{
  netcp_session_t *s = 0;
  uword * p;
  i32 retval = 0;
  ip4_header_t * ip0;
  netcp_header_t * nh0 = vlib_buffer_get_current (b0);
  netcp_data_header_t *d0;
  netcp_ack_header_t *ack0;
  u32 session_id = clib_net_to_host_u32 (nh0->session_id);
  u32 tmp;
  u8 * target;
  u64 new_offset;

  p = hash_get (nm->session_by_id, session_id);
  if (p == 0) 
    {
      b0->error = node->errors[NETCP_ERROR_NO_SESSION];
      return NETCP_NEXT_DROP;
    }

  s = pool_elt_at_index (nm->sessions, p[0]);

  if (s->is_sender)
    {
      b0->error = node->errors[NETCP_ERROR_BOTCH];
      return NETCP_NEXT_DROP;
    }

  ip0 = vlib_buffer_get_current (b0);
  ip0--;

  d0 = (netcp_data_header_t *)(nh0+1);

  new_offset = clib_host_to_net_u64(d0->offset);

  if (s->my_current_offset + s->segment_size != new_offset)
    {
      b0->error = node->errors[NETCP_ERROR_LOST_DATA];
      return NETCP_NEXT_DROP;
    }

  s->my_current_offset = new_offset;

  if (s->my_current_offset + s->segment_size >= s->size_in_bytes)
    {
      b0->error = node->errors[NETCP_ERROR_BAD_OFFSET];
      return NETCP_NEXT_DROP;
    }

  target = s->map_addr + clib_host_to_net_u64(d0->offset);
  memcpy (target, d0->data, s->segment_size);

  /* turn pkt into ack */
  ack0 = (netcp_ack_header_t *)(nh0+1);
  b0->current_length = sizeof (*ip0) + sizeof (*nh0) + sizeof (*ack0);

  tmp = ip0->src_address.as_u32;
  ip0->ip_version_and_header_length = 0x45;
  ip0->ttl = 254;
  ip0->src_address.as_u32 = ip0->dst_address.as_u32;
  ip0->dst_address.as_u32 = tmp;
  ip0->length = clib_host_to_net_u16(b0->current_length);
  ip0->checksum = ip4_header_checksum (ip0);

  nh0->type = NETCP_TYPE_ACK;
  ack0->retval = clib_host_to_net_u32 (retval);
  ack0->offset = d0->offset;
  
  /* 
   * If we're done, close the file... 
   * Send final ACK. One chance. If the final ACK is lost, the sender 
   * will retry, and eventually give up...
   */
  if (s->my_current_offset >= s->size_in_bytes)
    {
      unmap_file (s->dst_file, s->map_addr, s->size_in_bytes, 1 /* truncate*/);
      hash_unset (nm->session_by_id, s->session_id);
      vec_free (s->src_file);
      vec_free (s->dst_file);
      vec_free (s->rewrite);
      pool_put (nm->sessions, s);
    }
  return NETCP_NEXT_IP4_LOOKUP;
}

static u8 * validate_filename (u8 * n)
{
  int i;
  for (i = 0; i < NETCP_PATH_MAX; i++)
    if (n[i] == '\0')
      {
        return format (0, "%s%c", n, 0);
      }
  return 0;
}

static u32 send_file_handler (netcp_main_t * nm, 
                              vlib_node_runtime_t * node,
                              vlib_buffer_t * b0)
{
  netcp_session_t *s = 0;
  uword * p;
  i32 retval = 0;
  u8 * dst_file;
  ip4_header_t * ip0;
  netcp_header_t * nh0 = vlib_buffer_get_current (b0);
  netcp_send_file_header_t *sf0;
  netcp_ack_header_t *ack0;
  u32 session_id = clib_net_to_host_u32 (nh0->session_id);
  u32 tmp;
  ip4_and_netcp_header_t *ipn;
  ip4_header_t * ip;
  netcp_header_t * nh;

  /* The session might exist, lost-ack case */
  p = hash_get (nm->session_by_id, session_id);
  if (p) 
    s = pool_elt_at_index (nm->sessions, p[0]);

  ip0 = vlib_buffer_get_current (b0);
  ip0--;

  sf0 = (netcp_send_file_header_t *)(nh0+1);

  dst_file = validate_filename (sf0->dst_file);

  if (dst_file == 0)
    {
      retval = -3;
      goto send_ack;
    }

  if (s == 0)
    {
      pool_get (nm->sessions, s);
      memset (s, 0, sizeof (*s));
    }

  s->to.ip4.as_u32 = ip0->dst_address.as_u32;
  s->from.ip4.as_u32 = ip0->src_address.as_u32;
  s->src_file = 0;
  s->dst_file = dst_file;
  s->session_id = clib_net_to_host_u32 (nh0->session_id);
  s->is_ip4 = 1;
  s->segment_size = nm->segment_size;
  s->window_size = 1;
  s->size_in_bytes = clib_net_to_host_u64(sf0->size_in_bytes);
  s->state = NETCP_STATE_DATA;
  /* retry case */
  if (s->map_addr == 0)
    s->map_addr = map_file (dst_file, &s->size_in_bytes, 1 /* is_write */);
  if (s->map_addr == 0)
    {
      pool_put (nm->sessions, s);
      retval = -4;
      goto send_ack;
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
  ip->src_address.as_u32 = s->to.ip4.as_u32;
  ip->dst_address.as_u32 = s->from.ip4.as_u32;
  ip->checksum = ip4_header_checksum (ip);
  nh->netcp_version = NETCP_VERSION;
  nh->type = 0;
  nh->session_id = clib_host_to_net_u32(s->session_id);

  hash_set (nm->session_by_id, s->session_id, s - nm->sessions);


  /* turn pkt into ack */
 send_ack:
  ack0 = (netcp_ack_header_t *)(nh0+1);
  b0->current_length = sizeof (*ip0) + sizeof (*nh0) + sizeof (*ack0);

  tmp = ip0->src_address.as_u32;
  ip0->ip_version_and_header_length = 0x45;
  ip0->ttl = 254;
  ip0->src_address.as_u32 = ip0->dst_address.as_u32;
  ip0->dst_address.as_u32 = tmp;
  ip0->length = clib_host_to_net_u16(b0->current_length);
  ip0->checksum = ip4_header_checksum (ip0);

  nh0->type = NETCP_TYPE_ACK;
  ack0->retval = clib_host_to_net_u32 (retval);
  ack0->offset = (u64) ~0;
  
  return NETCP_NEXT_IP4_LOOKUP;
}

static uword
netcp_node_fn (vlib_main_t * vm,
               vlib_node_runtime_t * node,
               vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  netcp_next_t next_index;
  netcp_main_t * nm = &netcp_main;
  u32 (*fp)(netcp_main_t *, vlib_node_runtime_t *, vlib_buffer_t *);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      /* Single-loop only */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
          u32 bi0;
	  vlib_buffer_t * b0;
          u32 next0 = NETCP_NEXT_DROP;
          netcp_header_t * nh0;

          /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
          
          nh0 = vlib_buffer_get_current (b0);

          if (PREDICT_FALSE(nh0->netcp_version != NETCP_VERSION))
            {
              b0->error = node->errors[NETCP_ERROR_BAD_VERSION];
              goto trace0;
            }
          if (PREDICT_FALSE(nh0->type >= NETCP_N_TYPES))
            {
              b0->error = node->errors[NETCP_ERROR_BAD_TYPE];
              goto trace0;
            }
          
          fp = nm->rx_handlers[nh0->type];
          next0 = (*fp)(nm, node, b0);

        trace0:
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
            netcp_trace_t *t = 
              vlib_add_trace (vm, node, b0, sizeof (*t));
            t->next_index = next0;
          }
          /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (netcp_node) = {
  .function = netcp_node_fn,
  .name = "netcp",
  .vector_size = sizeof (u32),
  .format_trace = format_netcp_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(netcp_error_strings),
  .error_strings = netcp_error_strings,

  .n_next_nodes = NETCP_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = 
  {
    [NETCP_NEXT_IP4_LOOKUP] = "ip4-lookup", 
    [NETCP_NEXT_DROP] = "error-drop",
  },
};

static clib_error_t *init_rx_handlers (vlib_main_t * vm)
{
  netcp_main_t * nm = &netcp_main;
  clib_error_t * error;

  if ((error = vlib_call_init_function (vm, netcp_init)))
    return error;

  vec_validate (nm->rx_handlers, NETCP_N_TYPES - 1);

#define _(a,b)                                  \
  do {                                          \
    void * fp = b##_handler;                    \
    nm->rx_handlers[NETCP_TYPE_##a] = fp;       \
  } while (0);
  foreach_netcp_type;
#undef _
  return 0;
}

VLIB_INIT_FUNCTION (init_rx_handlers);
