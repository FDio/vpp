/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include "nat_ha.h"
#include <vnet/udp/udp_local.h>
#include <nat/nat.h>
#include <vppinfra/atomics.h>

/* number of retries */
#define NAT_HA_RETRIES 3

#define foreach_nat_ha_counter           \
_(RECV_ADD, "add-event-recv", 0)         \
_(RECV_DEL, "del-event-recv", 1)         \
_(RECV_REFRESH, "refresh-event-recv", 2) \
_(SEND_ADD, "add-event-send", 3)         \
_(SEND_DEL, "del-event-send", 4)         \
_(SEND_REFRESH, "refresh-event-send", 5) \
_(RECV_ACK, "ack-recv", 6)               \
_(SEND_ACK, "ack-send", 7)               \
_(RETRY_COUNT, "retry-count", 8)         \
_(MISSED_COUNT, "missed-count", 9)

/* NAT HA protocol version */
#define NAT_HA_VERSION 0x01

/* NAT HA protocol flags */
#define NAT_HA_FLAG_ACK 0x01

/* NAT HA event types */
typedef enum
{
  NAT_HA_ADD = 1,
  NAT_HA_DEL,
  NAT_HA_REFRESH,
} nat_ha_event_type_t;

/* NAT HA protocol header */
typedef struct
{
  /* version */
  u8 version;
  /* flags */
  u8 flags;
  /* event count */
  u16 count;
  /* sequence number */
  u32 sequence_number;
  /* thread index where events originated */
  u32 thread_index;
} __attribute__ ((packed)) nat_ha_message_header_t;

/* NAT HA protocol event data */
typedef struct
{
  /* event type */
  u8 event_type;
  /* session data */
  u8 protocol;
  u16 flags;
  u32 in_addr;
  u32 out_addr;
  u16 in_port;
  u16 out_port;
  u32 eh_addr;
  u32 ehn_addr;
  u16 eh_port;
  u16 ehn_port;
  u32 fib_index;
  u32 total_pkts;
  u64 total_bytes;
} __attribute__ ((packed)) nat_ha_event_t;

typedef enum
{
#define _(N, s, v) NAT_HA_COUNTER_##N = v,
  foreach_nat_ha_counter
#undef _
  NAT_HA_N_COUNTERS
} nat_ha_counter_t;

/* data waiting for ACK */
typedef struct
{
  /* sequence number */
  u32 seq;
  /* retry count */
  u32 retry_count;
  /* next retry time */
  f64 retry_timer;
  /* 1 if HA resync */
  u8 is_resync;
  /* packet data */
  u8 *data;
} nat_ha_resend_entry_t;

/* per thread data */
typedef struct
{
  /* buffer under construction */
  vlib_buffer_t *state_sync_buffer;
  /* frame containing NAT HA buffers */
  vlib_frame_t *state_sync_frame;
  /* number of events */
  u16 state_sync_count;
  /* next event offset */
  u32 state_sync_next_event_offset;
  /* data waiting for ACK */
  nat_ha_resend_entry_t *resend_queue;
} nat_ha_per_thread_data_t;

/* NAT HA settings */
typedef struct nat_ha_main_s
{
  u8 enabled;
  /* local IP address and UDP port */
  ip4_address_t src_ip_address;
  u16 src_port;
  /* failvoer IP address and UDP port */
  ip4_address_t dst_ip_address;
  u16 dst_port;
  /* path MTU between local and failover */
  u32 state_sync_path_mtu;
  /* number of seconds after which to send session counters refresh */
  u32 session_refresh_interval;
  /* counters */
  vlib_simple_counter_main_t counters[NAT_HA_N_COUNTERS];
  vlib_main_t *vlib_main;
  /* sequence number counter */
  u32 sequence_number;
  /* 1 if resync in progress */
  u8 in_resync;
  /* number of remaing ACK for resync */
  u32 resync_ack_count;
  /* number of missed ACK for resync */
  u32 resync_ack_missed;
  /* resync data */
  nat_ha_resync_event_cb_t event_callback;
  u32 client_index;
  u32 pid;
  /* call back functions for received HA events on failover */
  nat_ha_sadd_cb_t sadd_cb;
  nat_ha_sdel_cb_t sdel_cb;
  nat_ha_sref_cb_t sref_cb;
  /* per thread data */
  u32 num_workers;
  nat_ha_per_thread_data_t *per_thread_data;
  /* worker handoff frame-queue index */
  u32 fq_index;
} nat_ha_main_t;

nat_ha_main_t nat_ha_main;
vlib_node_registration_t nat_ha_process_node;
vlib_node_registration_t nat_ha_worker_node;
vlib_node_registration_t nat_ha_node;
vlib_node_registration_t nat_ha_handoff_node;

static void
nat_ha_resync_fin (void)
{
  nat_ha_main_t *ha = &nat_ha_main;

  /* if no more resync ACK remainig we are done */
  if (ha->resync_ack_count)
    return;

  ha->in_resync = 0;
  if (ha->resync_ack_missed)
    {
      nat_elog_info ("resync completed with result FAILED");
    }
  else
    {
      nat_elog_info ("resync completed with result SUCCESS");
    }
  if (ha->event_callback)
    ha->event_callback (ha->client_index, ha->pid, ha->resync_ack_missed);
}

/* cache HA NAT data waiting for ACK */
static int
nat_ha_resend_queue_add (u32 seq, u8 * data, u8 data_len, u8 is_resync,
			 u32 thread_index)
{
  nat_ha_main_t *ha = &nat_ha_main;
  nat_ha_per_thread_data_t *td = &ha->per_thread_data[thread_index];
  nat_ha_resend_entry_t *entry;
  f64 now = vlib_time_now (ha->vlib_main);

  vec_add2 (td->resend_queue, entry, 1);
  clib_memset (entry, 0, sizeof (*entry));
  entry->retry_timer = now + 2.0;
  entry->seq = seq;
  entry->is_resync = is_resync;
  vec_add (entry->data, data, data_len);

  return 0;
}

static_always_inline void
nat_ha_ack_recv (u32 seq, u32 thread_index)
{
  nat_ha_main_t *ha = &nat_ha_main;
  nat_ha_per_thread_data_t *td = &ha->per_thread_data[thread_index];
  u32 i;

  vec_foreach_index (i, td->resend_queue)
  {
    if (td->resend_queue[i].seq != seq)
      continue;

    vlib_increment_simple_counter (&ha->counters[NAT_HA_COUNTER_RECV_ACK],
				   thread_index, 0, 1);
    /* ACK received remove cached data */
    if (td->resend_queue[i].is_resync)
      {
	clib_atomic_fetch_sub (&ha->resync_ack_count, 1);
	nat_ha_resync_fin ();
      }
    vec_free (td->resend_queue[i].data);
    vec_del1 (td->resend_queue, i);
    nat_elog_debug_X1 ("ACK for seq %d received", "i4",
		       clib_net_to_host_u32 (seq));

    return;
  }
}

/* scan non-ACKed HA NAT for retry */
static void
nat_ha_resend_scan (f64 now, u32 thread_index)
{
  nat_ha_main_t *ha = &nat_ha_main;
  nat_ha_per_thread_data_t *td = &ha->per_thread_data[thread_index];
  u32 i, *del, *to_delete = 0;
  vlib_main_t *vm = ha->vlib_main;
  vlib_buffer_t *b = 0;
  vlib_frame_t *f;
  u32 bi, *to_next;
  ip4_header_t *ip;

  vec_foreach_index (i, td->resend_queue)
  {
    if (td->resend_queue[i].retry_timer > now)
      continue;

    /* maximum retry reached delete cached data */
    if (td->resend_queue[i].retry_count >= NAT_HA_RETRIES)
      {
	nat_elog_notice_X1 ("seq %d missed", "i4",
			    clib_net_to_host_u32 (td->resend_queue[i].seq));
	if (td->resend_queue[i].is_resync)
	  {
	    clib_atomic_fetch_add (&ha->resync_ack_missed, 1);
	    clib_atomic_fetch_sub (&ha->resync_ack_count, 1);
	    nat_ha_resync_fin ();
	  }
	vec_add1 (to_delete, i);
	vlib_increment_simple_counter (&ha->counters
				       [NAT_HA_COUNTER_MISSED_COUNT],
				       thread_index, 0, 1);
	continue;
      }

    /* retry to send non-ACKed data */
    nat_elog_debug_X1 ("state sync seq %d resend", "i4",
		       clib_net_to_host_u32 (td->resend_queue[i].seq));
    td->resend_queue[i].retry_count++;
    vlib_increment_simple_counter (&ha->counters[NAT_HA_COUNTER_RETRY_COUNT],
				   thread_index, 0, 1);
    if (vlib_buffer_alloc (vm, &bi, 1) != 1)
      {
	nat_elog_warn ("HA NAT state sync can't allocate buffer");
	return;
      }
    b = vlib_get_buffer (vm, bi);
    b->current_length = vec_len (td->resend_queue[i].data);
    b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
    b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
    vnet_buffer (b)->sw_if_index[VLIB_RX] = 0;
    vnet_buffer (b)->sw_if_index[VLIB_TX] = 0;
    ip = vlib_buffer_get_current (b);
    clib_memcpy (ip, td->resend_queue[i].data,
		 vec_len (td->resend_queue[i].data));
    f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
    to_next = vlib_frame_vector_args (f);
    to_next[0] = bi;
    f->n_vectors = 1;
    vlib_put_frame_to_node (vm, ip4_lookup_node.index, f);
    td->resend_queue[i].retry_timer = now + 2.0;
  }

  vec_foreach (del, to_delete)
  {
    vec_free (td->resend_queue[*del].data);
    vec_del1 (td->resend_queue, *del);
  }
  vec_free (to_delete);
}

void
nat_ha_enable (nat_ha_sadd_cb_t sadd_cb,
	       nat_ha_sdel_cb_t sdel_cb, nat_ha_sref_cb_t sref_cb)
{
  nat_ha_main_t *ha = &nat_ha_main;

  ha->sadd_cb = sadd_cb;
  ha->sdel_cb = sdel_cb;
  ha->sref_cb = sref_cb;

  ha->enabled = 1;
}

void
nat_ha_disable ()
{
  nat_ha_main_t *ha = &nat_ha_main;
  ha->dst_port = 0;
  ha->enabled = 0;
}

void
nat_ha_init (vlib_main_t * vm, u32 num_workers, u32 num_threads)
{
  nat_ha_main_t *ha = &nat_ha_main;
  clib_memset (ha, 0, sizeof (*ha));

  ha->vlib_main = vm;
  ha->fq_index = ~0;

  ha->num_workers = num_workers;
  vec_validate (ha->per_thread_data, num_threads);

#define _(N, s, v) ha->counters[v].name = s;          \
  ha->counters[v].stat_segment_name = "/nat44/ha/" s; \
  vlib_validate_simple_counter(&ha->counters[v], 0);  \
  vlib_zero_simple_counter(&ha->counters[v], 0);
  foreach_nat_ha_counter
#undef _
}

int
nat_ha_set_listener (ip4_address_t * addr, u16 port, u32 path_mtu)
{
  nat_ha_main_t *ha = &nat_ha_main;

  /* unregister previously set UDP port */
  if (ha->src_port)
    udp_unregister_dst_port (ha->vlib_main, ha->src_port, 1);

  ha->src_ip_address.as_u32 = addr->as_u32;
  ha->src_port = port;
  ha->state_sync_path_mtu = path_mtu;

  if (port)
    {
      /* if multiple worker threads first go to handoff node */
      if (ha->num_workers > 1)
	{
	  if (ha->fq_index == ~0)
	    ha->fq_index = vlib_frame_queue_main_init (nat_ha_node.index, 0);
	  udp_register_dst_port (ha->vlib_main, port,
				 nat_ha_handoff_node.index, 1);
	}
      else
	{
	  udp_register_dst_port (ha->vlib_main, port, nat_ha_node.index, 1);
	}
      nat_elog_info_X1 ("HA listening on port %d for state sync", "i4", port);
    }

  return 0;
}

void
nat_ha_get_listener (ip4_address_t * addr, u16 * port, u32 * path_mtu)
{
  nat_ha_main_t *ha = &nat_ha_main;

  addr->as_u32 = ha->src_ip_address.as_u32;
  *port = ha->src_port;
  *path_mtu = ha->state_sync_path_mtu;
}

int
nat_ha_set_failover (ip4_address_t * addr, u16 port,
		     u32 session_refresh_interval)
{
  nat_ha_main_t *ha = &nat_ha_main;

  ha->dst_ip_address.as_u32 = addr->as_u32;
  ha->dst_port = port;
  ha->session_refresh_interval = session_refresh_interval;

  vlib_process_signal_event (ha->vlib_main, nat_ha_process_node.index, 1, 0);

  return 0;
}

void
nat_ha_get_failover (ip4_address_t * addr, u16 * port,
		     u32 * session_refresh_interval)
{
  nat_ha_main_t *ha = &nat_ha_main;

  addr->as_u32 = ha->dst_ip_address.as_u32;
  *port = ha->dst_port;
  *session_refresh_interval = ha->session_refresh_interval;
}

static_always_inline void
nat_ha_recv_add (nat_ha_event_t * event, f64 now, u32 thread_index)
{
  nat_ha_main_t *ha = &nat_ha_main;
  ip4_address_t in_addr, out_addr, eh_addr, ehn_addr;
  u32 fib_index;
  u16 flags;

  vlib_increment_simple_counter (&ha->counters[NAT_HA_COUNTER_RECV_ADD],
				 thread_index, 0, 1);

  in_addr.as_u32 = event->in_addr;
  out_addr.as_u32 = event->out_addr;
  eh_addr.as_u32 = event->eh_addr;
  ehn_addr.as_u32 = event->ehn_addr;
  fib_index = clib_net_to_host_u32 (event->fib_index);
  flags = clib_net_to_host_u16 (event->flags);

  ha->sadd_cb (&in_addr, event->in_port, &out_addr, event->out_port, &eh_addr,
	       event->eh_port, &ehn_addr, event->ehn_port, event->protocol,
	       fib_index, flags, thread_index);
}

static_always_inline void
nat_ha_recv_del (nat_ha_event_t * event, u32 thread_index)
{
  nat_ha_main_t *ha = &nat_ha_main;
  ip4_address_t out_addr, eh_addr;
  u32 fib_index;

  vlib_increment_simple_counter (&ha->counters[NAT_HA_COUNTER_RECV_DEL],
				 thread_index, 0, 1);

  out_addr.as_u32 = event->out_addr;
  eh_addr.as_u32 = event->eh_addr;
  fib_index = clib_net_to_host_u32 (event->fib_index);

  ha->sdel_cb (&out_addr, event->out_port, &eh_addr, event->eh_port,
	       event->protocol, fib_index, thread_index);
}

static_always_inline void
nat_ha_recv_refresh (nat_ha_event_t * event, f64 now, u32 thread_index)
{
  nat_ha_main_t *ha = &nat_ha_main;
  ip4_address_t out_addr, eh_addr;
  u32 fib_index, total_pkts;
  u64 total_bytes;

  vlib_increment_simple_counter (&ha->counters[NAT_HA_COUNTER_RECV_REFRESH],
				 thread_index, 0, 1);

  out_addr.as_u32 = event->out_addr;
  eh_addr.as_u32 = event->eh_addr;
  fib_index = clib_net_to_host_u32 (event->fib_index);
  total_pkts = clib_net_to_host_u32 (event->total_pkts);
  total_bytes = clib_net_to_host_u64 (event->total_bytes);

  ha->sref_cb (&out_addr, event->out_port, &eh_addr, event->eh_port,
	       event->protocol, fib_index, total_pkts, total_bytes,
	       thread_index);
}

/* process received NAT HA event */
static_always_inline void
nat_ha_event_process (nat_ha_event_t * event, f64 now, u32 thread_index)
{
  switch (event->event_type)
    {
    case NAT_HA_ADD:
      nat_ha_recv_add (event, now, thread_index);
      break;
    case NAT_HA_DEL:
      nat_ha_recv_del (event, thread_index);
      break;
    case NAT_HA_REFRESH:
      nat_ha_recv_refresh (event, now, thread_index);
      break;
    default:
      nat_elog_notice_X1 ("Unsupported HA event type %d", "i4",
			  event->event_type);
      break;
    }
}

static inline void
nat_ha_header_create (vlib_buffer_t * b, u32 * offset, u32 thread_index)
{
  nat_ha_main_t *ha = &nat_ha_main;
  nat_ha_message_header_t *h;
  ip4_header_t *ip;
  udp_header_t *udp;
  u32 sequence_number;

  b->current_data = 0;
  b->current_length = sizeof (*ip) + sizeof (*udp) + sizeof (*h);
  b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  vnet_buffer (b)->sw_if_index[VLIB_RX] = 0;
  vnet_buffer (b)->sw_if_index[VLIB_TX] = 0;
  ip = vlib_buffer_get_current (b);
  udp = (udp_header_t *) (ip + 1);
  h = (nat_ha_message_header_t *) (udp + 1);

  /* IP header */
  ip->ip_version_and_header_length = 0x45;
  ip->ttl = 254;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->flags_and_fragment_offset =
    clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT);
  ip->src_address.as_u32 = ha->src_ip_address.as_u32;
  ip->dst_address.as_u32 = ha->dst_ip_address.as_u32;
  /* UDP header */
  udp->src_port = clib_host_to_net_u16 (ha->src_port);
  udp->dst_port = clib_host_to_net_u16 (ha->dst_port);
  udp->checksum = 0;

  /* NAT HA protocol header */
  h->version = NAT_HA_VERSION;
  h->flags = 0;
  h->count = 0;
  h->thread_index = clib_host_to_net_u32 (thread_index);
  sequence_number = clib_atomic_fetch_add (&ha->sequence_number, 1);
  h->sequence_number = clib_host_to_net_u32 (sequence_number);

  *offset =
    sizeof (ip4_header_t) + sizeof (udp_header_t) +
    sizeof (nat_ha_message_header_t);
}

static inline void
nat_ha_send (vlib_frame_t * f, vlib_buffer_t * b, u8 is_resync,
	     u32 thread_index)
{
  nat_ha_main_t *ha = &nat_ha_main;
  nat_ha_per_thread_data_t *td = &ha->per_thread_data[thread_index];
  nat_ha_message_header_t *h;
  ip4_header_t *ip;
  udp_header_t *udp;
  vlib_main_t *vm = vlib_mains[thread_index];

  ip = vlib_buffer_get_current (b);
  udp = ip4_next_header (ip);
  h = (nat_ha_message_header_t *) (udp + 1);

  h->count = clib_host_to_net_u16 (td->state_sync_count);

  ip->length = clib_host_to_net_u16 (b->current_length);
  ip->checksum = ip4_header_checksum (ip);
  udp->length = clib_host_to_net_u16 (b->current_length - sizeof (*ip));

  nat_ha_resend_queue_add (h->sequence_number, (u8 *) ip, b->current_length,
			   is_resync, thread_index);

  vlib_put_frame_to_node (vm, ip4_lookup_node.index, f);
}

/* add NAT HA protocol event */
static_always_inline void
nat_ha_event_add (nat_ha_event_t * event, u8 do_flush, u32 thread_index,
		  u8 is_resync)
{
  nat_ha_main_t *ha = &nat_ha_main;
  nat_ha_per_thread_data_t *td = &ha->per_thread_data[thread_index];
  vlib_main_t *vm = vlib_mains[thread_index];
  vlib_buffer_t *b = 0;
  vlib_frame_t *f;
  u32 bi = ~0, offset;

  b = td->state_sync_buffer;

  if (PREDICT_FALSE (b == 0))
    {
      if (do_flush)
	return;

      if (vlib_buffer_alloc (vm, &bi, 1) != 1)
	{
	  nat_elog_warn ("HA NAT state sync can't allocate buffer");
	  return;
	}

      b = td->state_sync_buffer = vlib_get_buffer (vm, bi);
      clib_memset (vnet_buffer (b), 0, sizeof (*vnet_buffer (b)));
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b);
      offset = 0;
    }
  else
    {
      bi = vlib_get_buffer_index (vm, b);
      offset = td->state_sync_next_event_offset;
    }

  f = td->state_sync_frame;
  if (PREDICT_FALSE (f == 0))
    {
      u32 *to_next;
      f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
      td->state_sync_frame = f;
      to_next = vlib_frame_vector_args (f);
      to_next[0] = bi;
      f->n_vectors = 1;
    }

  if (PREDICT_FALSE (td->state_sync_count == 0))
    nat_ha_header_create (b, &offset, thread_index);

  if (PREDICT_TRUE (do_flush == 0))
    {
      clib_memcpy_fast (b->data + offset, event, sizeof (*event));
      offset += sizeof (*event);
      td->state_sync_count++;
      b->current_length += sizeof (*event);

      switch (event->event_type)
	{
	case NAT_HA_ADD:
	  vlib_increment_simple_counter (&ha->counters
					 [NAT_HA_COUNTER_SEND_ADD],
					 thread_index, 0, 1);
	  break;
	case NAT_HA_DEL:
	  vlib_increment_simple_counter (&ha->counters
					 [NAT_HA_COUNTER_SEND_DEL],
					 thread_index, 0, 1);
	  break;
	case NAT_HA_REFRESH:
	  vlib_increment_simple_counter (&ha->counters
					 [NAT_HA_COUNTER_SEND_REFRESH],
					 thread_index, 0, 1);
	  break;
	default:
	  break;
	}
    }

  if (PREDICT_FALSE
      (do_flush || offset + (sizeof (*event)) > ha->state_sync_path_mtu))
    {
      nat_ha_send (f, b, is_resync, thread_index);
      td->state_sync_buffer = 0;
      td->state_sync_frame = 0;
      td->state_sync_count = 0;
      offset = 0;
      if (is_resync)
	{
	  clib_atomic_fetch_add (&ha->resync_ack_count, 1);
	  nat_ha_resync_fin ();
	}
    }

  td->state_sync_next_event_offset = offset;
}

#define skip_if_disabled()          \
do {                                \
  nat_ha_main_t *ha = &nat_ha_main; \
  if (PREDICT_TRUE (!ha->dst_port)) \
    return;                         \
} while (0)

void
nat_ha_flush (u8 is_resync)
{
  skip_if_disabled ();
  nat_ha_event_add (0, 1, 0, is_resync);
}

void
nat_ha_sadd (ip4_address_t * in_addr, u16 in_port, ip4_address_t * out_addr,
	     u16 out_port, ip4_address_t * eh_addr, u16 eh_port,
	     ip4_address_t * ehn_addr, u16 ehn_port, u8 proto, u32 fib_index,
	     u16 flags, u32 thread_index, u8 is_resync)
{
  nat_ha_event_t event;

  skip_if_disabled ();

  clib_memset (&event, 0, sizeof (event));
  event.event_type = NAT_HA_ADD;
  event.flags = clib_host_to_net_u16 (flags);
  event.in_addr = in_addr->as_u32;
  event.in_port = in_port;
  event.out_addr = out_addr->as_u32;
  event.out_port = out_port;
  event.eh_addr = eh_addr->as_u32;
  event.eh_port = eh_port;
  event.ehn_addr = ehn_addr->as_u32;
  event.ehn_port = ehn_port;
  event.fib_index = clib_host_to_net_u32 (fib_index);
  event.protocol = proto;
  nat_ha_event_add (&event, 0, thread_index, is_resync);
}

void
nat_ha_sdel (ip4_address_t * out_addr, u16 out_port, ip4_address_t * eh_addr,
	     u16 eh_port, u8 proto, u32 fib_index, u32 thread_index)
{
  nat_ha_event_t event;

  skip_if_disabled ();

  clib_memset (&event, 0, sizeof (event));
  event.event_type = NAT_HA_DEL;
  event.out_addr = out_addr->as_u32;
  event.out_port = out_port;
  event.eh_addr = eh_addr->as_u32;
  event.eh_port = eh_port;
  event.fib_index = clib_host_to_net_u32 (fib_index);
  event.protocol = proto;
  nat_ha_event_add (&event, 0, thread_index, 0);
}

void
nat_ha_sref (ip4_address_t * out_addr, u16 out_port, ip4_address_t * eh_addr,
	     u16 eh_port, u8 proto, u32 fib_index, u32 total_pkts,
	     u64 total_bytes, u32 thread_index, f64 * last_refreshed, f64 now)
{
  nat_ha_main_t *ha = &nat_ha_main;
  nat_ha_event_t event;

  skip_if_disabled ();

  if ((*last_refreshed + ha->session_refresh_interval) > now)
    return;

  *last_refreshed = now;
  clib_memset (&event, 0, sizeof (event));
  event.event_type = NAT_HA_REFRESH;
  event.out_addr = out_addr->as_u32;
  event.out_port = out_port;
  event.eh_addr = eh_addr->as_u32;
  event.eh_port = eh_port;
  event.fib_index = clib_host_to_net_u32 (fib_index);
  event.protocol = proto;
  event.total_pkts = clib_host_to_net_u32 (total_pkts);
  event.total_bytes = clib_host_to_net_u64 (total_bytes);
  nat_ha_event_add (&event, 0, thread_index, 0);
}

static_always_inline u8
plugin_enabled ()
{
  nat_ha_main_t *ha = &nat_ha_main;
  return ha->enabled;
}

/* per thread process waiting for interrupt */
static uword
nat_ha_worker_fn (vlib_main_t * vm, vlib_node_runtime_t * rt,
		  vlib_frame_t * f)
{
  u32 thread_index = vm->thread_index;

  if (plugin_enabled () == 0)
    return 0;

  /* flush HA NAT data under construction */
  nat_ha_event_add (0, 1, thread_index, 0);
  /* scan if we need to resend some non-ACKed data */
  nat_ha_resend_scan (vlib_time_now (vm), thread_index);
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat_ha_worker_node) = {
    .function = nat_ha_worker_fn,
    .type = VLIB_NODE_TYPE_INPUT,
    .state = VLIB_NODE_STATE_INTERRUPT,
    .name = "nat-ha-worker",
};
/* *INDENT-ON* */

/* periodically send interrupt to each thread */
static uword
nat_ha_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  nat_ha_main_t *ha = &nat_ha_main;
  uword event_type;
  uword *event_data = 0;
  u32 ti;

  vlib_process_wait_for_event (vm);
  event_type = vlib_process_get_events (vm, &event_data);
  if (event_type)
    nat_elog_info ("nat-ha-process: bogus kickoff event received");
  vec_reset_length (event_data);

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, 1.0);
      event_type = vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);
      for (ti = 0; ti < vec_len (vlib_mains); ti++)
	{
	  if (ti >= vec_len (ha->per_thread_data))
	    continue;

	  vlib_node_set_interrupt_pending (vlib_mains[ti],
					   nat_ha_worker_node.index);
	}
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat_ha_process_node) = {
    .function = nat_ha_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "nat-ha-process",
};
/* *INDENT-ON* */

void
nat_ha_get_resync_status (u8 * in_resync, u32 * resync_ack_missed)
{
  nat_ha_main_t *ha = &nat_ha_main;

  *in_resync = ha->in_resync;
  *resync_ack_missed = ha->resync_ack_missed;
}

typedef struct
{
  ip4_address_t addr;
  u32 event_count;
} nat_ha_trace_t;

static u8 *
format_nat_ha_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nat_ha_trace_t *t = va_arg (*args, nat_ha_trace_t *);

  s =
    format (s, "nat-ha: %u events from %U", t->event_count,
	    format_ip4_address, &t->addr);

  return s;
}

typedef enum
{
  NAT_HA_NEXT_IP4_LOOKUP,
  NAT_HA_NEXT_DROP,
  NAT_HA_N_NEXT,
} nat_ha_next_t;

#define foreach_nat_ha_error   \
_(PROCESSED, "pkts-processed") \
_(BAD_VERSION, "bad-version")

typedef enum
{
#define _(sym, str) NAT_HA_ERROR_##sym,
  foreach_nat_ha_error
#undef _
    NAT_HA_N_ERROR,
} nat_ha_error_t;

static char *nat_ha_error_strings[] = {
#define _(sym, str) str,
  foreach_nat_ha_error
#undef _
};

/* process received HA NAT protocol messages */
static uword
nat_ha_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next;
  f64 now = vlib_time_now (vm);
  u32 thread_index = vm->thread_index;
  u32 pkts_processed = 0;
  ip4_main_t *i4m = &ip4_main;
  u8 host_config_ttl = i4m->host_config.ttl;
  nat_ha_main_t *ha = &nat_ha_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, next0, src_addr0, dst_addr0;;
	  vlib_buffer_t *b0;
	  nat_ha_message_header_t *h0;
	  nat_ha_event_t *e0;
	  u16 event_count0, src_port0, dst_port0, old_len0;
	  ip4_header_t *ip0;
	  udp_header_t *udp0;
	  ip_csum_t sum0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  h0 = vlib_buffer_get_current (b0);
	  vlib_buffer_advance (b0, -sizeof (*udp0));
	  udp0 = vlib_buffer_get_current (b0);
	  vlib_buffer_advance (b0, -sizeof (*ip0));
	  ip0 = vlib_buffer_get_current (b0);

	  next0 = NAT_HA_NEXT_DROP;

	  if (h0->version != NAT_HA_VERSION)
	    {
	      b0->error = node->errors[NAT_HA_ERROR_BAD_VERSION];
	      goto done0;
	    }

	  event_count0 = clib_net_to_host_u16 (h0->count);
	  /* ACK for previously send data */
	  if (!event_count0 && (h0->flags & NAT_HA_FLAG_ACK))
	    {
	      nat_ha_ack_recv (h0->sequence_number, thread_index);
	      b0->error = node->errors[NAT_HA_ERROR_PROCESSED];
	      goto done0;
	    }

	  e0 = (nat_ha_event_t *) (h0 + 1);

	  /* process each event */
	  while (event_count0)
	    {
	      nat_ha_event_process (e0, now, thread_index);
	      event_count0--;
	      e0 = (nat_ha_event_t *) ((u8 *) e0 + sizeof (nat_ha_event_t));
	    }

	  next0 = NAT_HA_NEXT_IP4_LOOKUP;
	  pkts_processed++;

	  /* reply with ACK */
	  b0->current_length = sizeof (*ip0) + sizeof (*udp0) + sizeof (*h0);

	  src_addr0 = ip0->src_address.data_u32;
	  dst_addr0 = ip0->dst_address.data_u32;
	  ip0->src_address.data_u32 = dst_addr0;
	  ip0->dst_address.data_u32 = src_addr0;
	  old_len0 = ip0->length;
	  ip0->length = clib_host_to_net_u16 (b0->current_length);

	  sum0 = ip0->checksum;
	  sum0 = ip_csum_update (sum0, ip0->ttl, host_config_ttl,
				 ip4_header_t, ttl);
	  ip0->ttl = host_config_ttl;
	  sum0 =
	    ip_csum_update (sum0, old_len0, ip0->length, ip4_header_t,
			    length);
	  ip0->checksum = ip_csum_fold (sum0);

	  udp0->checksum = 0;
	  src_port0 = udp0->src_port;
	  dst_port0 = udp0->dst_port;
	  udp0->src_port = dst_port0;
	  udp0->dst_port = src_port0;
	  udp0->length =
	    clib_host_to_net_u16 (b0->current_length - sizeof (*ip0));

	  h0->flags = NAT_HA_FLAG_ACK;
	  h0->count = 0;
	  vlib_increment_simple_counter (&ha->counters
					 [NAT_HA_COUNTER_SEND_ACK],
					 thread_index, 0, 1);

	done0:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      nat_ha_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      ip4_header_t *ip =
		(void *) (b0->data + vnet_buffer (b0)->l3_hdr_offset);
	      t->event_count = clib_net_to_host_u16 (h0->count);
	      t->addr.as_u32 = ip->src_address.data_u32;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, nat_ha_node.index,
			       NAT_HA_ERROR_PROCESSED, pkts_processed);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat_ha_node) = {
  .function = nat_ha_node_fn,
  .name = "nat-ha",
  .vector_size = sizeof (u32),
  .format_trace = format_nat_ha_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (nat_ha_error_strings),
  .error_strings = nat_ha_error_strings,
  .n_next_nodes = NAT_HA_N_NEXT,
  .next_nodes = {
     [NAT_HA_NEXT_IP4_LOOKUP] = "ip4-lookup",
     [NAT_HA_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

typedef struct
{
  u32 next_worker_index;
  u8 in2out;
} nat_ha_handoff_trace_t;

#define foreach_nat_ha_handoff_error  \
_(CONGESTION_DROP, "congestion drop") \
_(SAME_WORKER, "same worker")         \
_(DO_HANDOFF, "do handoff")

typedef enum
{
#define _(sym,str) NAT_HA_HANDOFF_ERROR_##sym,
  foreach_nat_ha_handoff_error
#undef _
    NAT_HA_HANDOFF_N_ERROR,
} nat_ha_handoff_error_t;

static char *nat_ha_handoff_error_strings[] = {
#define _(sym,string) string,
  foreach_nat_ha_handoff_error
#undef _
};

static u8 *
format_nat_ha_handoff_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nat_ha_handoff_trace_t *t = va_arg (*args, nat_ha_handoff_trace_t *);

  s =
    format (s, "NAT_HA_WORKER_HANDOFF: next-worker %d", t->next_worker_index);

  return s;
}

/* do worker handoff based on thread_index in NAT HA protcol header */
static uword
nat_ha_handoff_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
			vlib_frame_t * frame)
{
  nat_ha_main_t *ha = &nat_ha_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 n_enq, n_left_from, *from;
  u16 thread_indices[VLIB_FRAME_SIZE], *ti;
  u32 thread_index = vm->thread_index;
  u32 do_handoff = 0, same_worker = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  b = bufs;
  ti = thread_indices;

  while (n_left_from > 0)
    {
      nat_ha_message_header_t *h0;

      h0 = vlib_buffer_get_current (b[0]);
      ti[0] = clib_net_to_host_u32 (h0->thread_index);

      if (ti[0] != thread_index)
	do_handoff++;
      else
	same_worker++;

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  nat_ha_handoff_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->next_worker_index = ti[0];
	}

      n_left_from -= 1;
      ti += 1;
      b += 1;
    }

  n_enq =
    vlib_buffer_enqueue_to_thread (vm, ha->fq_index, from, thread_indices,
				   frame->n_vectors, 1);

  if (n_enq < frame->n_vectors)
    vlib_node_increment_counter (vm, node->node_index,
				 NAT_HA_HANDOFF_ERROR_CONGESTION_DROP,
				 frame->n_vectors - n_enq);
  vlib_node_increment_counter (vm, node->node_index,
			       NAT_HA_HANDOFF_ERROR_SAME_WORKER, same_worker);
  vlib_node_increment_counter (vm, node->node_index,
			       NAT_HA_HANDOFF_ERROR_DO_HANDOFF, do_handoff);
  return frame->n_vectors;
}

int
nat_ha_resync (u32 client_index, u32 pid,
	       nat_ha_resync_event_cb_t event_callback)
{
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat_ha_handoff_node) = {
  .function = nat_ha_handoff_node_fn,
  .name = "nat-ha-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_nat_ha_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(nat_ha_handoff_error_strings),
  .error_strings = nat_ha_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
