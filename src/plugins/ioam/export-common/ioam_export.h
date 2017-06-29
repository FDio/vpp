/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#ifndef __included_ioam_export_h__
#define __included_ioam_export_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip6_hop_by_hop.h>
#include <vnet/udp/udp.h>
#include <vnet/flow/ipfix_packet.h>

#include <vppinfra/pool.h>
#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#include <vlib/threads.h>

typedef struct ioam_export_buffer
{
  /* Allocated buffer */
  u32 buffer_index;
  u64 touched_at;
  u8 records_in_this_buffer;
} ioam_export_buffer_t;


typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  u16 set_id;

  /* TODO: to support multiple collectors all this has to be grouped and create a vector here */
  u8 *record_header;
  u32 sequence_number;
  u32 domain_id;

  /* ipfix collector, our ip address */
  ip4_address_t ipfix_collector;
  ip4_address_t src_address;

  /* Pool of ioam_export_buffer_t */
  ioam_export_buffer_t *buffer_pool;
  /* Vector of per thread ioam_export_buffer_t to buffer pool index */
  u32 *buffer_per_thread;
  /* Lock per thread to swap buffers between worker and timer process */
  volatile u32 **lockp;

  /* time scale transform */
  u32 unix_time_0;
  f64 vlib_time_0;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ethernet_main_t *ethernet_main;
  u32 next_node_index;

  uword my_hbh_slot;
  u32 export_process_node_index;
} ioam_export_main_t;


#define DEFAULT_EXPORT_SIZE (3 * CLIB_CACHE_LINE_BYTES)
/*
 *  Number of records in a buffer
 * ~(MTU (1500) - [ip hdr(40) + UDP(8) + ipfix (24)]) / DEFAULT_EXPORT_SIZE
 */
#define DEFAULT_EXPORT_RECORDS 7

inline static void
ioam_export_set_next_node (ioam_export_main_t * em, u8 * next_node_name)
{
  vlib_node_t *next_node;

  next_node = vlib_get_node_by_name (em->vlib_main, next_node_name);
  em->next_node_index = next_node->index;
}

inline static void
ioam_export_reset_next_node (ioam_export_main_t * em)
{
  vlib_node_t *next_node;

  next_node = vlib_get_node_by_name (em->vlib_main, (u8 *) "ip4-lookup");
  em->next_node_index = next_node->index;
}

always_inline ioam_export_buffer_t *
ioam_export_get_my_buffer (ioam_export_main_t * em, u32 thread_id)
{

  if (vec_len (em->buffer_per_thread) > thread_id)
    return (pool_elt_at_index
	    (em->buffer_pool, em->buffer_per_thread[thread_id]));
  return (0);
}

inline static int
ioam_export_buffer_add_header (ioam_export_main_t * em, vlib_buffer_t * b0)
{
  clib_memcpy (b0->data, em->record_header, vec_len (em->record_header));
  b0->current_data = 0;
  b0->current_length = vec_len (em->record_header);
  b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  return (1);
}

inline static int
ioam_export_init_buffer (ioam_export_main_t * em, vlib_main_t * vm,
			 ioam_export_buffer_t * eb)
{
  vlib_buffer_t *b = 0;

  if (!eb)
    return (-1);
  /* TODO: Perhaps buffer init from template here */
  if (vlib_buffer_alloc (vm, &(eb->buffer_index), 1) != 1)
    return (-2);
  eb->records_in_this_buffer = 0;
  eb->touched_at = vlib_time_now (vm);
  b = vlib_get_buffer (vm, eb->buffer_index);
  (void) ioam_export_buffer_add_header (em, b);
  vnet_buffer (b)->sw_if_index[VLIB_RX] = 0;
  vnet_buffer (b)->sw_if_index[VLIB_TX] = ~0;
  return (1);
}

inline static void
ioam_export_thread_buffer_free (ioam_export_main_t * em)
{
  vlib_main_t *vm = em->vlib_main;
  ioam_export_buffer_t *eb = 0;
  int i;
  for (i = 0; i < vec_len (em->buffer_per_thread); i++)
    {
      eb = pool_elt_at_index (em->buffer_pool, em->buffer_per_thread[i]);
      if (eb)
	vlib_buffer_free (vm, &(eb->buffer_index), 1);
    }
  for (i = 0; i < vec_len (em->lockp); i++)
    clib_mem_free ((void *) em->lockp[i]);
  vec_free (em->buffer_per_thread);
  pool_free (em->buffer_pool);
  vec_free (em->lockp);
  em->buffer_per_thread = 0;
  em->buffer_pool = 0;
  em->lockp = 0;
}

inline static int
ioam_export_thread_buffer_init (ioam_export_main_t * em, vlib_main_t * vm)
{
  int no_of_threads = vec_len (vlib_worker_threads);
  int i;
  ioam_export_buffer_t *eb = 0;

  pool_alloc_aligned (em->buffer_pool,
		      no_of_threads - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (em->buffer_per_thread,
			no_of_threads - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (em->lockp, no_of_threads - 1, CLIB_CACHE_LINE_BYTES);

  if (!em->buffer_per_thread || !em->buffer_pool || !em->lockp)
    {
      return (-1);
    }
  for (i = 0; i < no_of_threads; i++)
    {
      eb = 0;
      pool_get_aligned (em->buffer_pool, eb, CLIB_CACHE_LINE_BYTES);
      memset (eb, 0, sizeof (*eb));
      em->buffer_per_thread[i] = eb - em->buffer_pool;
      if (ioam_export_init_buffer (em, vm, eb) != 1)
	{
	  ioam_export_thread_buffer_free (em);
	  return (-2);
	}
      em->lockp[i] = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES,
					     CLIB_CACHE_LINE_BYTES);
      memset ((void *) em->lockp[i], 0, CLIB_CACHE_LINE_BYTES);
    }
  return (1);
}

#define IPFIX_IOAM_EXPORT_ID 272
#define IPFIX_VXLAN_IOAM_EXPORT_ID 273
#define IPFIX_SR_IOAM_EXPORT_ID 280

/* Used to build the rewrite */
/* data set packet */
typedef struct
{
  ipfix_message_header_t h;
  ipfix_set_header_t s;
} ipfix_data_packet_t;

typedef struct
{
  ip4_header_t ip4;
  udp_header_t udp;
  ipfix_data_packet_t ipfix;
} ip4_ipfix_data_packet_t;


inline static void
ioam_export_header_cleanup (ioam_export_main_t * em,
			    ip4_address_t * collector_address,
			    ip4_address_t * src_address)
{
  vec_free (em->record_header);
  em->record_header = 0;
}

inline static int
ioam_export_header_create (ioam_export_main_t * em,
			   ip4_address_t * collector_address,
			   ip4_address_t * src_address)
{
  ip4_header_t *ip;
  udp_header_t *udp;
  ipfix_message_header_t *h;
  ipfix_set_header_t *s;
  u8 *rewrite = 0;
  ip4_ipfix_data_packet_t *tp;


  /* allocate rewrite space */
  vec_validate_aligned (rewrite,
			sizeof (ip4_ipfix_data_packet_t) - 1,
			CLIB_CACHE_LINE_BYTES);

  tp = (ip4_ipfix_data_packet_t *) rewrite;
  ip = (ip4_header_t *) & tp->ip4;
  udp = (udp_header_t *) (ip + 1);
  h = (ipfix_message_header_t *) (udp + 1);
  s = (ipfix_set_header_t *) (h + 1);

  ip->ip_version_and_header_length = 0x45;
  ip->ttl = 254;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->src_address.as_u32 = src_address->as_u32;
  ip->dst_address.as_u32 = collector_address->as_u32;
  udp->src_port = clib_host_to_net_u16 (UDP_DST_PORT_ipfix);
  udp->dst_port = clib_host_to_net_u16 (UDP_DST_PORT_ipfix);
  /* FIXUP: UDP length */
  udp->length = clib_host_to_net_u16 (vec_len (rewrite) +
				      (DEFAULT_EXPORT_RECORDS *
				       DEFAULT_EXPORT_SIZE) - sizeof (*ip));

  /* FIXUP: message header export_time */
  /* FIXUP: message header sequence_number */
  h->domain_id = clib_host_to_net_u32 (em->domain_id);

  /*FIXUP: Setid length in octets if records exported are not default */
  s->set_id_length = ipfix_set_id_length (em->set_id,
					  (sizeof (*s) +
					   (DEFAULT_EXPORT_RECORDS *
					    DEFAULT_EXPORT_SIZE)));

  /* FIXUP: h version and length length in octets if records exported are not default */
  h->version_length = version_length (sizeof (*h) +
				      (sizeof (*s) +
				       (DEFAULT_EXPORT_RECORDS *
					DEFAULT_EXPORT_SIZE)));

  /* FIXUP: ip length if records exported are not default */
  /* FIXUP: ip checksum if records exported are not default */
  ip->length = clib_host_to_net_u16 (vec_len (rewrite) +
				     (DEFAULT_EXPORT_RECORDS *
				      DEFAULT_EXPORT_SIZE));
  ip->checksum = ip4_header_checksum (ip);
  _vec_len (rewrite) = sizeof (ip4_ipfix_data_packet_t);
  em->record_header = rewrite;
  return (1);
}

inline static int
ioam_export_send_buffer (ioam_export_main_t * em, vlib_main_t * vm,
			 ioam_export_buffer_t * eb)
{
  ip4_header_t *ip;
  udp_header_t *udp;
  ipfix_message_header_t *h;
  ipfix_set_header_t *s;
  ip4_ipfix_data_packet_t *tp;
  vlib_buffer_t *b0;
  u16 new_l0, old_l0;
  ip_csum_t sum0;
  vlib_frame_t *nf = 0;
  u32 *to_next;

  b0 = vlib_get_buffer (vm, eb->buffer_index);
  tp = vlib_buffer_get_current (b0);
  ip = (ip4_header_t *) & tp->ip4;
  udp = (udp_header_t *) (ip + 1);
  h = (ipfix_message_header_t *) (udp + 1);
  s = (ipfix_set_header_t *) (h + 1);

  /* FIXUP: message header export_time */
  h->export_time = clib_host_to_net_u32 ((u32)
					 (((f64) em->unix_time_0) +
					  (vlib_time_now (em->vlib_main) -
					   em->vlib_time_0)));

  /* FIXUP: message header sequence_number */
  h->sequence_number = clib_host_to_net_u32 (em->sequence_number++);

  /* FIXUP: lengths if different from default */
  if (PREDICT_FALSE (eb->records_in_this_buffer != DEFAULT_EXPORT_RECORDS))
    {
      s->set_id_length = ipfix_set_id_length (em->set_id /* set_id */ ,
					      b0->current_length -
					      (sizeof (*ip) + sizeof (*udp) +
					       sizeof (*h)));
      h->version_length =
	version_length (b0->current_length - (sizeof (*ip) + sizeof (*udp)));
      sum0 = ip->checksum;
      old_l0 = ip->length;
      new_l0 = clib_host_to_net_u16 ((u16) b0->current_length);
      sum0 = ip_csum_update (sum0, old_l0, new_l0, ip4_header_t,
			     length /* changed member */ );
      ip->checksum = ip_csum_fold (sum0);
      ip->length = new_l0;
      udp->length = clib_host_to_net_u16 (b0->current_length - sizeof (*ip));
    }

  /* Enqueue pkts to ip4-lookup */

  nf = vlib_get_frame_to_node (vm, em->next_node_index);
  nf->n_vectors = 0;
  to_next = vlib_frame_vector_args (nf);
  nf->n_vectors = 1;
  to_next[0] = eb->buffer_index;
  vlib_put_frame_to_node (vm, em->next_node_index, nf);
  return (1);

}

#define EXPORT_TIMEOUT (20.0)
#define THREAD_PERIOD (30.0)
inline static uword
ioam_export_process_common (ioam_export_main_t * em, vlib_main_t * vm,
			    vlib_node_runtime_t * rt, vlib_frame_t * f,
			    u32 index)
{
  f64 now;
  f64 timeout = 30.0;
  uword event_type;
  uword *event_data = 0;
  int i;
  ioam_export_buffer_t *eb = 0, *new_eb = 0;
  u32 *vec_buffer_indices = 0;
  u32 *vec_buffer_to_be_sent = 0;
  u32 *thread_index = 0;
  u32 new_pool_index = 0;

  em->export_process_node_index = index;
  /* Wait for Godot... */
  vlib_process_wait_for_event_or_clock (vm, 1e9);
  event_type = vlib_process_get_events (vm, &event_data);
  if (event_type != 1)
    clib_warning ("bogus kickoff event received, %d", event_type);
  vec_reset_length (event_data);

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);
      event_type = vlib_process_get_events (vm, &event_data);
      switch (event_type)
	{
	case 2:		/* Stop and Wait for kickoff again */
	  timeout = 1e9;
	  break;
	case 1:		/* kickoff : Check for unsent buffers */
	  timeout = THREAD_PERIOD;
	  break;
	case ~0:		/* timeout */
	  break;
	}
      vec_reset_length (event_data);
      now = vlib_time_now (vm);
      /*
       * Create buffers for threads that are not active enough
       * to send out the export records
       */
      for (i = 0; i < vec_len (em->buffer_per_thread); i++)
	{
	  /* If the worker thread is processing export records ignore further checks */
	  if (*em->lockp[i] == 1)
	    continue;
	  eb = pool_elt_at_index (em->buffer_pool, em->buffer_per_thread[i]);
	  if (eb->records_in_this_buffer > 0
	      && now > (eb->touched_at + EXPORT_TIMEOUT))
	    {
	      pool_get_aligned (em->buffer_pool, new_eb,
				CLIB_CACHE_LINE_BYTES);
	      memset (new_eb, 0, sizeof (*new_eb));
	      if (ioam_export_init_buffer (em, vm, new_eb) == 1)
		{
		  new_pool_index = new_eb - em->buffer_pool;
		  vec_add (vec_buffer_indices, &new_pool_index, 1);
		  vec_add (vec_buffer_to_be_sent, &em->buffer_per_thread[i],
			   1);
		  vec_add (thread_index, &i, 1);
		}
	      else
		{
		  pool_put (em->buffer_pool, new_eb);
		  /*Give up */
		  goto CLEANUP;
		}
	    }
	}
      if (vec_len (thread_index) != 0)
	{
	  /*
	   * Now swap the buffers out
	   */
	  for (i = 0; i < vec_len (thread_index); i++)
	    {
	      while (__sync_lock_test_and_set (em->lockp[thread_index[i]], 1))
		;
	      em->buffer_per_thread[thread_index[i]] =
		vec_pop (vec_buffer_indices);
	      *em->lockp[thread_index[i]] = 0;
	    }

	  /* Send the buffers */
	  for (i = 0; i < vec_len (vec_buffer_to_be_sent); i++)
	    {
	      eb =
		pool_elt_at_index (em->buffer_pool, vec_buffer_to_be_sent[i]);
	      ioam_export_send_buffer (em, vm, eb);
	      pool_put (em->buffer_pool, eb);
	    }
	}

    CLEANUP:
      /* Free any leftover/unused buffers and everything that was allocated */
      for (i = 0; i < vec_len (vec_buffer_indices); i++)
	{
	  new_eb = pool_elt_at_index (em->buffer_pool, vec_buffer_indices[i]);
	  vlib_buffer_free (vm, &new_eb->buffer_index, 1);
	  pool_put (em->buffer_pool, new_eb);
	}
      vec_free (vec_buffer_indices);
      vec_free (vec_buffer_to_be_sent);
      vec_free (thread_index);
    }
  return 0;			/* not so much */
}

#define ioam_export_node_common(EM, VM, N, F, HTYPE, L, V, NEXT, FIXUP_FUNC)   \
do {                                                                           \
  u32 n_left_from, *from, *to_next;                                            \
  export_next_t next_index;                                                    \
  u32 pkts_recorded = 0;                                                       \
  ioam_export_buffer_t *my_buf = 0;                                            \
  vlib_buffer_t *eb0 = 0;                                                      \
  u32 ebi0 = 0;                                                                \
  from = vlib_frame_vector_args (F);                                           \
  n_left_from = (F)->n_vectors;                                                \
  next_index = (N)->cached_next_index;                                         \
  while (__sync_lock_test_and_set ((EM)->lockp[(VM)->thread_index], 1));       \
  my_buf = ioam_export_get_my_buffer (EM, (VM)->thread_index);                 \
  my_buf->touched_at = vlib_time_now (VM);                                     \
  while (n_left_from > 0)                                                      \
    {                                                                          \
      u32 n_left_to_next;                                                      \
      vlib_get_next_frame (VM, N, next_index, to_next, n_left_to_next);        \
      while (n_left_from >= 4 && n_left_to_next >= 2)                          \
	{                                                                      \
	  u32 next0 = NEXT;                                                    \
	  u32 next1 = NEXT;                                                    \
	  u32 bi0, bi1;                                                        \
	  HTYPE *ip0, *ip1;                                                    \
	  vlib_buffer_t *p0, *p1;                                              \
	  u32 ip_len0, ip_len1;                                                \
	  {                                                                    \
	    vlib_buffer_t *p2, *p3;                                            \
	    p2 = vlib_get_buffer (VM, from[2]);                                \
	    p3 = vlib_get_buffer (VM, from[3]);                                \
	    vlib_prefetch_buffer_header (p2, LOAD);                            \
	    vlib_prefetch_buffer_header (p3, LOAD);                            \
	    CLIB_PREFETCH (p2->data, 3 * CLIB_CACHE_LINE_BYTES, LOAD);         \
	    CLIB_PREFETCH (p3->data, 3 * CLIB_CACHE_LINE_BYTES, LOAD);         \
	  }                                                                    \
	  to_next[0] = bi0 = from[0];                                          \
	  to_next[1] = bi1 = from[1];                                          \
	  from += 2;                                                           \
	  to_next += 2;                                                        \
	  n_left_from -= 2;                                                    \
	  n_left_to_next -= 2;                                                 \
	  p0 = vlib_get_buffer (VM, bi0);                                      \
	  p1 = vlib_get_buffer (VM, bi1);                                      \
	  ip0 = vlib_buffer_get_current (p0);                                  \
	  ip1 = vlib_buffer_get_current (p1);                                  \
	  ip_len0 =                                                            \
	    clib_net_to_host_u16 (ip0->L) + sizeof (HTYPE);                    \
	  ip_len1 =                                                            \
	    clib_net_to_host_u16 (ip1->L) + sizeof (HTYPE);                    \
	  ebi0 = my_buf->buffer_index;                                         \
	  eb0 = vlib_get_buffer (VM, ebi0);                                    \
	  if (PREDICT_FALSE (eb0 == 0))                                        \
	    goto NO_BUFFER1;                                                   \
	  ip_len0 =                                                            \
	    ip_len0 > DEFAULT_EXPORT_SIZE ? DEFAULT_EXPORT_SIZE : ip_len0;     \
	  ip_len1 =                                                            \
	    ip_len1 > DEFAULT_EXPORT_SIZE ? DEFAULT_EXPORT_SIZE : ip_len1;     \
	  copy3cachelines (eb0->data + eb0->current_length, ip0, ip_len0);     \
	  FIXUP_FUNC(eb0, p0);                                                 \
	  eb0->current_length += DEFAULT_EXPORT_SIZE;                          \
	  my_buf->records_in_this_buffer++;                                    \
	  if (my_buf->records_in_this_buffer >= DEFAULT_EXPORT_RECORDS)        \
	    {                                                                  \
	      ioam_export_send_buffer (EM, VM, my_buf);                        \
	      ioam_export_init_buffer (EM, VM, my_buf);                        \
	    }                                                                  \
	  ebi0 = my_buf->buffer_index;                                         \
	  eb0 = vlib_get_buffer (VM, ebi0);                                    \
	  if (PREDICT_FALSE (eb0 == 0))                                        \
	    goto NO_BUFFER1;                                                   \
	  copy3cachelines (eb0->data + eb0->current_length, ip1, ip_len1);     \
	  FIXUP_FUNC(eb0, p1);                                                 \
	  eb0->current_length += DEFAULT_EXPORT_SIZE;                          \
	  my_buf->records_in_this_buffer++;                                    \
	  if (my_buf->records_in_this_buffer >= DEFAULT_EXPORT_RECORDS)        \
	    {                                                                  \
	      ioam_export_send_buffer (EM, VM, my_buf);                        \
	      ioam_export_init_buffer (EM, VM, my_buf);                        \
	    }                                                                  \
	  pkts_recorded += 2;                                                  \
	  if (PREDICT_FALSE (((node)->flags & VLIB_NODE_FLAG_TRACE)))          \
	    {                                                                  \
	      if (p0->flags & VLIB_BUFFER_IS_TRACED)                           \
		{                                                              \
		  export_trace_t *t =                                          \
		    vlib_add_trace (VM, node, p0, sizeof (*t));                \
		  t->flow_label =                                              \
		    clib_net_to_host_u32 (ip0->V);                             \
		  t->next_index = next0;                                       \
		}                                                              \
	      if (p1->flags & VLIB_BUFFER_IS_TRACED)                           \
		{                                                              \
		  export_trace_t *t =                                          \
		    vlib_add_trace (VM, N, p1, sizeof (*t));                   \
		  t->flow_label =                                              \
		    clib_net_to_host_u32 (ip1->V);                             \
		  t->next_index = next1;                                       \
		}                                                              \
	    }                                                                  \
	NO_BUFFER1:                                                            \
	  vlib_validate_buffer_enqueue_x2 (VM, N, next_index,                  \
					   to_next, n_left_to_next,            \
					   bi0, bi1, next0, next1);            \
	}                                                                      \
      while (n_left_from > 0 && n_left_to_next > 0)                            \
	{                                                                      \
	  u32 bi0;                                                             \
	  vlib_buffer_t *p0;                                                   \
	  u32 next0 = NEXT;                                                    \
	  HTYPE *ip0;                                                          \
	  u32 ip_len0;                                                         \
	  bi0 = from[0];                                                       \
	  to_next[0] = bi0;                                                    \
	  from += 1;                                                           \
	  to_next += 1;                                                        \
	  n_left_from -= 1;                                                    \
	  n_left_to_next -= 1;                                                 \
	  p0 = vlib_get_buffer (VM, bi0);                                      \
	  ip0 = vlib_buffer_get_current (p0);                                  \
	  ip_len0 =                                                            \
	    clib_net_to_host_u16 (ip0->L) + sizeof (HTYPE);                    \
	  ebi0 = my_buf->buffer_index;                                         \
	  eb0 = vlib_get_buffer (VM, ebi0);                                    \
	  if (PREDICT_FALSE (eb0 == 0))                                        \
	    goto NO_BUFFER;                                                    \
	  ip_len0 =                                                            \
	    ip_len0 > DEFAULT_EXPORT_SIZE ? DEFAULT_EXPORT_SIZE : ip_len0;     \
	  copy3cachelines (eb0->data + eb0->current_length, ip0, ip_len0);     \
	  FIXUP_FUNC(eb0, p0);                                                 \
	  eb0->current_length += DEFAULT_EXPORT_SIZE;                          \
	  my_buf->records_in_this_buffer++;                                    \
	  if (my_buf->records_in_this_buffer >= DEFAULT_EXPORT_RECORDS)        \
	    {                                                                  \
	      ioam_export_send_buffer (EM, VM, my_buf);                        \
	      ioam_export_init_buffer (EM, VM, my_buf);                        \
	    }                                                                  \
	  if (PREDICT_FALSE (((N)->flags & VLIB_NODE_FLAG_TRACE)               \
			     && (p0->flags & VLIB_BUFFER_IS_TRACED)))          \
	    {                                                                  \
	      export_trace_t *t = vlib_add_trace (VM, (N), p0, sizeof (*t));   \
	      t->flow_label =                                                  \
		clib_net_to_host_u32 (ip0->V);                                 \
	      t->next_index = next0;                                           \
	    }                                                                  \
	  pkts_recorded += 1;                                                  \
	NO_BUFFER:                                                             \
	  vlib_validate_buffer_enqueue_x1 (VM, N, next_index,                  \
					   to_next, n_left_to_next,            \
					   bi0, next0);                        \
	}                                                                      \
      vlib_put_next_frame (VM, N, next_index, n_left_to_next);                 \
    }                                                                          \
  vlib_node_increment_counter (VM, export_node.index,                          \
			       EXPORT_ERROR_RECORDED, pkts_recorded);          \
  *(EM)->lockp[(VM)->thread_index] = 0;                                        \
} while(0)

#endif /* __included_ioam_export_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
