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
#ifndef __included_sample_h__
#define __included_sample_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/udp.h>
#include <vnet/flow/ipfix_packet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#include <vlib/threads.h>

typedef struct ioam_export_buffer {
  /* Allocated buffer */
  u32 buffer_index;
  u64 allocated_at;
  u8 records_in_this_buffer;
} ioam_export_buffer_t;


typedef struct {
  /* API message ID base */
  u16 msg_id_base;

  /* TODO: to support multiple collectors all this has to be grouped and create a vector here*/
  u8 *record_header;
  u32 sequence_number;
  u32 domain_id;

  /* ipfix collector, our ip address */
  ip4_address_t ipfix_collector;
  ip4_address_t src_address;

  ioam_export_buffer_t *buffer_cache;

  /* time scale transform*/
  u32 unix_time_0;
  f64 vlib_time_0;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
  ethernet_main_t * ethernet_main; 
} ioam_export_main_t;

ioam_export_main_t ioam_export_main;

vlib_node_registration_t export_node;

#define DEFAULT_EXPORT_SIZE (3 * CLIB_CACHE_LINE_BYTES)
/* 
 *  Number of records in a buffer
 * ~(MTU (1500) - [ip hdr(40) + UDP(8) + ipfix (24)]) / DEFAULT_EXPORT_SIZE
 */
#define DEFAULT_EXPORT_RECORDS 7 


always_inline ioam_export_buffer_t *ioam_export_get_my_buffer(vlib_main_t *vm)
{
  ioam_export_main_t *em = &ioam_export_main;

  if (vec_len(em->buffer_cache) > vm->cpu_index)
    return(&(em->buffer_cache[vm->cpu_index]));
  return(0);
}

inline static int ioam_export_buffer_add_header (vlib_buffer_t *b0)
{
  ioam_export_main_t *em = &ioam_export_main;
  clib_memcpy(b0->data, em->record_header, vec_len(em->record_header));
  b0->current_data = 0;
  b0->current_length = vec_len(em->record_header);
  b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  return(1);
}

inline static int ioam_export_init_buffer (vlib_main_t *vm,
					   ioam_export_buffer_t *eb)
{
  vlib_buffer_t *b = 0;
  
  if (!eb)
    return(-1);
  /* TODO: Perhaps buffer init from template here */
  if (vlib_buffer_alloc (vm, &(eb->buffer_index), 1) != 1)
    return(-2);
  eb->records_in_this_buffer = 0;
  eb->allocated_at = vlib_time_now(vm);
  b = vlib_get_buffer(vm, eb->buffer_index);
  (void) ioam_export_buffer_add_header(b);
  vnet_buffer(b)->sw_if_index[VLIB_RX] = 0;
  vnet_buffer(b)->sw_if_index[VLIB_TX] = ~0;
  return(1);
}

inline static void ioam_export_thread_buffer_free (void)
{
  ioam_export_main_t *em = &ioam_export_main;
  vlib_main_t *vm = em->vlib_main;
  int i;

  for (i=0; i<vec_len(em->buffer_cache); i++)
    {
      vlib_buffer_free(vm, &((em->buffer_cache[i]).buffer_index), 1);
    }
}
  
inline static int ioam_export_thread_buffer_init (vlib_main_t *vm)
{
  ioam_export_main_t *em = &ioam_export_main;
  int no_of_threads = vec_len(vlib_worker_threads);
  int i;
  ioam_export_buffer_t *eb = 0;

  vec_validate_aligned (em->buffer_cache, no_of_threads,
			CLIB_CACHE_LINE_BYTES);
  if (!em->buffer_cache)
    {
      return(-1);
    }
  for (i=0; i < no_of_threads; i++)
    {
      eb = &(em->buffer_cache[i]);
      if (ioam_export_init_buffer(vm, eb) != 1)
	{
	  ioam_export_thread_buffer_free();
	  vec_free(em->buffer_cache);
	  return(-2);
	}	  
    }
  return(1);
}

#define IPFIX_IOAM_EXPORT_ID 272

/* Used to build the rewrite */
/* data set packet */
typedef struct {
  ipfix_message_header_t h;
  ipfix_set_header_t s;
} ipfix_data_packet_t;

typedef struct {
  ip4_header_t ip4;
  udp_header_t udp;
  ipfix_data_packet_t ipfix;
} ip4_ipfix_data_packet_t;


inline static void ioam_export_header_cleanup (ip4_address_t * collector_address,
					       ip4_address_t * src_address)
{
  ioam_export_main_t *em = &ioam_export_main;
  vec_free(em->record_header);
  em->record_header = 0;
}
  
inline static int ioam_export_header_create (ip4_address_t * collector_address,
					     ip4_address_t * src_address)
{
  ioam_export_main_t *em = &ioam_export_main;
  ip4_header_t * ip;
  udp_header_t * udp;
  ipfix_message_header_t * h;
  ipfix_set_header_t * s;
  u8 * rewrite = 0;
  ip4_ipfix_data_packet_t * tp;

  
  /* allocate rewrite space */
  vec_validate_aligned (rewrite, 
                        sizeof (ip4_ipfix_data_packet_t),
                        CLIB_CACHE_LINE_BYTES);

  tp = (ip4_ipfix_data_packet_t *) rewrite;
  ip = (ip4_header_t *) &tp->ip4;
  udp = (udp_header_t *) (ip+1);
  h = (ipfix_message_header_t *)(udp+1);
  s = (ipfix_set_header_t *)(h+1);

  ip->ip_version_and_header_length = 0x45;
  ip->ttl = 254;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->src_address.as_u32 = src_address->as_u32;
  ip->dst_address.as_u32 = collector_address->as_u32;
  udp->src_port = clib_host_to_net_u16 (4750 /* $$FIXME */);
  udp->dst_port = clib_host_to_net_u16 (4750);
  /* FIXUP: UDP length */
  udp->length = clib_host_to_net_u16 (vec_len(rewrite) +
    (DEFAULT_EXPORT_RECORDS * DEFAULT_EXPORT_SIZE) - sizeof (*ip));

  /* FIXUP: message header export_time */ 
  /* FIXUP: message header sequence_number */
  h->domain_id = clib_host_to_net_u32 (em->domain_id);

  /*FIXUP: Setid length in octets if records exported are not default*/
  s->set_id_length = ipfix_set_id_length (IPFIX_IOAM_EXPORT_ID,
    (sizeof(*s) + (DEFAULT_EXPORT_RECORDS * DEFAULT_EXPORT_SIZE)));
                          
  /* FIXUP: h version and length length in octets if records exported are not default */
  h->version_length = version_length (sizeof(*h)+
    (sizeof(*s) + (DEFAULT_EXPORT_RECORDS * DEFAULT_EXPORT_SIZE)));

  /* FIXUP: ip length if records exported are not default */
  /* FIXUP: ip checksum if records exported are not default */
  ip->length = clib_host_to_net_u16 (vec_len(rewrite) +
    (DEFAULT_EXPORT_RECORDS * DEFAULT_EXPORT_SIZE));
  ip->checksum = ip4_header_checksum (ip);
  _vec_len(rewrite) = sizeof(ip4_ipfix_data_packet_t);
  em->record_header = rewrite;
  return(1);
}

 inline static int ioam_export_send_buffer (vlib_main_t *vm,
    ioam_export_buffer_t *eb)
 {
  ioam_export_main_t *em = &ioam_export_main;
  ip4_header_t * ip;
  udp_header_t * udp;
  ipfix_message_header_t * h;
  ipfix_set_header_t * s;
  ip4_ipfix_data_packet_t * tp;
  vlib_buffer_t *b0;
  u16 new_l0, old_l0;
  ip_csum_t sum0;
  u32 ip4_lookup_node_index;
  vlib_node_t * ip4_lookup_node;
  vlib_frame_t * nf = 0;
  u32 * to_next;

  b0 = vlib_get_buffer(vm, eb->buffer_index);
  tp = vlib_buffer_get_current (b0);
  ip = (ip4_header_t *) &tp->ip4;
  udp = (udp_header_t *) (ip+1);
  h = (ipfix_message_header_t *)(udp+1);
  s = (ipfix_set_header_t *)(h+1);
                  
  /* FIXUP: message header export_time */ 
  h->export_time = (u32) 
    (((f64)em->unix_time_0) + 
    (vlib_time_now(em->vlib_main) - em->vlib_time_0));
  h->export_time = clib_host_to_net_u32(h->export_time);
                  
  /* FIXUP: message header sequence_number */
  h->sequence_number = em->sequence_number++;
  h->sequence_number = clib_host_to_net_u32 (h->sequence_number);

  /* FIXUP: lengths if different from default */

  if (PREDICT_FALSE(eb->records_in_this_buffer != DEFAULT_EXPORT_RECORDS)) {
     s->set_id_length = ipfix_set_id_length (IPFIX_IOAM_EXPORT_ID /* set_id */,
                                            b0->current_length -
                                            (sizeof (*ip) + sizeof (*udp) +
                                            sizeof (*h)));
     h->version_length = version_length (b0->current_length -
                                        (sizeof (*ip) + sizeof (*udp)));
     sum0 = ip->checksum;
     old_l0 = clib_net_to_host_u16 (ip->length);
     new_l0 = clib_host_to_net_u16 ((u16)b0->current_length);
     sum0 = ip_csum_update (sum0, old_l0, new_l0, ip4_header_t,
                            length /* changed member */);
     ip->checksum = ip_csum_fold (sum0);
     ip->length = new_l0;
     udp->length = clib_host_to_net_u16 (b0->current_length - sizeof (ip));
  }

  /* Enqueue pkts to ip4-lookup */
  ip4_lookup_node = vlib_get_node_by_name (vm, (u8 *) "ip4-lookup");
  ip4_lookup_node_index = ip4_lookup_node->index;

  nf = vlib_get_frame_to_node (vm, ip4_lookup_node_index);
  nf->n_vectors = 0;
  to_next = vlib_frame_vector_args (nf);
  nf->n_vectors = 1;
  to_next[0] = eb->buffer_index;
  vlib_put_frame_to_node(vm, ip4_lookup_node_index, nf);
  return(1);	  
  
}

#endif /* __included_export_h__ */
