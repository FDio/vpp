/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include <vnet/flow/flow_report.h>
#include <vnet/ip/ip6_ioam_flow_report.h>
#include <vnet/ip/ip6_hop_by_hop.h>
#include <vnet/api_errno.h>

#ifdef ORIG_CODE
typedef struct {
  u32 classify_table_index;
  ioam_ipfix_elts_t ifix;
  u32 trace_option_elts;
} ip6_ioam_flow_report_main_t;

ip6_ioam_flow_report_main_t ip6_ioam_flow_report_main;
#endif

static u8 * ip6_ioam_template_rewrite (flow_report_main_t * frm,
                              flow_report_t * fr,
                              ip4_address_t * collector_address,
                              ip4_address_t * src_address)
{
  ip6_hop_by_hop_ioam_main_t * hm = &ip6_hop_by_hop_ioam_main;
#ifdef ORIG_CODE
  ip6_ioam_flow_report_main_t *fsm = 
    (ip6_ioam_flow_report_main_t *) fr->opaque;
#endif
  ip4_header_t * ip;
  udp_header_t * udp;
  ipfix_message_header_t * h;
  ipfix_set_header_t * s;
  ipfix_template_header_t * t;
  ipfix_field_specifier_t * f;
  ipfix_field_specifier_t * first_field;
  u8 * rewrite = 0;
  ip4_ipfix_template_packet_t * tp;
  u32 field_count = 0;
  u32 field_index = 0;
  
#ifdef ORIG_CODE
  vnet_classify_table_t * tblp;
  vnet_classify_main_t * vcm = &vnet_classify_main;
  i32 l3_offset = -2;  /* sizeof (ethernet_header_t) - sizeof (u32x4) */
  tblp = pool_elt_at_index (vcm->tables, fsm->classify_table_index);

  /* 
   * Mumble, assumes that we're not classifying on L2 or first 2 octets
   * of L3..
   */

  ip = (ip4_header_t *)(((u8 *)(tblp->mask)) + l3_offset);
  udp = (udp_header_t *)(ip+1);
#endif

  /* Determine field count */
#define _(field,mask,item,length)                                       \
  /*if ((field) == (mask))                                                \*/\
    {                                                                   \
      field_count++;                                                    \
                                                                        \
      fr->fields_to_send = clib_bitmap_set (fr->fields_to_send,         \
                                            field_index, 1);            \
    }                                                                   \
  field_index++;
  
  foreach_ioam_ipfix_field;
#undef _
  /* Add sourceIPv6Address, destinationIPv6Address, ioamPathMap manually */
  field_count += 3;

  /* $$$ enterprise fields, at some later date */

  /* allocate rewrite space */
  vec_validate_aligned (rewrite, 
                        sizeof (ip4_ipfix_template_packet_t) 
                        + field_count * sizeof (ipfix_field_specifier_t) - 1,
                        CLIB_CACHE_LINE_BYTES);

  tp = (ip4_ipfix_template_packet_t *) rewrite;
  ip = (ip4_header_t *) &tp->ip4;
  udp = (udp_header_t *) (ip+1);
  h = (ipfix_message_header_t *)(udp+1);
  s = (ipfix_set_header_t *)(h+1);
  t = (ipfix_template_header_t *)(s+1);
  first_field = f = (ipfix_field_specifier_t *)(t+1);

  ip->ip_version_and_header_length = 0x45;
  ip->ttl = 254;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->src_address.as_u32 = src_address->as_u32;
  ip->dst_address.as_u32 = collector_address->as_u32;
  udp->src_port = clib_host_to_net_u16 (4739 /* $$FIXME */);
  udp->dst_port = clib_host_to_net_u16 (UDP_DST_PORT_ipfix);
  udp->length = clib_host_to_net_u16 (vec_len(rewrite) - sizeof (*ip));

  /* FIXUP: message header export_time */ 
  /* FIXUP: message header sequence_number */
  h->domain_id = clib_host_to_net_u32 (fr->domain_id);

  /* Take another trip through the mask and build the template */

  /* Add source and destination IPv6 address manually */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */,
                               sourceIPv6Address, sizeof(ip6_address_t));
  f++;
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */,
                               destinationIPv6Address, sizeof(ip6_address_t));
  f++;

#define _(field,mask,item,length)                               \
    {                                                           \
      f->e_id_length = ipfix_e_id_length (0 /* enterprise */,   \
                                          item, length);        \
      f++;                                                      \
    }
  foreach_ioam_ipfix_field;
#undef _


  /* Add ioamPathMap manually */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */,
           ioamPathMap, (hm->trace_option_elts * sizeof(ioam_path_map_t)));
  f++;

  /* Back to the template packet... */
  ip = (ip4_header_t *) &tp->ip4;
  udp = (udp_header_t *) (ip+1);
  
  ASSERT (f - first_field);
  /* Field count in this template */
  t->id_count = ipfix_id_count (260 /* template_id */, f - first_field);

  /* set length in octets*/
  s->set_id_length = ipfix_set_id_length (2 /* set_id */, (u8 *) f - (u8 *)s);

  /* message length in octets */
  h->version_length = version_length ((u8 *)f - (u8 *)h);

  ip->length = clib_host_to_net_u16 ((u8 *)f - (u8 *)ip);
  ip->checksum = ip4_header_checksum (ip);

  return rewrite;
}

static vlib_frame_t * ip6_ioam_send_flows (flow_report_main_t * frm, 
                                  flow_report_t * fr,
                                  vlib_frame_t * f, u32 * to_next, 
                                  u32 node_index)
{
  ip6_hop_by_hop_ioam_main_t * hm = &ip6_hop_by_hop_ioam_main;
#ifdef ORIG_CODE
  vnet_classify_main_t * vcm = &vnet_classify_main;
  ip6_ioam_flow_report_main_t * fsm = 
    (ip6_ioam_flow_report_main_t *) fr->opaque;
  ioam_ipfix_elts_t *ifix = &fsm->ifix;
  
  vnet_classify_table_t * t = 
    pool_elt_at_index (vcm->tables, fsm->classify_table_index);
#else
  ioam_ipfix_elts_t *ifix;
#endif
  vlib_buffer_t *b0 = 0;
  u32 next_offset = 0;
  u32 bi0 = ~0;
  int i, j;
  ip4_ipfix_template_packet_t * tp;
  ipfix_message_header_t * h;
  ipfix_set_header_t * s = 0;
  ip4_header_t * ip;
  udp_header_t * udp;
  int field_index;
  u32 records_this_buffer;
  u16 new_l0, old_l0;
  ip_csum_t sum0;
  vlib_main_t * vm = frm->vlib_main;
  
#ifdef ORIG_CODE
  while (__sync_lock_test_and_set (t->writer_lock, 1))
    ; 
#endif
  
#ifndef ORIG_CODE
  for (i = 0, j = 0; i < MAX_FLOWS && j < hm->num_flows; i++)
  {
    ifix = &hm->ipfix_elts[i];
    if(is_zero_ip6_address(&ifix->dst_addr))
    {
      continue;
    }
    /* Non empty flow send it */
    j++;

    /* OK, we have something to send... */
    if (PREDICT_FALSE (b0 == 0))
    {
      if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
         goto flush;
      b0 = vlib_get_buffer (vm, bi0);

      memcpy (b0->data, fr->rewrite, vec_len (fr->rewrite));
      b0->current_data = 0;
      b0->current_length = vec_len (fr->rewrite);
      b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
      vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;
      /* $$$ for now, look up in fib-0. Later: arbitrary TX fib */
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = ~0;

      tp = vlib_buffer_get_current (b0);
      ip = (ip4_header_t *) &tp->ip4;
      udp = (udp_header_t *) (ip+1);
      h = (ipfix_message_header_t *)(udp+1);
      s = (ipfix_set_header_t *)(h+1);
      /* FIXUP: message header export_time */
      h->export_time = (u32)
        (((f64)hm->unix_time_0) +
         (vlib_time_now(hm->vlib_main) - hm->vlib_time_0));
      h->export_time = clib_host_to_net_u32(h->export_time);

      /* FIXUP: message header sequence_number */
      h->sequence_number = fr->sequence_number++;
      h->sequence_number = clib_host_to_net_u32 (h->sequence_number);
      next_offset = (u32) (((u8 *)(s+1)) - (u8 *)tp);
      records_this_buffer = 0;
    }

    field_index = 0;

    /* Add IPv6 source address manually */
    memcpy (b0->data + next_offset, &ifix->src_addr.as_u64[0], 8);
    next_offset += 8;
    memcpy (b0->data + next_offset, &ifix->src_addr.as_u64[1], 8);
    next_offset += 8;

    /* Add IPv6 destination address manually */
    memcpy (b0->data + next_offset, &ifix->dst_addr.as_u64[0], 8);
    next_offset += 8;
    memcpy (b0->data + next_offset, &ifix->dst_addr.as_u64[1], 8);
    next_offset += 8;

#if 0
  fformat(stdout, "Template Field %d copied. Value : %d. Length: %d, next_offset: %d\n", field_index, field, length, next_offset);
#endif
#define _(field,mask,item,length)                                       \
    if (clib_bitmap_get (fr->fields_to_send, field_index))   \
    {                                                       \
      if (length == 2)                                     \
      {                                                    \
        u16 tmp;                                             \
        tmp = clib_host_to_net_u16(field);             \
        memcpy (b0->data + next_offset, &tmp, length);       \
      }                                                      \
      else                                                  \
      {   /* Expect only 4 bytes or 2 bytes */             \
        u32 tmp;                                             \
        tmp = clib_host_to_net_u32(field);                 \
        memcpy (b0->data + next_offset, &tmp, length);       \
      }                                                     \
      next_offset += length;                                \
    }
    field_index++;
    foreach_ioam_ipfix_field;
#undef _

    /* Add ioamPathMap manually */
    {
      u16 n;
      u16 t16;
      u32 t32;
      ioam_path_map_t *pm = (ioam_path_map_t *)ifix->path;

      for (n = 0; n < hm->trace_option_elts; n++, pm++)
      {
        /* node id */
        t32 = clib_host_to_net_u32(pm->node_id);
        memcpy(b0->data + next_offset, &t32, 4);
        next_offset += 4;

        /* ingress_if */
        t16 = clib_host_to_net_u16(pm->ingress_if);
        memcpy(b0->data + next_offset, &t16, 2);
        next_offset += 2;

        /* egress_if */
        t16 = clib_host_to_net_u16(pm->egress_if);
        memcpy(b0->data + next_offset, &t16, 2);
        next_offset += 2;
      }
    }
    records_this_buffer++;

    if (next_offset > 1450)
    {
      s->set_id_length = ipfix_set_id_length (260 /* template ID*/,
                            next_offset - 
                            (sizeof (*ip) + sizeof (*udp) + sizeof (*h)));
      b0->current_length = next_offset;
      b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
      tp = vlib_buffer_get_current (b0);
      ip = (ip4_header_t *) &tp->ip4;
      udp = (udp_header_t *) (ip+1);

      sum0 = ip->checksum;
      old_l0 = clib_net_to_host_u16 (ip->length);
      new_l0 = clib_host_to_net_u16 ((u16)next_offset); 
      sum0 = ip_csum_update (sum0, old_l0, new_l0, ip4_header_t,
                                         length /* changed member */);

      ip->checksum = ip_csum_fold (sum0);
      ip->length = new_l0;
      udp->length = clib_host_to_net_u16 (b0->current_length - sizeof (ip));

      to_next[0] = bi0;
      f->n_vectors++;
      to_next++;

      if (f->n_vectors == VLIB_FRAME_SIZE)
      {
        vlib_put_frame_to_node (vm, node_index, f);
        f = vlib_get_frame_to_node (vm, node_index);
        f->n_vectors = 0;
        to_next = vlib_frame_vector_args (f);
      }
      b0 = 0;
      bi0 = ~0;
    }
    /* Reset counters */
    ifix->pkt_counter = 0;
    ifix->bytes_counter = 0;
    ifix->sfc_validated_count = 0;
    ifix->sfc_invalidated_count = 0;
  } /* End of for loop */
#else
  for (i = 0; i < t->nbuckets; i++)
    {
      b = &t->buckets [i];
      if (b->offset == 0)
        continue;
      
      save_v = vnet_classify_get_entry (t, b->offset);
      for (j = 0; j < (1<<b->log2_pages); j++)
        {
          for (k = 0; k < t->entries_per_page; k++)
            {
              v = vnet_classify_entry_at_index 
                (t, save_v, j*t->entries_per_page + k);
              
              if (vnet_classify_entry_is_free (v))
                continue;
              
              /* OK, we have something to send... */
              if (PREDICT_FALSE (b0 == 0))
                {
                  if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
                    goto flush;
                  b0 = vlib_get_buffer (vm, bi0);
                  
                  memcpy (b0->data, fr->rewrite, vec_len (fr->rewrite));
                  b0->current_data = 0;
                  b0->current_length = vec_len (fr->rewrite);
                  b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
                  vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;
                  /* $$$ for now, look up in fib-0. Later: arbitrary TX fib */
                  vnet_buffer (b0)->sw_if_index[VLIB_TX] = ~0;
                  
                  tp = vlib_buffer_get_current (b0);
                  ip = (ip4_header_t *) &tp->ip4;
                  udp = (udp_header_t *) (ip+1);
                  h = (ipfix_message_header_t *)(udp+1);
                  s = (ipfix_set_header_t *)(h+1);
                  
                  /* FIXUP: message header export_time */ 
                  h->export_time = (u32) 
                    (((f64)frm->unix_time_0) + 
                     (vlib_time_now(frm->vlib_main) - frm->vlib_time_0));
                  h->export_time = clib_host_to_net_u32(h->export_time);
                  
                  /* FIXUP: message header sequence_number */
                  h->sequence_number = fr->sequence_number++;
                  h->sequence_number = clib_host_to_net_u32 (h->sequence_number);
                  next_offset = (u32) (((u8 *)(s+1)) - (u8 *)tp);
                  records_this_buffer = 0;
                }
              
              field_index = 0;
              match = (ip4_header_t *) (((u8 *)v->key) - 2);
              ip = match;
              udp = (udp_header_t * )(ip+1);
              
#define _(field,mask,item,length)                                       \
              if (clib_bitmap_get (fr->fields_to_send, field_index))    \
                {                                                       \
                  memcpy (b0->data + next_offset, &field,               \
                          length);                                      \
                  next_offset += length;                                \
                }                                                       \
              field_index++;
              foreach_ioam_ipfix_field;
#undef _
              
              /* Add packetTotalCount manually */
              {
                u64 packets = clib_host_to_net_u64 (v->hits);
                memcpy (b0->data + next_offset, &packets, sizeof (packets));
                next_offset += sizeof (packets);
              }
              records_this_buffer++;
              
              if (next_offset > 1450)
                {
                  s->set_id_length = ipfix_set_id_length (256 /* template ID*/, 
                                                          next_offset - 
                                                          (sizeof (*ip) + sizeof (*udp) +
                                                           sizeof (*h)));
                  b0->current_length = next_offset;
                  b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
                  
                  tp = vlib_buffer_get_current (b0);
                  ip = (ip4_header_t *) &tp->ip4;
                  udp = (udp_header_t *) (ip+1);
                  
                  sum0 = ip->checksum;
                  old_l0 = clib_net_to_host_u16 (ip->length);
                  new_l0 = 
                    clib_host_to_net_u16 ((u16)next_offset);
                  
                  sum0 = ip_csum_update (sum0, old_l0, new_l0, ip4_header_t,
                                         length /* changed member */);
                  
                  ip->checksum = ip_csum_fold (sum0);
                  ip->length = new_l0;
                  udp->length = 
                      clib_host_to_net_u16 (b0->current_length - sizeof (ip));
                  
                  to_next[0] = bi0;
                  f->n_vectors++;
                  to_next++;
                  
                  if (f->n_vectors == VLIB_FRAME_SIZE)
                    {
                      vlib_put_frame_to_node (vm, node_index, f);
                      f = vlib_get_frame_to_node (vm, node_index);
                      f->n_vectors = 0;
                      to_next = vlib_frame_vector_args (f);
                    }
                  b0 = 0;
                  bi0 = ~0;
                }
            }
        }
    }
#endif
  
flush:
  if (b0)
  {
        s->set_id_length = ipfix_set_id_length (260 /* template ID*/, 
                                                next_offset - 
                                                (sizeof (*ip) + sizeof (*udp) +
                                                 sizeof (*h)));
      b0->current_length = next_offset;
      b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
      
      tp = vlib_buffer_get_current (b0);
      ip = (ip4_header_t *) &tp->ip4;
      udp = (udp_header_t *) (ip+1);
      
      sum0 = ip->checksum;
      old_l0 = ip->length;
      new_l0 = clib_host_to_net_u16 ((u16)next_offset);
      
      sum0 = ip_csum_update (sum0, old_l0, new_l0, ip4_header_t,
                             length /* changed member */);
      
      ip->checksum = ip_csum_fold (sum0);
      ip->length = new_l0;
      udp->length = clib_host_to_net_u16 (b0->current_length - sizeof (*ip));

      ASSERT (ip->checksum == ip4_header_checksum (ip));
      
      to_next[0] = bi0;
      f->n_vectors++;
      
      b0 = 0;
      bi0 = ~0;
  }
  
#ifdef ORIG_CODE
  *(t->writer_lock) = 0;
#endif
  return f;
}

static clib_error_t *
set_ioam_ipfix_command_fn (vlib_main_t * vm,
		 unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{
  vnet_flow_report_add_del_args_t args;
  int rv;
  int is_add = 1;
  u32 domain_id = 0;
  flow_report_main_t *frm = &flow_report_main;

#ifdef ORIG_CODE
  ip6_ioam_flow_report_main_t *fsm = &ip6_ioam_flow_report_main;

  domain_id = 0;
  fsm->classify_table_index = ~0;
  memset (&args, 0, sizeof (args));

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "table %d", &fsm->classify_table_index))
      ;
    else if (unformat (input, "domain %d", &domain_id))
      ;
    else if (unformat (input, "del"))
      is_add = 0;
    else
      return clib_error_return (0, "unknown input `%U'",
                                format_unformat_error, input);
  }

  if (fsm->classify_table_index == ~0)
    return clib_error_return (0, "classifier table not specified");

  args.opaque = (void *) fsm;
#endif

  args.rewrite_callback = ip6_ioam_template_rewrite;
  args.flow_data_callback = ip6_ioam_send_flows;
  args.is_add = is_add;
  args.domain_id = domain_id;

  rv = vnet_flow_report_add_del (frm, &args);

  switch (rv)
    {
    case 0:
      break;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      return clib_error_return (0, "registration not found...");
    default:
      return clib_error_return (0, "vnet_flow_report_add_del returned %d", rv);
    }

  return 0;
}

VLIB_CLI_COMMAND (set_ioam_ipfix_command, static) = {
  .path = "set ioam ipfix",
  .short_help = "set ioam ipfix <table-id>",
  .function = set_ioam_ipfix_command_fn,
};

static clib_error_t *
ip6_ioam_flow_report_init (vlib_main_t *vm)
{
  clib_error_t * error;

  if ((error = vlib_call_init_function (vm, flow_report_init)))
    return error;

  return 0;
}

VLIB_INIT_FUNCTION (ip6_ioam_flow_report_init);

void ip6_ioam_flow_report_reference (void) { }
