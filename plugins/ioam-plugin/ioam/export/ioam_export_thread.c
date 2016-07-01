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
/*
 * flow_report.c
 */
#include <vnet/flow/flow_report.h>
#include <vnet/api_errno.h>

int send_template_packet (flow_report_main_t *frm, 
                          flow_report_t *fr,
                          u32 * buffer_indexp)
{
  u32 bi0;
  vlib_buffer_t * b0;
  ip4_ipfix_template_packet_t * tp;
  ipfix_message_header_t * h;
  ip4_header_t * ip;
  udp_header_t * udp;
  vlib_main_t * vm = frm->vlib_main;

  ASSERT (buffer_indexp);

  if (fr->update_rewrite || fr->rewrite == 0)
    {
      if (frm->ipfix_collector.as_u32 == 0 
          || frm->src_address.as_u32 == 0)
        {
          clib_warning ("no collector: disabling flow collector process");
          vlib_node_set_state (frm->vlib_main, flow_report_process_node.index,
                               VLIB_NODE_STATE_DISABLED);
          return -1;
        }
      vec_free (fr->rewrite);
      fr->update_rewrite = 1;
    }

  if (fr->update_rewrite)
    {
      fr->rewrite = fr->rewrite_callback (frm, fr,
                                          &frm->ipfix_collector,
                                          &frm->src_address);
      fr->update_rewrite = 0;
    }

  if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
    return -1;
  
  b0 = vlib_get_buffer (vm, bi0);

  ASSERT (vec_len (fr->rewrite) < VLIB_BUFFER_DEFAULT_FREE_LIST_BYTES);
    
  clib_memcpy (b0->data, fr->rewrite, vec_len (fr->rewrite));
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

  /* FIXUP: message header export_time */ 
  h->export_time = (u32) 
    (((f64)frm->unix_time_0) + 
     (vlib_time_now(frm->vlib_main) - frm->vlib_time_0));
  h->export_time = clib_host_to_net_u32(h->export_time);

  /* FIXUP: message header sequence_number. Templates do not increase it */
  h->sequence_number = clib_host_to_net_u32(fr->sequence_number);

  /* FIXUP: udp length */
  udp->length = clib_host_to_net_u16 (b0->current_length - sizeof (*ip));

  *buffer_indexp = bi0;
  return 0;
}

static uword
flow_report_process (vlib_main_t * vm,
                     vlib_node_runtime_t * rt,
                     vlib_frame_t * f)
{
  flow_report_main_t * frm = &flow_report_main;
  flow_report_t * fr;
  u32 ip4_lookup_node_index;
  vlib_node_t * ip4_lookup_node;
  vlib_frame_t * nf = 0;
  u32 template_bi;
  u32 * to_next;
  int send_template;
  f64 now;
  int rv;
  uword event_type;
  uword *event_data = 0;

  /* Wait for Godot... */
  vlib_process_wait_for_event_or_clock (vm, 1e9);
  event_type = vlib_process_get_events (vm, &event_data);
  if (event_type != 1)
      clib_warning ("bogus kickoff event received, %d", event_type);
  vec_reset_length (event_data);

  /* Enqueue pkts to ip4-lookup */
  ip4_lookup_node = vlib_get_node_by_name (vm, (u8 *) "ip4-lookup");
  ip4_lookup_node_index = ip4_lookup_node->index;

  while (1) 
    {
      vlib_process_suspend (vm, 5.0);
      
      vec_foreach (fr, frm->reports)
        {
          now = vlib_time_now (vm);

          /* Need to send a template packet? */
          send_template = now > (fr->last_template_sent + 20.0);
          send_template += fr->last_template_sent == 0;
          template_bi = ~0;
	  rv = 0;

          if (send_template)
            rv = send_template_packet (frm, fr, &template_bi);

          if (rv < 0)
            continue;

          nf = vlib_get_frame_to_node (vm, ip4_lookup_node_index);
          nf->n_vectors = 0;
          to_next = vlib_frame_vector_args (nf);

          if (template_bi != ~0)
            {
              to_next[0] = template_bi;
              to_next++;
              nf->n_vectors++;
            }
      
          nf = fr->flow_data_callback (frm, fr, 
                                       nf, to_next, ip4_lookup_node_index);
          if (nf)
            vlib_put_frame_to_node (vm, ip4_lookup_node_index, nf);
        }
    }

  return 0; /* not so much */
}

VLIB_REGISTER_NODE (flow_report_process_node) = {
    .function = flow_report_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "flow-report-process",
};

int vnet_flow_report_add_del (flow_report_main_t *frm, 
                              vnet_flow_report_add_del_args_t *a)
{
  int i;
  int found_index = ~0;
  flow_report_t *fr;
  
  for (i = 0; i < vec_len(frm->reports); i++)
    {
      fr = vec_elt_at_index (frm->reports, i);
      if (fr->opaque == a->opaque
          && fr->rewrite_callback == a->rewrite_callback
          && fr->flow_data_callback == a->flow_data_callback)
        {
          found_index = i;
          break;
        }
    }

  if (a->is_add == 0)
    {
      if (found_index != ~0)
        {
          vec_delete (frm->reports, 1, found_index);
          return 0;
        }
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  vec_add2 (frm->reports, fr, 1);

  fr->sequence_number = 0;
  fr->domain_id = a->domain_id;
  fr->update_rewrite = 1;
  fr->opaque = a->opaque;
  fr->rewrite_callback = a->rewrite_callback;
  fr->flow_data_callback = a->flow_data_callback;
  
  return 0;
}

static clib_error_t *
set_ipfix_command_fn (vlib_main_t * vm,
		 unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{
  flow_report_main_t * frm = &flow_report_main;
  ip4_address_t collector, src;
  
  collector.as_u32 = 0;
  src.as_u32 = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "collector %U", unformat_ip4_address, &collector))
      ;
    else if (unformat (input, "src %U", unformat_ip4_address, &src))
      ;
    else
      break;
  }
  
  if (collector.as_u32 == 0)
    return clib_error_return (0, "collector address required");

  if (src.as_u32 == 0)
    return clib_error_return (0, "src address required");

  frm->ipfix_collector.as_u32 = collector.as_u32;
  frm->src_address.as_u32 = src.as_u32;
  
  vlib_cli_output (vm, "Collector %U, src address %U",
                   format_ip4_address, &frm->ipfix_collector,
                   format_ip4_address, &frm->src_address);
  
  /* Turn on the flow reporting process */
  vlib_process_signal_event (vm, flow_report_process_node.index,
                             1, 0);
  return 0;
}

VLIB_CLI_COMMAND (set_ipfix_command, static) = {
    .path = "set ipfix",
    .short_help = "set ipfix collector <ip4-address> src <ip4-address>",
    .function = set_ipfix_command_fn,
};

static clib_error_t * 
flow_report_init (vlib_main_t *vm)
{
  flow_report_main_t * frm = &flow_report_main;

  frm->vlib_main = vm;
  frm->vnet_main = vnet_get_main();

  return 0;
}

VLIB_INIT_FUNCTION (flow_report_init)
