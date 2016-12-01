/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#include <vppinfra/error.h>
#include <vnet/ip/ip.h>
#include <ioam/export-common/ioam_export.h>
#include <ioam/encap/ip6_ioam_trace.h>
#include <ioam/encap/ip6_ioam_pot.h>
#include <ioam/lib-pot/pot_util.h>
#include <ioam/encap/ip6_ioam_e2e.h>
#include <ioam/analyse/ioam_analyse.h>
#include <ioam/analyse/ip6/ip6_ioam_analyse.h>
#include <vnet/plugin/plugin.h>

typedef struct
{
  u32 next_index;
  u32 flow_id;
} analyse_trace_t;

vlib_node_registration_t analyse_node_local;
vlib_node_registration_t analyse_node_remote;

#define foreach_analyse_error \
_(ANALYSED, "Packets analysed for summarization") \
_(FAILED, "Packets analysis failed") \

typedef enum
{
#define _(sym,str) ANALYSE_ERROR_##sym,
  foreach_analyse_error
#undef _
    ANALYSE_N_ERROR,
} analyse_error_t;

static char *analyse_error_strings[] = {
#define _(sym,string) string,
  foreach_analyse_error
#undef _
};

typedef enum
{
  ANALYSE_NEXT_IP4_LOOKUP,
  ANALYSE_NEXT_IP4_DROP,
  ANALYSE_N_NEXT,
} analyse_next_t;

ip6_ioam_analyser_main_t ioam_analyser_main;

/* packet trace format function */
static u8 *
format_analyse_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  analyse_trace_t *t = va_arg (*args, analyse_trace_t *);

  s = format (s, "IP6-ioam-analyse: flow_id %d, next index %d",
	      t->flow_id, t->next_index);
  return s;
}

always_inline u8
ioam_analyse_hbh (u32 flow_id,
		  ip6_hop_by_hop_header_t * hbh0,
		  ip6_hop_by_hop_option_t * opt0,
		  ip6_hop_by_hop_option_t * limit0, u16 len)
{
  ip6_ioam_analyser_main_t *am = &ioam_analyser_main;
  u8 type0;
  u8 error0 = 0;

  while (opt0 < limit0)
    {
      type0 = opt0->type;
      switch (type0)
	{
	case 0:		/* Pad1 */
	  opt0 = (ip6_hop_by_hop_option_t *) ((u8 *) opt0) + 1;
	  continue;
	case 1:		/* PadN */
	  break;
	default:
	  if (am->analyse_hbh_handler[type0])
	    {
	      if (PREDICT_TRUE
		  ((*am->analyse_hbh_handler[type0]) (flow_id, opt0,
						      len) < 0))
		{
		  error0 = ANALYSE_ERROR_FAILED;
		  return (error0);
		}
	    }
	}
      opt0 =
	(ip6_hop_by_hop_option_t *) (((u8 *) opt0) + opt0->length +
				     sizeof (ip6_hop_by_hop_option_t));
    }
  return (error0);
}

/**
 * @brief IPv6 InBandOAM Analyse node.
 * @node ip6-hbh-analyse-local, ip6-hbh-analyse-remote
 *
 * This function receives IP-FIX packets containing IPv6-iOAM records, analyses
 * them and collects/aggregates the statistics.
 *
 * @param vm    vlib_main_t corresponding to the current thread.
 * @param node  vlib_node_runtime_t data for this node.
 * @param frame vlib_frame_t whose contents should be dispatched.
 *
 * @par Graph mechanics: buffer, next index usage
 *
 * <em>Uses:</em>
 * - <code>vlib_buffer_get_current(p0)</code>
 *     - Walks on each ioam record present in IP-Fix record, analyse them and
 *       store the statistics.
 *
 * <em>Next Index:</em>
 * - Dispatches the packet to ip4-lookup if executed under ip6-hbh-analyse-local
 *   node context and to ip4-drop if executed under ip6-hbh-analyse-remote node
 *   context.
 */
static uword
ip6_ioam_analyse_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
			  vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  analyse_next_t next_index;
  u32 pkts_analysed = 0;
  u32 pkts_failed = 0;
  u8 remote = 0;
  u32 next0 = ANALYSE_NEXT_IP4_LOOKUP;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  if (PREDICT_FALSE (analyse_node_remote.index == node->node_index))
    {
      remote = 1;
      next0 = ANALYSE_NEXT_IP4_DROP;
    }

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *p0;
	  ip4_header_t *ip40;
	  u8 *data, *limit;
	  u16 num_ioam_records;

	  /* speculatively enqueue p0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, bi0);
	  if (PREDICT_FALSE (remote))
	    {
	      vlib_buffer_advance (p0, -(word) (sizeof (udp_header_t) +
						sizeof (ip4_header_t) +
						sizeof
						(ipfix_message_header_t) +
						sizeof (ipfix_set_header_t)));
	    }
	  data = (u8 *) vlib_buffer_get_current (p0);
	  ip40 = (ip4_header_t *) vlib_buffer_get_current (p0);
	  limit = data + clib_net_to_host_u16 (ip40->length);
	  data += sizeof (ip4_header_t) + sizeof (udp_header_t)
	    + sizeof (ipfix_message_header_t) + sizeof (ipfix_set_header_t);

	  num_ioam_records = (limit - data) / DEFAULT_EXPORT_SIZE;

	  while (num_ioam_records >= 4)
	    {
	      /* Prefetch next 2 ioam records */
	      {
		CLIB_PREFETCH (data + (2 * DEFAULT_EXPORT_SIZE),
			       (DEFAULT_EXPORT_SIZE), LOAD);
		CLIB_PREFETCH (data + (3 * DEFAULT_EXPORT_SIZE),
			       (DEFAULT_EXPORT_SIZE), LOAD);
	      }

	      num_ioam_records -= 2;

	      ip6_header_t *ip60, *ip61;
	      ip6_hop_by_hop_header_t *hbh0, *hbh1;
	      ip6_hop_by_hop_option_t *opt0, *limit0, *opt1, *limit1;
	      u32 flow_id0, flow_id1;
	      u8 error0, error1;
	      ioam_analyser_data_t *data0, *data1;
	      u16 p_len0, p_len1;

	      ip60 = (ip6_header_t *) data;
	      ip61 = (ip6_header_t *) (data + DEFAULT_EXPORT_SIZE);

	      data += (2 * DEFAULT_EXPORT_SIZE);

	      hbh0 = (ip6_hop_by_hop_header_t *) (ip60 + 1);
	      hbh1 = (ip6_hop_by_hop_header_t *) (ip61 + 1);

	      opt0 = (ip6_hop_by_hop_option_t *) (hbh0 + 1);
	      opt1 = (ip6_hop_by_hop_option_t *) (hbh1 + 1);

	      limit0 =
		(ip6_hop_by_hop_option_t *) ((u8 *) hbh0 +
					     ((hbh0->length + 1) << 3));
	      limit1 =
		(ip6_hop_by_hop_option_t *) ((u8 *) hbh1 +
					     ((hbh1->length + 1) << 3));

	      flow_id0 =
		clib_net_to_host_u32
		(ip60->ip_version_traffic_class_and_flow_label) & 0xFFFFF;
	      flow_id1 =
		clib_net_to_host_u32
		(ip61->ip_version_traffic_class_and_flow_label) & 0xFFFFF;

	      p_len0 = clib_net_to_host_u16 (ip60->payload_length);
	      p_len1 = clib_net_to_host_u16 (ip61->payload_length);

	      error0 =
		ioam_analyse_hbh (flow_id0, hbh0, opt0, limit0, p_len0);
	      error1 =
		ioam_analyse_hbh (flow_id1, hbh1, opt1, limit1, p_len0);

	      if (PREDICT_TRUE ((error0 == 0) && (error1 == 0)))
		{
		  pkts_analysed += 2;
		  data0 = ioam_analyse_get_data_from_flow_id (flow_id0);
		  data1 = ioam_analyse_get_data_from_flow_id (flow_id1);

		  while (__sync_lock_test_and_set (data0->writer_lock, 1))
		    ;
		  data0->pkt_counter++;
		  data0->bytes_counter += p_len0;
		  *(data0->writer_lock) = 0;

		  while (__sync_lock_test_and_set (data1->writer_lock, 1))
		    ;
		  data1->pkt_counter++;
		  data1->bytes_counter += p_len1;
		  *(data1->writer_lock) = 0;
		}
	      else if (error0 == 0)
		{
		  pkts_analysed++;
		  pkts_failed++;

		  data0 = ioam_analyse_get_data_from_flow_id (flow_id0);
		  while (__sync_lock_test_and_set (data0->writer_lock, 1))
		    ;
		  data0->pkt_counter++;
		  data0->bytes_counter += p_len0;
		  *(data0->writer_lock) = 0;
		}
	      else if (error1 == 0)
		{
		  pkts_analysed++;
		  pkts_failed++;

		  data1 = ioam_analyse_get_data_from_flow_id (flow_id1);
		  while (__sync_lock_test_and_set (data1->writer_lock, 1))
		    ;
		  data1->pkt_counter++;
		  data1->bytes_counter += p_len1;
		  *(data1->writer_lock) = 0;
		}
	      else
		pkts_failed += 2;
	    }

	  while (num_ioam_records > 0)
	    {
	      num_ioam_records--;

	      ip6_header_t *ip60;
	      ip6_hop_by_hop_header_t *hbh0;
	      ip6_hop_by_hop_option_t *opt0, *limit0;
	      u32 flow_id0;
	      u8 error0;
	      ioam_analyser_data_t *data0;
	      u16 p_len0;

	      ip60 = (ip6_header_t *) data;
	      data += (1 * DEFAULT_EXPORT_SIZE);
	      hbh0 = (ip6_hop_by_hop_header_t *) (ip60 + 1);
	      opt0 = (ip6_hop_by_hop_option_t *) (hbh0 + 1);
	      limit0 =
		(ip6_hop_by_hop_option_t *) ((u8 *) hbh0 +
					     ((hbh0->length + 1) << 3));

	      flow_id0 =
		clib_net_to_host_u32
		(ip60->ip_version_traffic_class_and_flow_label) & 0xFFFFF;
	      p_len0 = clib_net_to_host_u16 (ip60->payload_length);
	      error0 =
		ioam_analyse_hbh (flow_id0, hbh0, opt0, limit0, p_len0);

	      if (PREDICT_TRUE (error0 == 0))
		{
		  pkts_analysed++;
		  data0 = ioam_analyse_get_data_from_flow_id (flow_id0);
		  while (__sync_lock_test_and_set (data0->writer_lock, 1))
		    ;
		  data0->pkt_counter++;
		  data0->bytes_counter +=
		    clib_net_to_host_u16 (ip60->payload_length);
		  *(data0->writer_lock) = 0;
		}
	      else
		pkts_failed++;
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index, ANALYSE_ERROR_ANALYSED,
			       pkts_analysed);

  if (PREDICT_FALSE (pkts_failed))
    vlib_node_increment_counter (vm, node->node_index, ANALYSE_ERROR_FAILED,
				 pkts_failed);

  return frame->n_vectors;
}

int
ip6_ioam_analyse_hbh_trace_internal (u32 flow_id,
				     ip6_hop_by_hop_option_t * opt, u16 len)
{
  ioam_analyser_data_t *data;
  ioam_trace_option_t *trace = (ioam_trace_option_t *) opt;

  data = ioam_analyse_get_data_from_flow_id (flow_id);
  ASSERT (data != NULL);

  (void) ip6_ioam_analyse_hbh_trace (data, &trace->trace_hdr, len,
				     (trace->hdr.length - 2)
				     /*ioam_trace_type,data_list_elts_left */
    );
  return 0;
}

int
ip6_ioam_analyse_hbh_pot (u32 flow_id, ip6_hop_by_hop_option_t * opt0,
			  u16 len)
{

  ioam_pot_option_t *pot0;
  u64 random = 0;
  u64 cumulative = 0;
  pot_profile *pot_profile = 0;
  int ret;
  ioam_analyser_data_t *data;

  data = ioam_analyse_get_data_from_flow_id (flow_id);

  pot0 = (ioam_pot_option_t *) opt0;
  random = clib_net_to_host_u64 (pot0->random);
  cumulative = clib_net_to_host_u64 (pot0->cumulative);
  pot_profile = pot_profile_get_active ();
  ret = pot_validate (pot_profile, cumulative, random);

  while (__sync_lock_test_and_set (data->writer_lock, 1))
    ;

  (0 == ret) ? (data->pot_data.sfc_validated_count++) :
    (data->pot_data.sfc_invalidated_count++);

  *(data->writer_lock) = 0;
  return 0;
}

int
ip6_ioam_analyse_hbh_e2e_internal (u32 flow_id, ip6_hop_by_hop_option_t * opt,
				   u16 len)
{
  ioam_analyser_data_t *data;
  ioam_e2e_option_t *e2e;

  data = ioam_analyse_get_data_from_flow_id (flow_id);
  e2e = (ioam_e2e_option_t *) opt;
  ip6_ioam_analyse_hbh_e2e (data, &e2e->e2e_hdr, len);
  return 0;
}

int
ip6_ioam_analyse_register_hbh_handler (u8 option,
				       int options (u32 flow_id,
						    ip6_hop_by_hop_option_t *
						    opt, u16 len))
{
  ip6_ioam_analyser_main_t *am = &ioam_analyser_main;

  ASSERT (option < ARRAY_LEN (am->analyse_hbh_handler));

  /* Already registered */
  if (am->analyse_hbh_handler[option])
    return (-1);

  am->analyse_hbh_handler[option] = options;

  return (0);
}

int
ip6_ioam_analyse_unregister_hbh_handler (u8 option)
{
  ip6_ioam_analyser_main_t *am = &ioam_analyser_main;

  ASSERT (option < ARRAY_LEN (am->analyse_hbh_handler));

  /* Not registered */
  if (!am->analyse_hbh_handler[option])
    return (-1);

  am->analyse_hbh_handler[option] = NULL;
  return (0);
}

void
ip6_ioam_analyse_register_handlers ()
{
  ip6_ioam_analyse_register_hbh_handler (HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST,
					 ip6_ioam_analyse_hbh_trace_internal);
  ip6_ioam_analyse_register_hbh_handler
    (HBH_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT, ip6_ioam_analyse_hbh_pot);
  ip6_ioam_analyse_register_hbh_handler (HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE,
					 ip6_ioam_analyse_hbh_e2e_internal);
}

void
ip6_ioam_analyse_unregister_handlers ()
{
  ip6_ioam_analyse_unregister_hbh_handler
    (HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST);
  ip6_ioam_analyse_unregister_hbh_handler
    (HBH_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT);
  ip6_ioam_analyse_unregister_hbh_handler (HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE);
}

/* *INDENT-OFF* */

/*
 * Node for IP6 analyse - packets
 */
VLIB_REGISTER_NODE (analyse_node_local) = {
  .function = ip6_ioam_analyse_node_fn,
  .name = "ip6-hbh-analyse-local",
  .vector_size = sizeof (u32),
  .format_trace = format_analyse_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (analyse_error_strings),
  .error_strings = analyse_error_strings,
  .n_next_nodes = ANALYSE_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes = {
    [ANALYSE_NEXT_IP4_LOOKUP] = "ip4-lookup",
    [ANALYSE_NEXT_IP4_DROP] = "ip4-drop",
  },
};

/*
 * Node for IP6 analyse - packets
 */
VLIB_REGISTER_NODE (analyse_node_remote) =
{
  .function = ip6_ioam_analyse_node_fn,
  .name = "ip6-hbh-analyse-remote",
  .vector_size = sizeof (u32),
  .format_trace = format_analyse_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (analyse_error_strings),
  .error_strings = analyse_error_strings,
  .n_next_nodes = ANALYSE_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes = {
    [ANALYSE_NEXT_IP4_LOOKUP] = "ip4-lookup",
    [ANALYSE_NEXT_IP4_DROP] = "ip4-drop",
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
