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

#ifndef PLUGINS_IOAM_PLUGIN_IOAM_ANALYSE_IOAM_ANALYSE_H_
#define PLUGINS_IOAM_PLUGIN_IOAM_ANALYSE_IOAM_ANALYSE_H_

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/types.h>
#include <ioam/lib-e2e/e2e_util.h>
#include <ioam/lib-trace/trace_util.h>
#include <ioam/lib-trace/trace_config.h>

#define IOAM_FLOW_TEMPLATE_ID    260
#define IOAM_TRACE_MAX_NODES      10
#define IOAM_MAX_PATHS_PER_FLOW   10

typedef struct
{
  u16 ingress_if;
  u16 egress_if;
  u32 node_id;
  u32 state_up;
} ioam_path_map_t;

/** @brief Analysed iOAM trace data.
    @note cache aligned.
*/
typedef struct
{
  /** No of nodes in path. */
  u8 num_nodes;

  /** Data contained in trace - NodeId, TTL, Ingress & Egress Link, Timestamp. */
  u8 trace_type;

  /** Flag to indicate whether node is allocated. */
  u8 is_free;

  u8 pad[5];

  /** Actual PATH flow has taken. */
  ioam_path_map_t path[IOAM_TRACE_MAX_NODES];

  /** Num of pkts in the flow going over path. */
  u32 pkt_counter;

  /** Num of bytes in the flow going over path. */
  u32 bytes_counter;

  /** Minumum Dealay for the flow. */
  u32 min_delay;

  /** Maximum Dealay for the flow. */
  u32 max_delay;

  /** Average Dealay for the flow. */
  u32 mean_delay;

  u32 reserve;
} ioam_analyse_trace_record;

typedef struct
{
  ioam_analyse_trace_record path_data[IOAM_MAX_PATHS_PER_FLOW];
} ioam_analyse_trace_data;

/** @brief Analysed iOAM pot data.
    @note cache aligned.
*/
typedef struct
{
  /** Number of packets validated (passes through the service chain)
      within the timestamps. */
  u32 sfc_validated_count;

  /** Number of packets invalidated (failed through the service chain)
      within the timestamps. */
  u32 sfc_invalidated_count;
} ioam_analyse_pot_data;

/** @brief Analysed iOAM data.
    @note cache aligned.
*/
typedef struct ioam_analyser_data_t_
{
  u8 is_free;
  u8 pad[3];

  /** Num of pkts sent for this flow. */
  u32 pkt_sent;

  /** Num of pkts matching this flow. */
  u32 pkt_counter;

  /** Num of bytes matching this flow. */
  u32 bytes_counter;

  /** Analysed iOAM trace data. */
  ioam_analyse_trace_data trace_data;

  /** Analysed iOAM pot data. */
  ioam_analyse_pot_data pot_data;

  /** Analysed iOAM seqno data. */
  seqno_rx_info seqno_data;

  /** Cache of previously analysed data, useful for export. */
  struct ioam_analyser_data_t_ *chached_data_list;

  /** Lock to since we use this to export the data in other thread. */
  volatile u32 *writer_lock;
} ioam_analyser_data_t;

always_inline f64
ip6_ioam_analyse_calc_delay (ioam_trace_hdr_t * trace, u16 trace_len,
			     u8 oneway)
{
  u16 size_of_all_traceopts;
  u8 size_of_traceopt_per_node;
  u8 num_nodes;
  u32 *start_elt, *end_elt, *uturn_elt;;
  u32 start_time, end_time;
  u8 done = 0;

  size_of_traceopt_per_node = fetch_trace_data_size (trace->ioam_trace_type);
  // Unknown trace type
  if (size_of_traceopt_per_node == 0)
    return 0;
  size_of_all_traceopts = trace_len;	/*ioam_trace_type,data_list_elts_left */

  num_nodes = (u8) (size_of_all_traceopts / size_of_traceopt_per_node);
  if ((num_nodes == 0) || (num_nodes <= trace->data_list_elts_left))
    return 0;

  num_nodes -= trace->data_list_elts_left;

  start_elt = trace->elts;
  end_elt =
    trace->elts +
    (u32) ((size_of_traceopt_per_node / sizeof (u32)) * (num_nodes - 1));

  if (oneway && (trace->ioam_trace_type & BIT_TTL_NODEID))
    {
      done = 0;
      do
	{
	  uturn_elt = start_elt - size_of_traceopt_per_node / sizeof (u32);

	  if ((clib_net_to_host_u32 (*start_elt) >> 24) <=
	      (clib_net_to_host_u32 (*uturn_elt) >> 24))
	    done = 1;
	}
      while (!done && (start_elt = uturn_elt) != end_elt);
    }
  if (trace->ioam_trace_type & BIT_TTL_NODEID)
    {
      start_elt++;
      end_elt++;
    }
  if (trace->ioam_trace_type & BIT_ING_INTERFACE)
    {
      start_elt++;
      end_elt++;
    }
  start_time = clib_net_to_host_u32 (*start_elt);
  end_time = clib_net_to_host_u32 (*end_elt);

  return (f64) (end_time - start_time);
}

always_inline void
ip6_ioam_analyse_set_paths_down (ioam_analyser_data_t * data)
{
  ioam_analyse_trace_data *trace_data;
  ioam_analyse_trace_record *trace_record;
  ioam_path_map_t *path;
  u8 k, i;

  while (__sync_lock_test_and_set (data->writer_lock, 1))
    ;

  trace_data = &data->trace_data;

  for (i = 0; i < IOAM_MAX_PATHS_PER_FLOW; i++)
    {
      trace_record = trace_data->path_data + i;

      if (trace_record->is_free)
	continue;

      path = trace_record->path;

      for (k = 0; k < trace_record->num_nodes; k++)
	path[k].state_up = 0;
    }
  *(data->writer_lock) = 0;
}

always_inline void
ip6_ioam_analyse_hbh_trace_loopback (ioam_analyser_data_t * data,
				     ioam_trace_hdr_t * trace, u16 trace_len)
{
  ioam_analyse_trace_data *trace_data;
  ioam_analyse_trace_record *trace_record;
  ioam_path_map_t *path;
  u8 i, j, k, num_nodes, max_nodes;
  u8 *ptr;
  u32 nodeid;
  u16 ingress_if, egress_if;
  u16 size_of_traceopt_per_node;
  u16 size_of_all_traceopts;

  while (__sync_lock_test_and_set (data->writer_lock, 1))
    ;

  trace_data = &data->trace_data;

  size_of_traceopt_per_node = fetch_trace_data_size (trace->ioam_trace_type);
  if (0 == size_of_traceopt_per_node)
    goto end;

  size_of_all_traceopts = trace_len;

  ptr = (u8 *) trace->elts;
  max_nodes = (u8) (size_of_all_traceopts / size_of_traceopt_per_node);
  num_nodes = max_nodes - trace->data_list_elts_left;

  for (i = 0; i < IOAM_MAX_PATHS_PER_FLOW; i++)
    {
      trace_record = trace_data->path_data + i;
      path = trace_record->path;

      if (trace_record->is_free)
	continue;

      for (j = max_nodes, k = 0; k < num_nodes; j--, k++)
	{
	  ptr =
	    (u8 *) ((u8 *) trace->elts +
		    (size_of_traceopt_per_node * (j - 1)));

	  nodeid = clib_net_to_host_u32 (*((u32 *) ptr)) & 0x00ffffff;
	  ptr += 4;

	  if (nodeid != path[k].node_id)
	    goto end;

	  if ((trace->ioam_trace_type == TRACE_TYPE_IF_TS_APP) ||
	      (trace->ioam_trace_type == TRACE_TYPE_IF))
	    {
	      ingress_if = clib_net_to_host_u16 (*((u16 *) ptr));
	      ptr += 2;
	      egress_if = clib_net_to_host_u16 (*((u16 *) ptr));
	      if ((ingress_if != path[k].ingress_if) ||
		  (egress_if != path[k].egress_if))
		{
		  goto end;
		}
	    }
	  /* Found Match - set path hop state to up */
	  path[k].state_up = 1;
	}
    }
end:
  *(data->writer_lock) = 0;
}

always_inline int
ip6_ioam_analyse_hbh_trace (ioam_analyser_data_t * data,
			    ioam_trace_hdr_t * trace, u16 pak_len,
			    u16 trace_len)
{
  ioam_analyse_trace_data *trace_data;
  u16 size_of_traceopt_per_node;
  u16 size_of_all_traceopts;
  u8 i, j, k, num_nodes, max_nodes;
  u8 *ptr;
  u32 nodeid;
  u16 ingress_if, egress_if;
  ioam_path_map_t *path = NULL;
  ioam_analyse_trace_record *trace_record;

  while (__sync_lock_test_and_set (data->writer_lock, 1))
    ;

  trace_data = &data->trace_data;

  size_of_traceopt_per_node = fetch_trace_data_size (trace->ioam_trace_type);
  // Unknown trace type
  if (size_of_traceopt_per_node == 0)
    goto DONE;
  size_of_all_traceopts = trace_len;

  ptr = (u8 *) trace->elts;
  max_nodes = (u8) (size_of_all_traceopts / size_of_traceopt_per_node);
  num_nodes = max_nodes - trace->data_list_elts_left;

  for (i = 0; i < IOAM_MAX_PATHS_PER_FLOW; i++)
    {
      trace_record = trace_data->path_data + i;

      if (trace_record->is_free ||
	  (num_nodes != trace_record->num_nodes) ||
	  (trace->ioam_trace_type != trace_record->trace_type))
	continue;

      path = trace_record->path;

      for (j = max_nodes, k = 0; k < num_nodes; j--, k++)
	{
	  ptr =
	    (u8 *) ((u8 *) trace->elts +
		    (size_of_traceopt_per_node * (j - 1)));

	  nodeid = clib_net_to_host_u32 (*((u32 *) ptr)) & 0x00ffffff;
	  ptr += 4;

	  if (nodeid != path[k].node_id)
	    break;

	  if ((trace->ioam_trace_type == TRACE_TYPE_IF_TS_APP) ||
	      (trace->ioam_trace_type == TRACE_TYPE_IF))
	    {
	      ingress_if = clib_net_to_host_u16 (*((u16 *) ptr));
	      ptr += 2;
	      egress_if = clib_net_to_host_u16 (*((u16 *) ptr));
	      if ((ingress_if != path[k].ingress_if) ||
		  (egress_if != path[k].egress_if))
		{
		  break;
		}
	    }
	}

      if (k == num_nodes)
	{
	  goto found_match;
	}
    }

  for (i = 0; i < IOAM_MAX_PATHS_PER_FLOW; i++)
    {
      trace_record = trace_data->path_data + i;
      if (trace_record->is_free)
	{
	  trace_record->is_free = 0;
	  trace_record->num_nodes = num_nodes;
	  trace_record->trace_type = trace->ioam_trace_type;
	  path = trace_data->path_data[i].path;
	  trace_record->pkt_counter = 0;
	  trace_record->bytes_counter = 0;
	  trace_record->min_delay = 0xFFFFFFFF;
	  trace_record->max_delay = 0;
	  trace_record->mean_delay = 0;
	  break;
	}
    }

  for (j = max_nodes, k = 0; k < num_nodes; j--, k++)
    {
      ptr =
	(u8 *) ((u8 *) trace->elts + (size_of_traceopt_per_node * (j - 1)));

      path[k].node_id = clib_net_to_host_u32 (*((u32 *) ptr)) & 0x00ffffff;
      ptr += 4;

      if ((trace->ioam_trace_type == TRACE_TYPE_IF_TS_APP) ||
	  (trace->ioam_trace_type == TRACE_TYPE_IF))
	{
	  path[k].ingress_if = clib_net_to_host_u16 (*((u16 *) ptr));
	  ptr += 2;
	  path[k].egress_if = clib_net_to_host_u16 (*((u16 *) ptr));
	}
    }

found_match:
  /* Set path state to UP */
  for (k = 0; k < num_nodes; k++)
    path[k].state_up = 1;

  trace_record->pkt_counter++;
  trace_record->bytes_counter += pak_len;
  if (trace->ioam_trace_type & BIT_TIMESTAMP)
    {
      /* Calculate time delay */
      u32 delay = (u32) ip6_ioam_analyse_calc_delay (trace, trace_len, 0);
      if (delay < trace_record->min_delay)
	trace_record->min_delay = delay;
      else if (delay > trace_record->max_delay)
	trace_record->max_delay = delay;

      u64 sum = (trace_record->mean_delay * data->seqno_data.rx_packets);
      trace_record->mean_delay =
	(u32) ((sum + delay) / (data->seqno_data.rx_packets + 1));
    }
DONE:
  *(data->writer_lock) = 0;
  return 0;
}

always_inline int
ip6_ioam_analyse_hbh_e2e (ioam_analyser_data_t * data,
			  ioam_e2e_packet_t * e2e, u16 len)
{
  while (__sync_lock_test_and_set (data->writer_lock, 1))
    ;

  ioam_analyze_seqno (&data->seqno_data,
		      (u64) clib_net_to_host_u32 (e2e->e2e_data));

  *(data->writer_lock) = 0;
  return 0;
}

always_inline u8 *
format_path_map (u8 * s, va_list * args)
{
  ioam_path_map_t *pm = va_arg (*args, ioam_path_map_t *);
  u32 num_of_elts = va_arg (*args, u32);
  u32 i;

  for (i = 0; i < num_of_elts; i++)
    {
      s =
	format (s,
		"node_id: 0x%x, ingress_if: 0x%x, egress_if:0x%x, state:%s\n",
		pm->node_id, pm->ingress_if, pm->egress_if,
		pm->state_up ? "UP" : "DOWN");
      pm++;
    }

  return (s);
}

always_inline u8 *
print_analyse_flow (u8 * s, ioam_analyser_data_t * record)
{
  int j;
  ioam_analyse_trace_record *trace_record;

  s = format (s, "pkt_sent : %u\n", record->pkt_sent);
  s = format (s, "pkt_counter : %u\n", record->pkt_counter);
  s = format (s, "bytes_counter : %u\n", record->bytes_counter);

  s = format (s, "Trace data: \n");

  for (j = 0; j < IOAM_MAX_PATHS_PER_FLOW; j++)
    {
      trace_record = record->trace_data.path_data + j;
      if (trace_record->is_free)
	continue;

      s = format (s, "path_map:\n%U", format_path_map,
		  trace_record->path, trace_record->num_nodes);
      s = format (s, "pkt_counter: %u\n", trace_record->pkt_counter);
      s = format (s, "bytes_counter: %u\n", trace_record->bytes_counter);

      s = format (s, "min_delay: %u\n", trace_record->min_delay);
      s = format (s, "max_delay: %u\n", trace_record->max_delay);
      s = format (s, "mean_delay: %u\n", trace_record->mean_delay);
    }

  s = format (s, "\nPOT data: \n");
  s = format (s, "sfc_validated_count : %u\n",
	      record->pot_data.sfc_validated_count);
  s = format (s, "sfc_invalidated_count : %u\n",
	      record->pot_data.sfc_invalidated_count);

  s = format (s, "\nSeqno Data:\n");
  s = format (s,
	      "RX Packets        : %lu\n"
	      "Lost Packets      : %lu\n"
	      "Duplicate Packets : %lu\n"
	      "Reordered Packets : %lu\n",
	      record->seqno_data.rx_packets,
	      record->seqno_data.lost_packets,
	      record->seqno_data.dup_packets,
	      record->seqno_data.reordered_packets);

  s = format (s, "\n");
  return s;
}

always_inline void
ioam_analyse_init_data (ioam_analyser_data_t * data)
{
  u16 j;
  ioam_analyse_trace_data *trace_data;

  data->is_free = 1;

  /* We maintain data corresponding to last IP-Fix export, this may
   * get extended in future to maintain history of data */
  vec_validate_aligned (data->chached_data_list, 0, CLIB_CACHE_LINE_BYTES);

  data->writer_lock = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES,
					      CLIB_CACHE_LINE_BYTES);
  *(data->writer_lock) = 0;

  trace_data = &(data->trace_data);
  for (j = 0; j < IOAM_MAX_PATHS_PER_FLOW; j++)
    trace_data->path_data[j].is_free = 1;
}

#endif /* PLUGINS_IOAM_PLUGIN_IOAM_ANALYSE_IOAM_ANALYSE_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
