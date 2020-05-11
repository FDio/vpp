/* Hey Emacs use -*- mode: C -*- */
/*
 * Copyright 2020 Rubicon Communications, LLC.
 *
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

#include <sys/socket.h>
#include <linux/if.h>

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <vnet/vnet_msg_enum.h>

#define vl_typedefs
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>

#include <vlib/trace.h>


#define MIN(a,b)	((a) < (b) ? (a) : (b))


static void
vl_api_pkt_trace_clear_packets_t_handler (vl_api_pkt_trace_clear_packets_t *
					  mp)
{
  vl_api_pkt_trace_clear_packets_reply_t *rmp;
  int rv;

  vlib_trace_stop_and_clear ();

  rv = 0;
  REPLY_MACRO (VL_API_PKT_TRACE_CLEAR_PACKETS_REPLY);
}

static void
vl_api_pkt_trace_capture_packets_t_handler (vl_api_pkt_trace_capture_packets_t
					    * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 add = ntohl (mp->max_packets);
  u32 node_index = ntohl (mp->node_index);
  u8 filter = mp->use_filter;
  u8 verbose = mp->verbose;
  u8 pre_clear = mp->pre_capture_clear;
  vl_api_pkt_trace_capture_packets_reply_t *rmp;
  int rv = 0;

  if (!vnet_trace_dummy)
    vec_validate_aligned (vnet_trace_dummy, 2048, CLIB_CACHE_LINE_BYTES);

  vlib_node_t *node;
  node = vlib_get_node (vm, node_index);
  if (!node)
    {
      rv = VNET_API_ERROR_NO_SUCH_NODE;
      goto done;
    }

  if ((node->flags & VLIB_NODE_FLAG_TRACE_SUPPORTED) == 0)
    {
      /* FIXME: Make a new, better error like "UNSUPPORTED_NODE_OPERATION"? */
      rv = VNET_API_ERROR_NO_SUCH_NODE;
      goto done;
    }

  if (filter)
    {
      if (vlib_enable_disable_pkt_trace_filter (1) < 0)	/* enable */
	{
	  /* FIXME: Make a new error like "UNSUPPORTED_NODE_OPERATION"? */
	  rv = VNET_API_ERROR_NO_SUCH_NODE;
	  goto done;
	}
    }

  if (pre_clear)
    vlib_trace_stop_and_clear ();

  trace_update_capture_options (add, node_index, filter, verbose);

done:
  REPLY_MACRO (VL_API_PKT_TRACE_CAPTURE_PACKETS_REPLY);
}


static void
trace_send_packet_details (vl_api_registration_t * reg,
			   u32 context,
			   u32 thread_id, u32 packet_number, u8 * packet_log)
{
  vl_api_pkt_trace_capture_details_t *mp;
  int log_len;

  log_len = vec_len (packet_log);
  mp = vl_msg_api_alloc (sizeof (*mp) + log_len);
  if (!mp)
    return;

  clib_memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = ntohs (VL_API_PKT_TRACE_CAPTURE_DETAILS);
  mp->context = context;

  mp->thread_id = htonl (thread_id);
  mp->packet_number = htonl (packet_number);
  mp->log_size = htonl (log_len);	/* including trailing 0 */

  clib_strncpy ((char *) mp->packet_log.buf, (char *) packet_log,
		log_len - 1);

  vl_api_send_msg (reg, (u8 *) mp);
}


static void
trace_all_packets (vl_api_registration_t * reg, u32 context, u32 max)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 thread_id = 0;
  u8 *s = 0;

  /* *INDENT-OFF* */
  foreach_vlib_main (
  ({
    vlib_trace_main_t *tm;
    vlib_trace_header_t **h, **traces;

    tm = &this_vlib_main->trace_main;

    trace_apply_filter(this_vlib_main);

    traces = 0;
    pool_foreach (h, tm->trace_buffer_pool,
    ({
      vec_add1 (traces, h[0]);
    }));

    if (vec_len (traces) > 0)
      {
	int i;

	vec_sort_with_function (traces, trace_time_cmp);

	u32 n = MIN(max, vec_len (traces));
	for (i = 0; i < n; i++)
	  {
	    u8 *log;

	    log = format (s, "%U%c", format_vlib_trace, vm, traces[i], 0);
	    trace_send_packet_details(reg, context, thread_id, i, log);
	    vec_free (log);
	  }
      }

    vec_free (traces);

    ++thread_id;
  }));
  /* *INDENT-ON* */
}


static void
vl_api_pkt_trace_capture_dump_t_handler (vl_api_pkt_trace_capture_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  u32 max = ntohl (mp->max_packets_dumped);
  trace_all_packets (reg, mp->context, max);
}


static void
vl_api_pkt_trace_set_filters_t_handler (vl_api_pkt_trace_set_filters_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 node_index = ntohl (mp->node_index);
  u32 flag = ntohl (mp->flag);
  u32 count = ntohl (mp->count);
  vl_api_pkt_trace_set_filters_reply_t *rmp;
  int rv = 0;

  if (flag == TRACE_FF_NONE)
    {
      count = node_index = 0;
    }
  else if (flag != TRACE_FF_INCLUDE_NODE && flag != TRACE_FF_EXCLUDE_NODE)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  vlib_node_t *node;
  node = vlib_get_node (vm, node_index);
  if (!node)
    {
      rv = VNET_API_ERROR_NO_SUCH_NODE;
      goto done;
    }

  trace_filter_set (node_index, flag, count);

done:
  REPLY_MACRO (VL_API_PKT_TRACE_SET_FILTERS_REPLY);
}



#define vl_msg_name_crc_list
#include <vnet/pkt_trace.api.h>
#undef vl_msg_name_crc_list


static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_pkt_trace;
#undef _
}


#define foreach_vpe_api_msg				  \
  _(PKT_TRACE_CLEAR_PACKETS, pkt_trace_clear_packets)	  \
  _(PKT_TRACE_SET_FILTERS, pkt_trace_set_filters)	  \
  _(PKT_TRACE_CAPTURE_PACKETS, pkt_trace_capture_packets) \
  _(PKT_TRACE_CAPTURE_DUMP, pkt_trace_capture_dump)	  \


static clib_error_t *
pkt_trace_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = vlibapi_get_main ();

#define _(N,n)						      \
  vl_msg_api_set_handlers(VL_API_##N, #n,                     \
			  vl_api_##n##_t_handler,	      \
			  vl_noop_handler,		      \
			  vl_api_##n##_t_endian,	      \
			  vl_api_##n##_t_print,		      \
			  sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_msg;
#undef _

  setup_message_id_table (am);

  return 0;
}

VLIB_INIT_FUNCTION (pkt_trace_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
