/*
* Copyright (c) 2017-2019 Cisco and/or its affiliates.
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
#include <vnet/session/session.h>
#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vppinfra/tw_timer_2t_1w_2048sl.h>

#include "upf_pfcp.h"
#include "upf_pfcp_api.h"
#include "upf_pfcp_server.h"

#if CLIB_DEBUG > 1
#define upf_debug clib_warning
#else
#define upf_debug(...)				\
  do { } while (0)
#endif

typedef struct
{
  svm_msg_q_t **vpp_queue;

  uword *handler_by_get_request;

  /* Sever's event queue */
  svm_queue_t *vl_input_queue;

  /* API application handle */
  u32 app_index;

  /* process node index for evnt scheduling */
  u32 node_index;

  tw_timer_wheel_2t_1w_2048sl_t tw;
  clib_spinlock_t tw_lock;

  u32 prealloc_fifos;
  u32 private_segment_size;
  u32 fifo_size;
  vlib_main_t *vlib_main;
} pfcp_session_server_main_t;

pfcp_session_server_main_t pfcp_session_server_main;

static int
pfcp_session_server_rx_callback (session_t * s)
{
  upf_main_t *gtm = &upf_main;
  session_dgram_pre_hdr_t ph;
  pfcp_msg_t *msg;
  u32 max_deq;
  int len, rv;

  max_deq = svm_fifo_max_dequeue_cons (s->rx_fifo);
  if (PREDICT_FALSE (max_deq < sizeof (session_dgram_hdr_t)))
    return -1;

  svm_fifo_peek (s->rx_fifo, 0, sizeof (ph), (u8 *) & ph);
  ASSERT (ph.data_length >= ph.data_offset);

  len = ph.data_length - ph.data_offset;
  msg = clib_mem_alloc_aligned_no_fail (sizeof (*msg), CLIB_CACHE_LINE_BYTES);
  memset (msg, 0, sizeof (*msg));

  msg->session_handle = session_handle (s);

  if (!ph.data_offset)
    {
      app_session_transport_t at;

      svm_fifo_peek (s->rx_fifo, sizeof (ph), sizeof (at), (u8 *) & at);

      msg->lcl.address = at.lcl_ip;
      msg->rmt.address = at.rmt_ip;
      msg->lcl.port = at.lcl_port;
      msg->rmt.port = at.rmt_port;

      if (at.is_ip4)
	{
	  ip46_address_mask_ip4 (&msg->lcl.address);
	  ip46_address_mask_ip4 (&msg->rmt.address);
	}
    }

  vec_validate (msg->data, len);
  rv =
    svm_fifo_peek (s->rx_fifo, ph.data_offset + SESSION_CONN_HDR_LEN, len,
		   msg->data);

  ph.data_offset += rv;
  if (ph.data_offset == ph.data_length)
    svm_fifo_dequeue_drop (s->rx_fifo, ph.data_length + SESSION_CONN_HDR_LEN);
  else
    svm_fifo_overwrite_head (s->rx_fifo, (u8 *) & ph, sizeof (ph));

  upf_debug ("sending event %d, %p %U:%d - %U:%d, data %p",
	     ph.data_offset, msg,
	     format_ip46_address, &msg->rmt.address, IP46_TYPE_ANY,
	     clib_net_to_host_u16 (msg->rmt.port),
	     format_ip46_address, &msg->lcl.address, IP46_TYPE_ANY,
	     clib_net_to_host_u16 (msg->lcl.port), msg->data);

  vlib_process_signal_event_mt (gtm->vlib_main, pfcp_api_process_node.index,
				EVENT_RX, (uword) msg);

  return 0;
}

static int
pfcp_session_server_session_accept_callback (session_t * s)
{
  upf_debug ("called...");
  return -1;
}

static void
pfcp_session_server_session_disconnect_callback (session_t * s)
{
  upf_debug ("called...");
}

static void
pfcp_session_server_session_reset_callback (session_t * s)
{
  upf_debug ("called...");
}

static int
pfcp_session_server_session_connected_callback (u32 app_index,
						u32 api_context,
						session_t * s, u8 is_fail)
{
  upf_debug ("called...");
  return -1;
}

static int
pfcp_session_server_add_segment_callback (u32 client_index,
					  u64 segment_handle)
{
  upf_debug ("called...");
  return -1;
}

static session_cb_vft_t pfcp_session_server_session_cb_vft = {
  .session_accept_callback = pfcp_session_server_session_accept_callback,
  .session_disconnect_callback =
    pfcp_session_server_session_disconnect_callback,
  .session_connected_callback =
    pfcp_session_server_session_connected_callback,
  .add_segment_callback = pfcp_session_server_add_segment_callback,
  .builtin_app_rx_callback = pfcp_session_server_rx_callback,
  .session_reset_callback = pfcp_session_server_session_reset_callback
};

static void
pfcp_session_server_session_cleanup_cb (void *ps_handlep)
{
  upf_debug ("called...");
}

static void
pfcp_expired_timers_dispatch (u32 * expired_timers)
{
  u32 ps_handle;
  int i;

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      /* Get session handle. The first bit is the timer id */
      ps_handle = expired_timers[i] & 0x7FFFFFFF;
      session_send_rpc_evt_to_thread (ps_handle >> 24,
				      pfcp_session_server_session_cleanup_cb,
				      uword_to_pointer (ps_handle, void *));
    }
}

static uword
pfcp_session_server_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
			     vlib_frame_t * f)
{
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;
  f64 now, timeout = 1.0;
  uword *event_data = 0;
  uword __clib_unused event_type;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);
      now = vlib_time_now (vm);
      event_type = vlib_process_get_events (vm, (uword **) & event_data);

      /* expire timers */
      clib_spinlock_lock (&pfcp_session_server_main.tw_lock);
      tw_timer_expire_timers_2t_1w_2048sl (&pssm->tw, now);
      clib_spinlock_unlock (&pfcp_session_server_main.tw_lock);

      vec_reset_length (event_data);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (pfcp_session_server_process_node) =
{
  .function = pfcp_session_server_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "pfcp-server-process",
  .state = VLIB_NODE_STATE_DISABLED,
};
/* *INDENT-ON* */

static int
pfcp_server_attach (vlib_main_t * vm)
{
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;
  u64 options[APP_OPTIONS_N_OPTIONS];
  vnet_app_attach_args_t _a, *a = &_a;

  if (pssm->app_index != ~0)
    return 0;

  vnet_session_enable_disable (vm, 1 /* turn on TCP, etc. */ );

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->api_client_index = ~0;
  a->name = format (0, "upf-pfcp-server");
  a->session_cb_vft = &pfcp_session_server_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = pssm->private_segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = pssm->fifo_size;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = pssm->fifo_size;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = pssm->prealloc_fifos;

  if (vnet_application_attach (a))
    {
      vec_free (a->name);
      upf_debug ("failed to attach server");
      return -1;
    }

  vec_free (a->name);
  pssm->app_index = a->app_index;

  return 0;
}

int
vnet_upf_pfcp_endpoint_add_del (ip46_address_t * ip, u32 fib_index, u8 add)
{
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;
  upf_main_t *gtm = &upf_main;
  ip46_address_fib_t key;
  int rv = 0;
  uword *p;

  key.addr = *ip;
  key.fib_index = fib_index;

  p = mhash_get (&gtm->pfcp_endpoint_index, &key);

  if (add)
    {
      vnet_listen_args_t _a, *a = &_a;

      if (p)
	return VNET_API_ERROR_VALUE_EXIST;

      pfcp_server_attach (pssm->vlib_main);

      clib_memset (a, 0, sizeof (*a));

      a->app_index = pssm->app_index;
      a->sep_ext = (session_endpoint_cfg_t) SESSION_ENDPOINT_CFG_NULL;
      a->sep_ext.fib_index = fib_index;
      a->sep_ext.transport_proto = TRANSPORT_PROTO_UDP;
      a->sep_ext.is_ip4 = ip46_address_is_ip4 (ip);
      a->sep_ext.ip = *ip;
      a->sep_ext.port = clib_host_to_net_u16 (UDP_DST_PORT_PFCP);

      if ((rv = vnet_listen (a)) == 0)
	mhash_set (&gtm->pfcp_endpoint_index, &key, a->handle, NULL);
    }
  else
    {
      vnet_unlisten_args_t _a, *a = &_a;

      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      clib_memset (a, 0, sizeof (*a));

      a->app_index = pssm->app_index;
      a->handle = p[0];

      mhash_unset (&gtm->pfcp_endpoint_index, &key, NULL);
      rv = vnet_unlisten (a);
    }

  return rv;
}

static clib_error_t *
pfcp_session_server_set_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 prealloc_fifos = pssm->prealloc_fifos;
  u32 fifo_size = pssm->fifo_size;
  u64 seg_size = pssm->private_segment_size;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "prealloc-fifos %d", &prealloc_fifos))
	;
      else if (unformat (line_input, "private-segment-size %U",
			 unformat_memory_size, &seg_size))
	{
	  if (seg_size >= 0x100000000ULL)
	    {
	      vlib_cli_output (vm, "private segment size %llu, too large",
			       seg_size);
	      return 0;
	    }
	}
      else if (unformat (line_input, "fifo-size %d", &fifo_size))
	fifo_size <<= 10;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, line_input);
    }
  unformat_free (line_input);

  if (pssm->app_index != (u32) ~ 0)
    return clib_error_return (0, "test pfcp server is already running");

  pssm->prealloc_fifos = prealloc_fifos;
  pssm->fifo_size = fifo_size;
  pssm->private_segment_size = seg_size;

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (pfcp_session_server_set_command, static) =
{
  .path = "upf pfcp server set",
  .short_help = "upf pfcp server set",
  .function = pfcp_session_server_set_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
pfcp_session_server_main_init (vlib_main_t * vm)
{
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 num_threads;

  pssm->app_index = ~0;
  pssm->vlib_main = vm;

  /* PFPC server defaults */
  pssm->prealloc_fifos = 0;
  pssm->fifo_size = 64 << 10;
  pssm->private_segment_size = 0;

  num_threads = 1 /* main thread */  + vtm->n_threads;
  vec_validate (pssm->vpp_queue, num_threads - 1);

  clib_spinlock_init (&pssm->tw_lock);

  /* Init timer wheel and process */
  tw_timer_wheel_init_2t_1w_2048sl (&pssm->tw, pfcp_expired_timers_dispatch,
				    1 /* timer interval */ , ~0);
  vlib_node_set_state (vm, pfcp_session_server_process_node.index,
		       VLIB_NODE_STATE_POLLING);

  return 0;
}

VLIB_INIT_FUNCTION (pfcp_session_server_main_init);

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
