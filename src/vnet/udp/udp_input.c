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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ip/ip.h>

#include <vnet/udp/udp.h>
#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#include <vnet/udp/udp_packet.h>

#include <vlibmemory/api.h>
#include "../session/application_interface.h"

vlib_node_registration_t udp4_uri_input_node;

typedef struct
{
  u32 session;
  u32 disposition;
  u32 thread_index;
} udp4_uri_input_trace_t;

/* packet trace format function */
static u8 *
format_udp4_uri_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  udp4_uri_input_trace_t *t = va_arg (*args, udp4_uri_input_trace_t *);

  s = format (s, "UDP4_URI_INPUT: session %d, disposition %d, thread %d",
	      t->session, t->disposition, t->thread_index);
  return s;
}

typedef enum
{
  UDP4_URI_INPUT_NEXT_DROP,
  UDP4_URI_INPUT_N_NEXT,
} udp4_uri_input_next_t;

static char *udp4_uri_input_error_strings[] = {
#define _(sym,string) string,
  foreach_session_input_error
#undef _
};

static uword
udp4_uri_input_node_fn (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  udp4_uri_input_next_t next_index;
  udp_uri_main_t *um = vnet_get_udp_main ();
  session_manager_main_t *smm = vnet_get_session_manager_main ();
  u32 my_thread_index = vm->thread_index;
  u8 my_enqueue_epoch;
  u32 *session_indices_to_enqueue;
  static u32 serial_number;
  int i;

  my_enqueue_epoch = ++smm->current_enqueue_epoch[my_thread_index];

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = UDP4_URI_INPUT_NEXT_DROP;
	  u32 error0 = SESSION_ERROR_ENQUEUED;
	  udp_header_t *udp0;
	  ip4_header_t *ip0;
	  stream_session_t *s0;
	  svm_fifo_t *f0;
	  u16 udp_len0;
	  u8 *data0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  /* udp_local hands us a pointer to the udp data */

	  data0 = vlib_buffer_get_current (b0);
	  udp0 = (udp_header_t *) (data0 - sizeof (*udp0));

	  /* $$$$ fixme: udp_local doesn't do ip options correctly anyhow */
	  ip0 = (ip4_header_t *) (((u8 *) udp0) - sizeof (*ip0));
	  s0 = 0;

	  /* lookup session */
	  s0 = stream_session_lookup4 (&ip0->dst_address, &ip0->src_address,
				       udp0->dst_port, udp0->src_port,
				       SESSION_TYPE_IP4_UDP);

	  /* no listener */
	  if (PREDICT_FALSE (s0 == 0))
	    {
	      error0 = SESSION_ERROR_NO_LISTENER;
	      goto trace0;
	    }

	  f0 = s0->server_rx_fifo;

	  /* established hit */
	  if (PREDICT_TRUE (s0->session_state == SESSION_STATE_READY))
	    {
	      udp_len0 = clib_net_to_host_u16 (udp0->length);

	      if (PREDICT_FALSE (udp_len0 > svm_fifo_max_enqueue (f0)))
		{
		  error0 = SESSION_ERROR_FIFO_FULL;
		  goto trace0;
		}

	      svm_fifo_enqueue_nowait (f0, udp_len0 - sizeof (*udp0),
				       (u8 *) (udp0 + 1));

	      b0->error = node->errors[SESSION_ERROR_ENQUEUED];

	      /* We need to send an RX event on this fifo */
	      if (s0->enqueue_epoch != my_enqueue_epoch)
		{
		  s0->enqueue_epoch = my_enqueue_epoch;

		  vec_add1 (smm->session_indices_to_enqueue_by_thread
			    [my_thread_index],
			    s0 - smm->sessions[my_thread_index]);
		}
	    }
	  /* listener hit */
	  else if (s0->session_state == SESSION_STATE_LISTENING)
	    {
	      udp_connection_t *us;
	      int rv;

	      error0 = SESSION_ERROR_NOT_READY;

	      /*
	       * create udp transport session
	       */
	      pool_get (um->udp_sessions[my_thread_index], us);

	      us->mtu = 1024;	/* $$$$ policy */

	      us->c_lcl_ip4.as_u32 = ip0->dst_address.as_u32;
	      us->c_rmt_ip4.as_u32 = ip0->src_address.as_u32;
	      us->c_lcl_port = udp0->dst_port;
	      us->c_rmt_port = udp0->src_port;
	      us->c_transport_proto = TRANSPORT_PROTO_UDP;
	      us->c_c_index = us - um->udp_sessions[my_thread_index];

	      /*
	       * create stream session and attach the udp session to it
	       */
	      rv = stream_session_accept (&us->connection, s0->session_index,
					  SESSION_TYPE_IP4_UDP,
					  1 /*notify */ );
	      if (rv)
		error0 = rv;

	    }
	  else
	    {

	      error0 = SESSION_ERROR_NOT_READY;
	      goto trace0;
	    }

	trace0:
	  b0->error = node->errors[error0];

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      udp4_uri_input_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));

	      t->session = ~0;
	      if (s0)
		t->session = s0 - smm->sessions[my_thread_index];
	      t->disposition = error0;
	      t->thread_index = my_thread_index;
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Send enqueue events */

  session_indices_to_enqueue =
    smm->session_indices_to_enqueue_by_thread[my_thread_index];

  for (i = 0; i < vec_len (session_indices_to_enqueue); i++)
    {
      session_fifo_event_t evt;
      unix_shared_memory_queue_t *q;
      stream_session_t *s0;
      application_t *server0;

      /* Get session */
      s0 = pool_elt_at_index (smm->sessions[my_thread_index],
			      session_indices_to_enqueue[i]);

      /* Get session's server */
      server0 = application_get (s0->app_index);

      /* Built-in server? Deliver the goods... */
      if (server0->cb_fns.builtin_server_rx_callback)
	{
	  server0->cb_fns.builtin_server_rx_callback (s0);
	  continue;
	}

      if (svm_fifo_set_event (s0->server_rx_fifo))
	{
	  /* Fabricate event */
	  evt.fifo = s0->server_rx_fifo;
	  evt.event_type = FIFO_EVENT_APP_RX;
	  evt.event_id = serial_number++;

	  /* Add event to server's event queue */
	  q = server0->event_queue;

	  /* Don't block for lack of space */
	  if (PREDICT_TRUE (q->cursize < q->maxsize))
	    {
	      unix_shared_memory_queue_add (server0->event_queue,
					    (u8 *) & evt,
					    0 /* do wait for mutex */ );
	    }
	  else
	    {
	      vlib_node_increment_counter (vm, udp4_uri_input_node.index,
					   SESSION_ERROR_FIFO_FULL, 1);
	    }
	}
      /* *INDENT-OFF* */
      if (1)
	{
	  ELOG_TYPE_DECLARE (e) =
	  {
	      .format = "evt-enqueue: id %d length %d",
	      .format_args = "i4i4",};
	  struct
	  {
	    u32 data[2];
	  } *ed;
	  ed = ELOG_DATA (&vlib_global_main.elog_main, e);
	  ed->data[0] = evt.event_id;
	  ed->data[1] = svm_fifo_max_dequeue (s0->server_rx_fifo);
	}
      /* *INDENT-ON* */

    }

  vec_reset_length (session_indices_to_enqueue);

  smm->session_indices_to_enqueue_by_thread[my_thread_index] =
    session_indices_to_enqueue;

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (udp4_uri_input_node) =
{
  .function = udp4_uri_input_node_fn,.name = "udp4-uri-input",.vector_size =
    sizeof (u32),.format_trace = format_udp4_uri_input_trace,.type =
    VLIB_NODE_TYPE_INTERNAL,.n_errors =
    ARRAY_LEN (udp4_uri_input_error_strings),.error_strings =
    udp4_uri_input_error_strings,.n_next_nodes = UDP4_URI_INPUT_N_NEXT,
    /* edit / add dispositions here */
    .next_nodes =
  {
  [UDP4_URI_INPUT_NEXT_DROP] = "error-drop",}
,};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
