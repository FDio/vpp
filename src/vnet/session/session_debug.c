/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <vnet/session/session_debug.h>
#include <vnet/session/session.h>

#if SESSION_DEBUG > 0

session_dbg_main_t session_dbg_main;

static clib_error_t *
show_session_dbg_clock_cycles_fn (vlib_main_t * vm, unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  u32 thread;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input `%U'", format_unformat_error,
			      input);

  for (thread = 0; thread < vec_len (session_dbg_main.wrk); thread++)
    {
      vlib_cli_output (vm, "Threads %u:\n", thread);
      session_dbg_evts_t *sdm = &session_dbg_main.wrk[thread];

#define _(sym, disp, type, str) 								         \
  if(disp)								\
    {									\
      if (!type)							\
	vlib_cli_output (vm, "\t %25s : %12lu ", str,                 	\
	                 sdm->counters[SESS_Q_##sym].u64);		\
      else								\
	vlib_cli_output (vm, "\t %25s : %12.3f ", str,                  \
	                 sdm->counters[SESS_Q_##sym].f64);		\
    }
      foreach_session_events
#undef _
    }
  return 0;
}


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_session_dbg_clock_cycles_command, static) =
{
  .path = "show session dbg clock_cycles",
  .short_help = "show session dbg clock_cycles",
  .function = show_session_dbg_clock_cycles_fn,
};
/* *INDENT-ON* */


static clib_error_t *
clear_session_dbg_clock_cycles_fn (vlib_main_t * vm, unformat_input_t * input,
				   vlib_cli_command_t * cmd)
{
  session_dbg_evts_t *sde;
  u32 thread;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input `%U'", format_unformat_error,
			      input);

  for (thread = 0; thread < vec_len (session_dbg_main.wrk); thread++)
    {
      sde = &session_dbg_main.wrk[thread];
      clib_memset (sde, 0, sizeof (session_dbg_evts_t));
      sde->last_time = vlib_time_now (vlib_mains[thread]);
      sde->start_time = sde->last_time;
    }

  return 0;
}


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (clear_session_clock_cycles_command, static) =
{
  .path = "clear session dbg clock_cycles",
  .short_help = "clear session dbg clock_cycles",
  .function = clear_session_dbg_clock_cycles_fn,
};
/* *INDENT-ON* */

void
session_debug_init (void)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  session_dbg_main_t *sdm = &session_dbg_main;
  u32 num_threads, thread;

  num_threads = vtm->n_vlib_mains;

  vec_validate_aligned (sdm->wrk, num_threads - 1, CLIB_CACHE_LINE_BYTES);
  for (thread = 0; thread < num_threads; thread++)
    {
      clib_memset (&sdm->wrk[thread], 0, sizeof (session_dbg_evts_t));
      sdm->wrk[thread].start_time = vlib_time_now (vlib_mains[thread]);
    }
}
#else
void
session_debug_init (void)
{
}
#endif

void
dump_thread_0_event_queue (void)
{
  vlib_main_t *vm = vlib_mains[0];
  u32 my_thread_index = vm->thread_index;
  session_event_t _e, *e = &_e;
  svm_msg_q_shared_queue_t *sq;
  svm_msg_q_ring_t *ring;
  session_t *s0;
  svm_msg_q_msg_t *msg;
  svm_msg_q_t *mq;
  int i, index;

  mq = session_main_get_vpp_event_queue (my_thread_index);
  sq = mq->q.shr;
  index = sq->head;

  for (i = 0; i < sq->cursize; i++)
    {
      msg = (svm_msg_q_msg_t *) (&sq->data[0] + sq->elsize * index);
      ring = svm_msg_q_ring (mq, msg->ring_index);
      clib_memcpy_fast (e, svm_msg_q_msg_data (mq, msg), ring->elsize);

      switch (e->event_type)
	{
	case SESSION_IO_EVT_TX:
	  s0 = session_get_if_valid (e->session_index, my_thread_index);
	  fformat (stdout, "[%04d] TX session %d\n", i, s0->session_index);
	  break;

	case SESSION_CTRL_EVT_CLOSE:
	  s0 = session_get_from_handle (e->session_handle);
	  fformat (stdout, "[%04d] disconnect session %d\n", i,
		   s0->session_index);
	  break;

	case SESSION_IO_EVT_BUILTIN_RX:
	  s0 = session_get_if_valid (e->session_index, my_thread_index);
	  fformat (stdout, "[%04d] builtin_rx %d\n", i, s0->session_index);
	  break;

	case SESSION_CTRL_EVT_RPC:
	  fformat (stdout, "[%04d] RPC call %llx with %llx\n",
		   i, (u64) (uword) (e->rpc_args.fp),
		   (u64) (uword) (e->rpc_args.arg));
	  break;

	default:
	  fformat (stdout, "[%04d] unhandled event type %d\n",
		   i, e->event_type);
	  break;
	}

      index++;

      if (index == sq->maxsize)
	index = 0;
    }
}

static u8
session_node_cmp_event (session_event_t * e, svm_fifo_t * f)
{
  session_t *s;
  switch (e->event_type)
    {
    case SESSION_IO_EVT_RX:
    case SESSION_IO_EVT_TX:
    case SESSION_IO_EVT_BUILTIN_RX:
    case SESSION_IO_EVT_BUILTIN_TX:
    case SESSION_IO_EVT_TX_FLUSH:
      if (e->session_index == f->shr->master_session_index)
	return 1;
      break;
    case SESSION_CTRL_EVT_CLOSE:
      break;
    case SESSION_CTRL_EVT_RPC:
      s = session_get_from_handle (e->session_handle);
      if (!s)
	{
	  clib_warning ("session has event but doesn't exist!");
	  break;
	}
      if (s->rx_fifo == f || s->tx_fifo == f)
	return 1;
      break;
    default:
      break;
    }
  return 0;
}

u8
session_node_lookup_fifo_event (svm_fifo_t * f, session_event_t * e)
{
  svm_msg_q_shared_queue_t *sq;
  session_evt_elt_t *elt;
  session_worker_t *wrk;
  int i, index, found = 0;
  svm_msg_q_msg_t *msg;
  svm_msg_q_ring_t *ring;
  svm_msg_q_t *mq;
  u8 thread_index;

  ASSERT (e);
  thread_index = f->master_thread_index;
  wrk = session_main_get_worker (thread_index);

  /*
   * Search evt queue
   */
  mq = wrk->vpp_event_queue;
  sq = mq->q.shr;
  index = sq->head;
  for (i = 0; i < sq->cursize; i++)
    {
      msg = (svm_msg_q_msg_t *) (&sq->data[0] + sq->elsize * index);
      ring = svm_msg_q_ring (mq, msg->ring_index);
      clib_memcpy_fast (e, svm_msg_q_msg_data (mq, msg), ring->elsize);
      found = session_node_cmp_event (e, f);
      if (found)
	return 1;
      index = (index + 1) % sq->maxsize;
    }
  /*
   * Search pending events vector
   */

  /* *INDENT-OFF* */
  clib_llist_foreach (wrk->event_elts, evt_list,
                      pool_elt_at_index (wrk->event_elts, wrk->new_head),
                      elt, ({
    found = session_node_cmp_event (&elt->evt, f);
    if (found)
      {
	clib_memcpy_fast (e, &elt->evt, sizeof (*e));
	goto done;
      }
  }));
  /* *INDENT-ON* */

  /* *INDENT-OFF* */
  clib_llist_foreach (wrk->event_elts, evt_list,
                      pool_elt_at_index (wrk->event_elts, wrk->old_head),
                      elt, ({
    found = session_node_cmp_event (&elt->evt, f);
    if (found)
      {
	clib_memcpy_fast (e, &elt->evt, sizeof (*e));
	goto done;
      }
  }));
  /* *INDENT-ON* */

done:
  return found;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
