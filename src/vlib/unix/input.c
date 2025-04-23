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
 * input.c: Unix file input
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vlib/vlib.h>
#include <vlib/file.h>
#include <vlib/unix/unix.h>
#include <signal.h>
#include <unistd.h>
#include <vppinfra/tw_timer_1t_3w_1024sl_ov.h>

/* FIXME autoconf */
#define HAVE_LINUX_EPOLL

#ifdef HAVE_LINUX_EPOLL

#include <sys/epoll.h>

static void
linux_epoll_file_update (clib_file_t * f, clib_file_update_type_t update_type)
{
  vlib_main_t *vm = vlib_get_main ();
  struct epoll_event e = { 0 };
  int op, add_del = 0;

  e.events = EPOLLIN;
  if (f->flags & UNIX_FILE_DATA_AVAILABLE_TO_WRITE)
    e.events |= EPOLLOUT;
  if (f->flags & UNIX_FILE_EVENT_EDGE_TRIGGERED)
    e.events |= EPOLLET;
  e.data.u32 = f->index;

  op = -1;

  switch (update_type)
    {
    case UNIX_FILE_UPDATE_ADD:
      op = EPOLL_CTL_ADD;
      add_del = 1;
      break;

    case UNIX_FILE_UPDATE_MODIFY:
      op = EPOLL_CTL_MOD;
      break;

    case UNIX_FILE_UPDATE_DELETE:
      op = EPOLL_CTL_DEL;
      add_del = -1;
      break;

    default:
      clib_warning ("unknown update_type %d", update_type);
      return;
    }

  /* worker threads open epoll fd only if needed */
  if (update_type == UNIX_FILE_UPDATE_ADD && vm->epoll_fd == -1)
    {
      vm->epoll_fd = epoll_create (1);
      if (vm->epoll_fd < 0)
	{
	  clib_unix_warning ("epoll_create");
	  return;
	}
      vm->n_epoll_fds = 0;
    }

  if (epoll_ctl (vm->epoll_fd, op, f->file_descriptor, &e) < 0)
    {
      clib_unix_warning ("epoll_ctl");
      return;
    }

  vm->n_epoll_fds += add_del;

  if (vm->n_epoll_fds == 0)
    {
      close (vm->epoll_fd);
      vm->epoll_fd = -1;
    }
}

static int
is_int_pending (vlib_node_main_t *nm)
{

  for (int nt = 0; nt < VLIB_N_NODE_TYPE; nt++)
    if (nm->node_interrupts[nt] &&
	clib_interrupt_is_any_pending (nm->node_interrupts[nt]))
      return 1;
  return 0;
}

static_always_inline uword
linux_epoll_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			  vlib_frame_t * frame, u32 thread_index)
{
  unix_main_t *um = &unix_main;
  clib_file_main_t *fm = &file_main;
  struct epoll_event *e, epoll_events[256];
  int n_fds_ready;
  int is_main = (thread_index == 0);

  {
    vlib_node_main_t *nm = &vm->node_main;
    u32 ticks_until_expiration;
    f64 timeout;
    f64 now;
    int timeout_ms = 0, max_timeout_ms = 10;
    f64 vector_rate = vlib_last_vectors_per_main_loop (vm);

    if (is_main == 0)
      now = vlib_time_now (vm);

    /*
     * If we've been asked for a fixed-sleep between main loop polls,
     * do so right away.
     */
    if (PREDICT_FALSE (is_main && um->poll_sleep_usec))
      {
	struct timespec ts, tsrem;
	timeout = 0;
	timeout_ms = 0;
	node->input_main_loops_per_call = 0;
	ts.tv_sec = 0;
	ts.tv_nsec = 1000 * um->poll_sleep_usec;

	while (nanosleep (&ts, &tsrem) < 0)
	  {
	    ts = tsrem;
	  }
      }
    /* If we're not working very hard, decide how long to sleep */
    else if (is_main && vector_rate < 2 && vm->api_queue_nonempty == 0
	     && nm->input_node_counts_by_state[VLIB_NODE_STATE_POLLING] == 0)
      {
	ticks_until_expiration = vlib_tw_timer_first_expires_in_ticks (vm);

	/* Nothing on the fast wheel, sleep 10ms */
	if (ticks_until_expiration == TW_SLOTS_PER_RING)
	  {
	    timeout = 10e-3;
	    timeout_ms = max_timeout_ms;
	  }
	else
	  {
	    timeout = (f64) ticks_until_expiration *1e-5;
	    if (timeout < 1e-3)
	      timeout_ms = 0;
	    else
	      {
		timeout_ms = timeout * 1e3;
		/* Must be between 1 and 10 ms. */
		timeout_ms = clib_max (1, timeout_ms);
		timeout_ms = clib_min (max_timeout_ms, timeout_ms);
	      }
	  }
	node->input_main_loops_per_call = 0;
      }
    else if (is_main == 0 && vector_rate < 2 &&
	     (vlib_get_first_main ()->time_last_barrier_release + 0.5 < now) &&
	     nm->input_node_counts_by_state[VLIB_NODE_STATE_POLLING] == 0)
      {
	timeout = 10e-3;
	timeout_ms = max_timeout_ms;
	node->input_main_loops_per_call = 0;
      }
    else			/* busy */
      {
	/* Don't come back for a respectable number of dispatch cycles */
	node->input_main_loops_per_call = 1024;
      }

    /* Allow any signal to wakeup our sleep. */
    if (is_main || vm->epoll_fd != -1)
      {
	static sigset_t unblock_all_signals;
	n_fds_ready =
	  epoll_pwait (vm->epoll_fd, epoll_events, ARRAY_LEN (epoll_events),
		       timeout_ms, &unblock_all_signals);

	/* This kludge is necessary to run over absurdly old kernels */
	if (n_fds_ready < 0 && errno == ENOSYS)
	  {
	    n_fds_ready = epoll_wait (vm->epoll_fd, epoll_events,
				      ARRAY_LEN (epoll_events), timeout_ms);
	  }

      }
    else
      {
	/*
	 * Worker thread, no epoll fd's, sleep for 100us at a time
	 * and check for a barrier sync request
	 */
	if (timeout_ms)
	  {
	    struct timespec ts, tsrem;
	    f64 limit = now + (f64) timeout_ms * 1e-3;

	    while (vlib_time_now (vm) < limit)
	      {
		/* Sleep for 100us at a time */
		ts.tv_sec = 0;
		ts.tv_nsec = 1000 * 100;

		while (nanosleep (&ts, &tsrem) < 0)
		  ts = tsrem;
		if (*vlib_worker_threads->wait_at_barrier ||
		    is_int_pending (nm))
		  goto done;
	      }
	  }
	goto done;
      }
  }

  if (n_fds_ready < 0)
    {
      if (unix_error_is_fatal (errno))
	vlib_panic_with_error (vm, clib_error_return_unix (0, "epoll_wait"));

      /* non fatal error (e.g. EINTR). */
      goto done;
    }

  vm->epoll_waits += 1;
  vm->epoll_files_ready += n_fds_ready;

  for (e = epoll_events; e < epoll_events + n_fds_ready; e++)
    {
      u32 i = e->data.u32;
      clib_file_t *f;
      clib_error_t *errors[4];
      int n_errors = 0;

      /*
       * Under rare scenarios, epoll may still post us events for the
       * deleted file descriptor. We just deal with it and throw away the
       * events for the corresponding file descriptor.
       */
      f = clib_file_get (fm, i);
      if (PREDICT_FALSE (!f))
	{
	  if (e->events & EPOLLIN)
	    {
	      errors[n_errors] =
		clib_error_return (0, "epoll event EPOLLIN dropped due "
				   "to free index %u", i);
	      n_errors++;
	    }
	  if (e->events & EPOLLOUT)
	    {
	      errors[n_errors] =
		clib_error_return (0, "epoll event EPOLLOUT dropped due "
				   "to free index %u", i);
	      n_errors++;
	    }
	  if (e->events & EPOLLERR)
	    {
	      errors[n_errors] =
		clib_error_return (0, "epoll event EPOLLERR dropped due "
				   "to free index %u", i);
	      n_errors++;
	    }
	}
      else if (PREDICT_TRUE (!(e->events & EPOLLERR)))
	{
	  if (e->events & EPOLLIN)
	    {
	      f->read_events++;
	      errors[n_errors] = f->read_function (f);
	      /* Make sure f is valid if the file pool moves */
	      if (pool_is_free_index (fm->file_pool, i))
		continue;
	      f = clib_file_get (fm, i);
	      n_errors += errors[n_errors] != 0;
	    }
	  if (e->events & EPOLLOUT)
	    {
	      f->write_events++;
	      errors[n_errors] = f->write_function (f);
	      n_errors += errors[n_errors] != 0;
	    }
	}
      else
	{
	  if (f->error_function)
	    {
	      f->error_events++;
	      errors[n_errors] = f->error_function (f);
	      n_errors += errors[n_errors] != 0;
	    }
	  else
	    close (f->file_descriptor);
	}

      ASSERT (n_errors < ARRAY_LEN (errors));
      for (i = 0; i < n_errors; i++)
	{
	  unix_save_error (um, errors[i]);
	}
    }

done:
  return 0;
}

static uword
linux_epoll_input (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 thread_index = vlib_get_thread_index ();

  if (thread_index == 0)
    return linux_epoll_input_inline (vm, node, frame, 0);
  else
    return linux_epoll_input_inline (vm, node, frame, thread_index);
}

VLIB_REGISTER_NODE (linux_epoll_input_node,static) = {
  .function = linux_epoll_input,
  .type = VLIB_NODE_TYPE_PRE_INPUT,
  .name = "unix-epoll-input",
};

clib_error_t *
linux_epoll_input_init (vlib_main_t * vm)
{
  clib_file_main_t *fm = &file_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  for (u32 i = 1; i < tm->n_vlib_mains; i++)
    vlib_get_main_by_index (i)->epoll_fd = -1;

  vm->epoll_fd = epoll_create (1);
  if (vm->epoll_fd < 0)
    return clib_error_return_unix (0, "epoll_create");

  fm->file_update = linux_epoll_file_update;

  return 0;
}

VLIB_INIT_FUNCTION (linux_epoll_input_init);

#endif /* HAVE_LINUX_EPOLL */

static clib_error_t *
unix_input_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (unix_input_init) =
{
  .runs_before = VLIB_INITS ("linux_epoll_input_init"),
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
