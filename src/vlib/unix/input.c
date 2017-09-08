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
#include <vlib/unix/unix.h>
#include <signal.h>
#include <vppinfra/tw_timer_1t_3w_1024sl_ov.h>

/* FIXME autoconf */
#define HAVE_LINUX_EPOLL

#ifdef HAVE_LINUX_EPOLL

#include <sys/epoll.h>

typedef struct
{
  int epoll_fd;
  struct epoll_event *epoll_events;

  /* Statistics. */
  u64 epoll_files_ready;
  u64 epoll_waits;
} linux_epoll_main_t;

static linux_epoll_main_t linux_epoll_main;

static void
linux_epoll_file_update (clib_file_t * f, unix_file_update_type_t update_type)
{
  clib_file_main_t *fm = &file_main;
  linux_epoll_main_t *em = &linux_epoll_main;
  struct epoll_event e;
  int op;

  memset (&e, 0, sizeof (e));

  e.events = EPOLLIN;
  if (f->flags & UNIX_FILE_DATA_AVAILABLE_TO_WRITE)
    e.events |= EPOLLOUT;
  if (f->flags & UNIX_FILE_EVENT_EDGE_TRIGGERED)
    e.events |= EPOLLET;
  e.data.u32 = f - fm->file_pool;

  op = -1;

  switch (update_type)
    {
    case UNIX_FILE_UPDATE_ADD:
      op = EPOLL_CTL_ADD;
      break;

    case UNIX_FILE_UPDATE_MODIFY:
      op = EPOLL_CTL_MOD;
      break;

    case UNIX_FILE_UPDATE_DELETE:
      op = EPOLL_CTL_DEL;
      break;

    default:
      clib_warning ("unknown update_type %d", update_type);
      return;
    }

  if (epoll_ctl (em->epoll_fd, op, f->file_descriptor, &e) < 0)
    clib_unix_warning ("epoll_ctl");
}

static uword
linux_epoll_input (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  unix_main_t *um = &unix_main;
  clib_file_main_t *fm = &file_main;
  linux_epoll_main_t *em = &linux_epoll_main;
  struct epoll_event *e;
  int n_fds_ready;

  {
    vlib_node_main_t *nm = &vm->node_main;
    u32 ticks_until_expiration;
    f64 timeout;
    int timeout_ms = 0, max_timeout_ms = 10;
    f64 vector_rate = vlib_last_vectors_per_main_loop (vm);

    /* If we're not working very hard, decide how long to sleep */
    if (vector_rate < 2 && vm->api_queue_nonempty == 0
	&& nm->input_node_counts_by_state[VLIB_NODE_STATE_POLLING] == 0)
      {
	ticks_until_expiration = TW (tw_timer_first_expires_in_ticks)
	  ((TWT (tw_timer_wheel) *) nm->timing_wheel);

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
    else			/* busy */
      {
	/* Don't come back for a respectable number of dispatch cycles */
	node->input_main_loops_per_call = 1024;
      }

    /* Allow any signal to wakeup our sleep. */
    {
      static sigset_t unblock_all_signals;
      n_fds_ready = epoll_pwait (em->epoll_fd,
				 em->epoll_events,
				 vec_len (em->epoll_events),
				 timeout_ms, &unblock_all_signals);

      /* This kludge is necessary to run over absurdly old kernels */
      if (n_fds_ready < 0 && errno == ENOSYS)
	{
	  n_fds_ready = epoll_wait (em->epoll_fd,
				    em->epoll_events,
				    vec_len (em->epoll_events), timeout_ms);
	}
    }
  }

  if (n_fds_ready < 0)
    {
      if (unix_error_is_fatal (errno))
	vlib_panic_with_error (vm, clib_error_return_unix (0, "epoll_wait"));

      /* non fatal error (e.g. EINTR). */
      return 0;
    }

  em->epoll_waits += 1;
  em->epoll_files_ready += n_fds_ready;

  for (e = em->epoll_events; e < em->epoll_events + n_fds_ready; e++)
    {
      u32 i = e->data.u32;
      clib_file_t *f = pool_elt_at_index (fm->file_pool, i);
      clib_error_t *errors[4];
      int n_errors = 0;

      if (PREDICT_TRUE (!(e->events & EPOLLERR)))
	{
	  if (e->events & EPOLLIN)
	    {
	      errors[n_errors] = f->read_function (f);
	      n_errors += errors[n_errors] != 0;
	    }
	  if (e->events & EPOLLOUT)
	    {
	      errors[n_errors] = f->write_function (f);
	      n_errors += errors[n_errors] != 0;
	    }
	}
      else
	{
	  if (f->error_function)
	    {
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

  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (linux_epoll_input_node,static) = {
  .function = linux_epoll_input,
  .type = VLIB_NODE_TYPE_PRE_INPUT,
  .name = "unix-epoll-input",
};
/* *INDENT-ON* */

clib_error_t *
linux_epoll_input_init (vlib_main_t * vm)
{
  linux_epoll_main_t *em = &linux_epoll_main;
  clib_file_main_t *fm = &file_main;

  /* Allocate some events. */
  vec_resize (em->epoll_events, VLIB_FRAME_SIZE);

  em->epoll_fd = epoll_create (vec_len (em->epoll_events));
  if (em->epoll_fd < 0)
    return clib_error_return_unix (0, "epoll_create");

  fm->file_update = linux_epoll_file_update;

  return 0;
}

VLIB_INIT_FUNCTION (linux_epoll_input_init);

#endif /* HAVE_LINUX_EPOLL */

static clib_error_t *
unix_input_init (vlib_main_t * vm)
{
  return vlib_call_init_function (vm, linux_epoll_input_init);
}

VLIB_INIT_FUNCTION (unix_input_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
