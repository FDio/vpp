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

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/eventfd.h>

#include <vc_conn.h>
#include <vc_keepalive.h>

#include <vc_log.h>

vapi_ctx_t vapi_ctx;

static char *app_name = "vc";
static char *api_prefix = NULL;
static const int max_outstanding_requests = 64;
static const int response_queue_size = 32;


static pthread_attr_t pattr;
static pthread_t pid;

static int efd;

/* three missed polls means dead */
#define N_POLLS 3
typedef struct vc_conn_poll_t
{
  u8 pos;
  u8 res[N_POLLS];
} vc_conn_poll_t;

vc_conn_poll_t vc_conn_poll;

bool
vc_conn_up (void)
{
  u8 n;

  for (n = 0; n < N_POLLS; n++)
    {
      if (vc_conn_poll.res[n])
	return (true);
    }
  return (false);
}

#define ARRAY_LEN(x)	(sizeof (x)/sizeof (x[0]))

static void
vc_conn_init (void)
{
  memset (vc_conn_poll.res, 1, ARRAY_LEN (vc_conn_poll.res));
}

static void
vc_conn_inc (u8 res)
{
  vc_conn_poll.res[vc_conn_poll.pos] = res;
  vc_conn_poll.pos = (vc_conn_poll.pos + 1) % 3;
}

static void *
vc_conn_loop (void *c)
{
  vapi_ctx_t v = c;
  vapi_error_e e;
  u64 counter;

  counter = 1;

  while (true)
    {
      e = vapi_wait (v, VAPI_WAIT_FOR_READ, 1);

      switch (e)
	{
	case VAPI_EAGAIN:
	  /* nothing doing this time around the loop */
	  vc_keepalive (v);
	  vc_conn_inc (0);
	  eventfd_write (efd, counter);

	  break;
	case VAPI_OK:
	  /* have message, poke main thread - write garbage */
	  vc_conn_inc (1);

	  eventfd_write (efd, counter);
	  break;
	default:
	  /* oops */
	  eventfd_write (efd, counter);
	  break;
	}

      ++counter;
    }

  return (NULL);
}

void
vc_conn_dispatch (int efd)
{
  eventfd_t garbage;

  while (0 == eventfd_read (efd, &garbage))
    {
      vapi_error_e rv = vapi_dispatch (vapi_ctx);

      // VC_DBG("dispatch:%ld, %d", garbage, rv);
      VC_ASSERT (rv == VAPI_OK);
    }
}

int
vc_conn_connect (void)
{
  vapi_error_e rv;
  int perr;

  vc_conn_init ();

  rv = vapi_ctx_alloc (&vapi_ctx);

  if (VAPI_OK != rv)
    {
      VC_ERROR ("Could not allocate VAPI context");
      exit (EXIT_FAILURE);
    }

  perr = pthread_attr_init (&pattr);

  if (perr != 0)
    {
      VC_ERROR ("Could not init pthread attribute");
      exit (EXIT_FAILURE);
    }

  do
    {
      rv = vapi_connect (vapi_ctx,
			 app_name,
			 api_prefix,
			 max_outstanding_requests,
			 response_queue_size, VAPI_MODE_NONBLOCKING, true);
    }
  while (VAPI_OK != rv);

  perr = pthread_create (&pid, &pattr, vc_conn_loop, vapi_ctx);

  if (perr != 0)
    {
      VC_ERROR ("Could not init pthread attribute");
      exit (EXIT_FAILURE);
    }

  efd = eventfd (0, EFD_CLOEXEC | EFD_NONBLOCK);

  if (efd == -1)
    {
      VC_ERROR ("Could not init event FD");
      exit (EXIT_FAILURE);
    }

  return (efd);
}

vapi_ctx_t
vc_conn_ctx (void)
{
  return (vapi_ctx);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
