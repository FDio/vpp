/*
 *------------------------------------------------------------------
 * api.c - message handler registration
 *
 * Copyright (c) 2010 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <vppinfra/clib.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/fifo.h>
#include <vppinfra/time.h>
#include <vppinfra/heap.h>
#include <vppinfra/pool.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>

#include <vnet/vnet.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <svm/svm.h>
#include <svm/svmdb.h>

#include <vpp/api/vpe_msg_enum.h>

#include <vnet/ip/ip.h>

#define f64_endian(a)
#define f64_print(a,b)

#define vl_typedefs		/* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <vpp/api/vpe_all_api_h.h>
#undef vl_printfun

vl_shmem_hdr_t *shmem_hdr;

typedef struct
{
  u32 pings_sent;
  u32 pings_replied;
  volatile u32 signal_received;

  /* convenience */
  svm_queue_t *vl_input_queue;
  u32 my_client_index;
  svmdb_client_t *svmdb_client;
} test_main_t;

test_main_t test_main;

static void vl_api_control_ping_reply_t_handler
  (vl_api_control_ping_reply_t * mp)
{
  test_main_t *tm = &test_main;

  fformat (stdout, "control ping reply from pid %d\n", ntohl (mp->vpe_pid));
  tm->pings_replied++;
}

vlib_main_t **vlib_mains;

void
vlib_cli_output (struct vlib_main_t *vm, char *fmt, ...)
{
  clib_warning ("BUG: vlib_cli_output called...");
}

#define foreach_api_msg                         \
_(CONTROL_PING_REPLY,control_ping_reply)

void
ping (test_main_t * tm)
{
  vl_api_control_ping_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_CONTROL_PING);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;

  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}

static void
noop_handler (void *notused)
{
}

int
connect_to_vpe (char *name)
{
  int rv = 0;
  test_main_t *tm = &test_main;
  api_main_t *am = vlibapi_get_main ();

  rv = vl_client_connect_to_vlib ("/vpe-api", name, 32);
  if (rv < 0)
    return rv;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           noop_handler,                        \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_api_msg;
#undef _

  shmem_hdr = api_main.shmem_hdr;
  tm->vl_input_queue = shmem_hdr->vl_input_queue;
  tm->my_client_index = am->my_client_index;
  return 0;
}

int
disconnect_from_vpe (void)
{
  vl_client_disconnect_from_vlib ();

  return 0;
}

void
signal_handler (int signo)
{
  test_main_t *tm = &test_main;

  tm->signal_received = 1;
}


int
main (int argc, char **argv)
{
  test_main_t *tm = &test_main;
  api_main_t *am = vlibapi_get_main ();
  u32 swt_pid = 0;
  int connected = 0;

  signal (SIGINT, signal_handler);

  while (1)
    {
      if (tm->signal_received)
	break;

      if (am->shmem_hdr)
	swt_pid = am->shmem_hdr->vl_pid;

      /* If kill returns 0, the vpe-f process is alive */
      if (kill (swt_pid, 0) == 0)
	{
	  /* Try to connect */
	  if (connected == 0)
	    {
	      fformat (stdout, "Connect to VPE-f\n");
	      if (connect_to_vpe ("test_ha_client") >= 0)
		{
		  tm->pings_sent = 0;
		  tm->pings_replied = 0;
		  connected = 1;
		}
	      else
		{
		  fformat (stdout, "Connect failed, sleep and retry...\n");
		  sleep (1);
		  continue;
		}
	    }
	  tm->pings_sent++;
	  ping (tm);

	  sleep (1);

	  /* havent heard back in 3 seconds, disco / reco */
	  if ((tm->pings_replied + 3) <= tm->pings_sent)
	    {
	      fformat (stdout, "VPE-f pid %d not responding\n", swt_pid);
	      swt_pid = 0;
	      disconnect_from_vpe ();
	      connected = 0;
	    }
	}
      else
	{
	  if (connected)
	    {
	      fformat (stdout, "VPE-f pid %d died\n", swt_pid);
	      swt_pid = 0;
	      disconnect_from_vpe ();
	      connected = 0;
	    }
	  sleep (1);
	}
    }

  fformat (stdout, "Signal received, graceful exit\n");
  disconnect_from_vpe ();
  exit (0);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
