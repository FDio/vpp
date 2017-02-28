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

#include <stdio.h>
#include <setjmp.h>
#include <vppinfra/clib.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>
#include <vppinfra/time.h>
#include <vppinfra/macros.h>
#include <vnet/vnet.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp-api/vpe_msg_enum.h>
#include <svm_fifo_segment.h>

#define vl_typedefs		/* define message structures */
#include <vpp-api/vpe_all_api_h.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun		/* define message structures */
#include <vpp-api/vpe_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <vpp-api/vpe_all_api_h.h>
#undef vl_printfun

typedef enum
{
  STATE_START,
  STATE_READY,
  STATE_DISCONNECTING,
} connection_state_t;

typedef struct
{
  /* vpe input queue */
  unix_shared_memory_queue_t *vl_input_queue;

  /* API client handle */
  u32 my_client_index;

  /* role */
  int i_am_master;

  /* The URI we're playing with */
  u8 *uri;

  /* fifo segment */
  svm_fifo_segment_private_t *seg;

  svm_fifo_t *rx_fifo;
  svm_fifo_t *tx_fifo;

  /* For deadman timers */
  clib_time_t clib_time;

  /* State of the connection, shared between msg RX thread and main thread */
  volatile connection_state_t state;

  /* VNET_API_ERROR_FOO -> "Foo" hash table */
  uword *error_string_by_error_number;
} uritest_main_t;

#if CLIB_DEBUG > 0
#define NITER 1000
#else
#define NITER 1000000
#endif

uritest_main_t uritest_main;

u8 *
format_api_error (u8 * s, va_list * args)
{
  uritest_main_t *utm = va_arg (*args, uritest_main_t *);
  i32 error = va_arg (*args, u32);
  uword *p;

  p = hash_get (utm->error_string_by_error_number, -error);

  if (p)
    s = format (s, "%s", p[0]);
  else
    s = format (s, "%d", error);
  return s;
}

int
wait_for_state_change (uritest_main_t * utm, connection_state_t state)
{
  f64 timeout = clib_time_now (&utm->clib_time) + 1.0;

  while (clib_time_now (&utm->clib_time) < timeout)
    {
      if (utm->state == state)
	return 0;
    }
  return -1;
}

static void
vl_api_bind_uri_reply_t_handler (vl_api_bind_uri_reply_t * mp)
{
  uritest_main_t *utm = &uritest_main;
  svm_fifo_segment_create_args_t _a, *a = &_a;
  int rv;

  ASSERT (utm->i_am_master);

  if (mp->segment_name_length == 0)
    {
      clib_warning ("segment_name_length zero");
      return;
    }

  a->segment_name = (char *) mp->segment_name;
  a->segment_size = mp->segment_size;

  /* Create the segment */
  rv = svm_fifo_segment_create (a);
  if (rv)
    {
      clib_warning ("sm_fifo_segment_create ('%s') failed", mp->segment_name);
      return;
    }

  vec_validate (utm->seg, 0);

  memcpy (utm->seg, a->rv, sizeof (*utm->seg));

  /*
   * By construction the master's idea of the rx fifo ends up in
   * fsh->fifos[0], and the master's idea of the tx fifo ends up in
   * fsh->fifos[1].
   */
  utm->rx_fifo = svm_fifo_segment_alloc_fifo (utm->seg, 10240);
  ASSERT (utm->rx_fifo);

  utm->tx_fifo = svm_fifo_segment_alloc_fifo (utm->seg, 10240);
  ASSERT (utm->tx_fifo);

  utm->state = STATE_READY;
}

static void
vl_api_connect_uri_reply_t_handler (vl_api_connect_uri_reply_t * mp)
{
  uritest_main_t *utm = &uritest_main;
  svm_fifo_segment_create_args_t _a, *a = &_a;
  ssvm_shared_header_t *sh;
  svm_fifo_segment_header_t *fsh;
  int rv;

  ASSERT (utm->i_am_master == 0);

  if (mp->segment_name_length == 0)
    {
      clib_warning ("segment_name_length zero");
      return;
    }

  memset (a, 0, sizeof (*a));

  a->segment_name = (char *) mp->segment_name;

  rv = svm_fifo_segment_attach (a);
  if (rv)
    {
      clib_warning ("sm_fifo_segment_create ('%s') failed", mp->segment_name);
      return;
    }

  vec_validate (utm->seg, 0);

  memcpy (utm->seg, a->rv, sizeof (*utm->seg));
  sh = utm->seg->ssvm.sh;
  fsh = (svm_fifo_segment_header_t *) sh->opaque[0];

  while (vec_len (fsh->fifos) < 2)
    sleep (1);

  utm->rx_fifo = (svm_fifo_t *) fsh->fifos[1];
  ASSERT (utm->rx_fifo);
  utm->tx_fifo = (svm_fifo_t *) fsh->fifos[0];
  ASSERT (utm->tx_fifo);

  /* security: could unlink /dev/shm/<mp->segment_name> here, maybe */

  utm->state = STATE_READY;
}

static void
vl_api_unbind_uri_reply_t_handler (vl_api_unbind_uri_reply_t * mp)
{
  uritest_main_t *utm = &uritest_main;

  if (mp->retval != 0)
    clib_warning ("returned %d", ntohl (mp->retval));

  utm->state = STATE_START;
}

#define foreach_uri_msg                         \
_(BIND_URI_REPLY, bind_uri_reply)               \
_(CONNECT_URI_REPLY, connect_uri_reply)         \
_(UNBIND_URI_REPLY, unbind_uri_reply)

void
uri_api_hookup (uritest_main_t * utm)
{
#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,	        \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_uri_msg;
#undef _

}


int
connect_to_vpp (char *name)
{
  uritest_main_t *utm = &uritest_main;
  api_main_t *am = &api_main;

  if (vl_client_connect_to_vlib ("/vpe-api", name, 32) < 0)
    return -1;

  utm->vl_input_queue = am->shmem_hdr->vl_input_queue;
  utm->my_client_index = am->my_client_index;

  return 0;
}

void
vlib_cli_output (struct vlib_main_t *vm, char *fmt, ...)
{
  clib_warning ("BUG");
}

static void
init_error_string_table (uritest_main_t * utm)
{
  utm->error_string_by_error_number = hash_create (0, sizeof (uword));

#define _(n,v,s) hash_set (utm->error_string_by_error_number, -v, s);
  foreach_vnet_api_error;
#undef _

  hash_set (utm->error_string_by_error_number, 99, "Misc");
}

void
uritest_master (uritest_main_t * utm)
{
  vl_api_bind_uri_t *bmp;
  vl_api_unbind_uri_t *ump;
  int i;
  u8 *test_data = 0;
  u8 *reply = 0;
  u32 reply_len;
  int mypid = getpid ();

  for (i = 0; i < 2048; i++)
    vec_add1 (test_data, 'a' + (i % 32));

  bmp = vl_msg_api_alloc (sizeof (*bmp));
  memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_BIND_URI);
  bmp->client_index = utm->my_client_index;
  bmp->context = ntohl (0xfeedface);
  bmp->segment_size = 256 << 10;
  memcpy (bmp->uri, utm->uri, vec_len (utm->uri));
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & bmp);

  if (wait_for_state_change (utm, STATE_READY))
    {
      clib_warning ("timeout waiting for STATE_READY");
      return;
    }

  for (i = 0; i < NITER; i++)
    svm_fifo_enqueue (utm->tx_fifo, mypid, vec_len (test_data), test_data);

  vec_validate (reply, 0);

  reply_len = svm_fifo_dequeue (utm->rx_fifo, mypid, vec_len (reply), reply);

  if (reply_len != 1)
    clib_warning ("reply length %d", reply_len);

  if (reply[0] == 1)
    fformat (stdout, "Test OK...");

  ump = vl_msg_api_alloc (sizeof (*ump));
  memset (ump, 0, sizeof (*ump));

  ump->_vl_msg_id = ntohs (VL_API_UNBIND_URI);
  ump->client_index = utm->my_client_index;
  memcpy (ump->uri, utm->uri, vec_len (utm->uri));
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & ump);

  if (wait_for_state_change (utm, STATE_START))
    {
      clib_warning ("timeout waiting for STATE_READY");
      return;
    }

  fformat (stdout, "Master done...\n");
}

void
uritest_slave (uritest_main_t * utm)
{
  vl_api_connect_uri_t *cmp;
  int i, j;
  u8 *test_data = 0;
  u8 *reply = 0;
  u32 bytes_received = 0;
  u32 actual_bytes;
  int mypid = getpid ();
  u8 ok;
  f64 before, after, delta, bytes_per_second;

  vec_validate (test_data, 4095);

  cmp = vl_msg_api_alloc (sizeof (*cmp));
  memset (cmp, 0, sizeof (*cmp));

  cmp->_vl_msg_id = ntohs (VL_API_CONNECT_URI);
  cmp->client_index = utm->my_client_index;
  cmp->context = ntohl (0xfeedface);
  memcpy (cmp->uri, utm->uri, vec_len (utm->uri));
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & cmp);

  if (wait_for_state_change (utm, STATE_READY))
    {
      clib_warning ("timeout waiting for STATE_READY");
      return;
    }

  ok = 1;
  before = clib_time_now (&utm->clib_time);
  for (i = 0; i < NITER; i++)
    {
      actual_bytes = svm_fifo_dequeue (utm->rx_fifo, mypid,
				       vec_len (test_data), test_data);
      j = 0;
      while (j < actual_bytes)
	{
	  if (test_data[j] != ('a' + (bytes_received % 32)))
	    ok = 0;
	  bytes_received++;
	  j++;
	}
      if (bytes_received == NITER * 2048)
	break;
    }

  vec_add1 (reply, ok);

  svm_fifo_enqueue (utm->tx_fifo, mypid, vec_len (reply), reply);
  after = clib_time_now (&utm->clib_time);
  delta = after - before;
  bytes_per_second = 0.0;

  if (delta > 0.0)
    bytes_per_second = (f64) bytes_received / delta;

  fformat (stdout,
	   "Slave done, %d bytes in %.2f seconds, %.2f bytes/sec...\n",
	   bytes_received, delta, bytes_per_second);
}

int
main (int argc, char **argv)
{
  uritest_main_t *utm = &uritest_main;
  unformat_input_t _argv, *a = &_argv;
  u8 *chroot_prefix;
  u8 *heap;
  char *bind_name = "fifo:uritest";
  mheap_t *h;
  int i_am_master = 0;

  clib_mem_init (0, 128 << 20);

  heap = clib_mem_get_per_cpu_heap ();
  h = mheap_header (heap);

  /* make the main heap thread-safe */
  h->flags |= MHEAP_FLAG_THREAD_SAFE;

  clib_time_init (&utm->clib_time);
  init_error_string_table (utm);
  svm_fifo_segment_init (0x200000000ULL, 20);
  unformat_init_command_line (a, argv);

  utm->uri = format (0, "%s%c", bind_name, 0);

  while (unformat_check_input (a) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (a, "master"))
	i_am_master = 1;
      else if (unformat (a, "slave"))
	i_am_master = 0;
      else if (unformat (a, "chroot prefix %s", &chroot_prefix))
	{
	  vl_set_memory_root_path ((char *) chroot_prefix);
	}
      else
	{
	  fformat (stderr, "%s: usage [master|slave]\n");
	  exit (1);
	}
    }

  uri_api_hookup (utm);

  if (connect_to_vpp (i_am_master ? "uritest_master" : "uritest_slave") < 0)
    {
      svm_region_exit ();
      fformat (stderr, "Couldn't connect to vpe, exiting...\n");
      exit (1);
    }

  utm->i_am_master = i_am_master;

  if (i_am_master)
    uritest_master (utm);
  else
    uritest_slave (utm);

  vl_client_disconnect_from_vlib ();
  exit (0);
}

#undef vl_api_version
#define vl_api_version(n,v) static u32 vpe_api_version = v;
#include <vpp-api/vpe.api.h>
#undef vl_api_version

void
vl_client_add_api_signatures (vl_api_memclnt_create_t * mp)
{
  /*
   * Send the main API signature in slot 0. This bit of code must
   * match the checks in ../vpe/api/api.c: vl_msg_api_version_check().
   */
  mp->api_versions[0] = clib_host_to_net_u32 (vpe_api_version);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
