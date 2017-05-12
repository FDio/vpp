/*
 *------------------------------------------------------------------
 * summary_stats_client -
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
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>
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
#include <vppinfra/mheap.h>
#include <vppinfra/heap.h>
#include <vppinfra/pool.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>

#include <vnet/vnet.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

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
  volatile int sigterm_received;

  struct sockaddr_in send_data_addr;
  int send_data_socket;
  u8 *display_name;

  /* convenience */
  unix_shared_memory_queue_t *vl_input_queue;
  u32 my_client_index;
} test_main_t;

test_main_t test_main;

/*
 * Satisfy external references when -lvlib is not available.
 */
vlib_main_t vlib_global_main;
vlib_main_t **vlib_mains;

void
vlib_cli_output (struct vlib_main_t *vm, char *fmt, ...)
{
  clib_warning ("vlib_cli_output callled...");
}


static void
  vl_api_vnet_get_summary_stats_reply_t_handler
  (vl_api_vnet_get_summary_stats_reply_t * mp)
{
  test_main_t *tm = &test_main;
  static u8 *sb;
  int n;

  printf ("total rx pkts %llu, total rx bytes %llu\n",
	  (unsigned long long) mp->total_pkts[0],
	  (unsigned long long) mp->total_bytes[0]);
  printf ("total tx pkts %llu, total tx bytes %llu\n",
	  (unsigned long long) mp->total_pkts[1],
	  (unsigned long long) mp->total_bytes[1]);
  printf ("vector rate %.2f\n", mp->vector_rate);

  vec_reset_length (sb);
  sb = format (sb, "%v,%.0f,%llu,%llu,%llu,%llu\n%c",
	       tm->display_name, mp->vector_rate,
	       (unsigned long long) mp->total_pkts[0],
	       (unsigned long long) mp->total_bytes[0],
	       (unsigned long long) mp->total_pkts[1],
	       (unsigned long long) mp->total_bytes[1], 0);

  n = sendto (tm->send_data_socket, sb, vec_len (sb),
	      0, (struct sockaddr *) &tm->send_data_addr,
	      sizeof (tm->send_data_addr));

  if (n != vec_len (sb))
    clib_unix_warning ("sendto");

}

#define foreach_api_msg                                                 \
_(VNET_GET_SUMMARY_STATS_REPLY, vnet_get_summary_stats_reply)

int
connect_to_vpe (char *name)
{
  int rv = 0;

  rv = vl_client_connect_to_vlib ("/vpe-api", name, 32);

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_api_msg;
#undef _

  shmem_hdr = api_main.shmem_hdr;

  return rv;
}

int
disconnect_from_vpe (void)
{
  vl_client_disconnect_from_vlib ();
  return 0;
}

static void
sigterm_handler (int sig)
{
  test_main_t *tm = &test_main;
  tm->sigterm_received = 1;
}

/* Parse an IP4 address %d.%d.%d.%d. */
uword
unformat_ip4_address (unformat_input_t * input, va_list * args)
{
  u8 *result = va_arg (*args, u8 *);
  unsigned a[4];

  if (!unformat (input, "%d.%d.%d.%d", &a[0], &a[1], &a[2], &a[3]))
    return 0;

  if (a[0] >= 256 || a[1] >= 256 || a[2] >= 256 || a[3] >= 256)
    return 0;

  result[0] = a[0];
  result[1] = a[1];
  result[2] = a[2];
  result[3] = a[3];

  return 1;
}

int
main (int argc, char **argv)
{
  api_main_t *am = &api_main;
  test_main_t *tm = &test_main;
  vl_api_vnet_get_summary_stats_t *mp;
  unformat_input_t _input, *input = &_input;
  clib_error_t *error = 0;
  ip4_address_t collector_ip;
  u8 *display_name = 0;
  u16 collector_port = 7654;

  collector_ip.as_u32 = (u32) ~ 0;

  unformat_init_command_line (input, argv);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "collector-ip %U",
		    unformat_ip4_address, &collector_ip))
	;
      else if (unformat (input, "display-name %v", &display_name))
	;
      else if (unformat (input, "collector-port %d", &collector_port))
	;
      else
	{
	  error =
	    clib_error_return
	    (0, "Usage: %s collector-ip <ip>\n"
	     "    [display-name <string>] [collector-port <num>]\n"
	     "    port defaults to 7654", argv[0]);
	  break;
	}
    }

  if (error == 0 && collector_ip.as_u32 == (u32) ~ 0)
    error = clib_error_return (0, "collector-ip not set...\n");


  if (error)
    {
      clib_error_report (error);
      exit (1);
    }

  if (display_name == 0)
    {
      display_name = format (0, "vpe-to-%d.%d.%d.%d",
			     collector_ip.as_u8[0],
			     collector_ip.as_u8[1],
			     collector_ip.as_u8[2], collector_ip.as_u8[3]);
    }


  connect_to_vpe ("test_client");

  tm->vl_input_queue = shmem_hdr->vl_input_queue;
  tm->my_client_index = am->my_client_index;
  tm->display_name = display_name;

  signal (SIGTERM, sigterm_handler);
  signal (SIGINT, sigterm_handler);
  signal (SIGQUIT, sigterm_handler);

  /* data (multicast) RX socket */
  tm->send_data_socket = socket (PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (tm->send_data_socket < 0)
    {
      clib_unix_warning (0, "data_rx_socket");
      exit (1);
    }

  memset (&tm->send_data_addr, 0, sizeof (tm->send_data_addr));
  tm->send_data_addr.sin_family = AF_INET;
  tm->send_data_addr.sin_addr.s_addr = collector_ip.as_u32;
  tm->send_data_addr.sin_port = htons (collector_port);

  fformat (stdout, "Send SIGINT or SIGTERM to quit...\n");

  while (1)
    {
      sleep (5);

      if (tm->sigterm_received)
	break;
      /* Poll for stats */
      mp = vl_msg_api_alloc (sizeof (*mp));
      memset (mp, 0, sizeof (*mp));
      mp->_vl_msg_id = ntohs (VL_API_VNET_GET_SUMMARY_STATS);
      mp->client_index = tm->my_client_index;
      vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
    }

  fformat (stdout, "Exiting...\n");

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
