/*
 *------------------------------------------------------------------
 * test.c -- VPP API/Stats tests
 * 
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
 *------------------------------------------------------------------
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>


#include <vnet/vnet.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlibapi/api.h>
#include <vppinfra/time.h>
#include <vpp/api/vpe_msg_enum.h>
#include <signal.h>
#include "vppapiclient.h"
#include "stat_client.h"

#define vl_typedefs             /* define message structures */
#include <vpp/api/vpe_all_api_h.h> 
#undef vl_typedefs

/* we are not linking with vlib */
vlib_main_t **vlib_mains;

volatile int sigterm_received = 0;
volatile u32 result_ready;
volatile u16 result_msg_id;

/* M_NOALLOC: construct, but don't yet send a message */

#define M_NOALLOC(T,t)                          \
  do {						\
    result_ready = 0;                           \
    clib_memset (mp, 0, sizeof (*mp));		\
    mp->_vl_msg_id = ntohs (VL_API_##T);	\
    mp->client_index = am->my_client_index;	\
  } while(0);



void
wrap_vac_callback (unsigned char *data, int len)
{
  result_ready = 1;
  result_msg_id = ntohs(*((u16 *)data));
}

static void
test_connect ()
{
  static int i;
  int rv = vac_connect("vac_client", NULL, wrap_vac_callback, 32 /* rx queue-length*/);
  if (rv != 0) {
    printf("Connect failed: %d\n", rv);
    exit(rv);
  }
  printf(".");
  vac_disconnect();
  i++;
}

static void
test_messages (void)
{
  api_main_t * am = vlibapi_get_main();
  vl_api_show_version_t message;
  vl_api_show_version_t *mp;
  int async = 1;

  int rv = vac_connect("vac_client", NULL, wrap_vac_callback, 32 /* rx queue-length*/);
  if (rv != 0) {
    printf("Connect failed: %d\n", rv);
    exit(rv);
  }

  double timestamp_start = unix_time_now_nsec() * 1e-6;
 
  /*
   * Test vpe_api_write and vpe_api_read to send and recv message for an
   * API 
   */
  int i;
  long int no_msgs = 10000;
  mp = &message;

  for (i = 0; i < no_msgs; i++) {
    /* Construct the API message */
    M_NOALLOC(SHOW_VERSION, show_version);
    vac_write((char *)mp, sizeof(*mp));
#ifndef __COVERITY__
    /* As given, async is always 1. Shut up Coverity about it */
    if (!async)
      while (result_ready == 0);
#endif
  }
  if (async) {
    vl_api_control_ping_t control;
    vl_api_control_ping_t *mp;
    mp = &control;
    M_NOALLOC(CONTROL_PING, control_ping);
    vac_write((char *)mp, sizeof(*mp));

    while (result_msg_id != VL_API_CONTROL_PING_REPLY);
  }

  double timestamp_end = unix_time_now_nsec() * 1e-6;
  printf("\nTook %.2f msec, %.0f msgs/msec \n", (timestamp_end - timestamp_start),
	 no_msgs/(timestamp_end - timestamp_start));
  printf("Exiting...\n");
  vac_disconnect();
}

static void
test_stats (void)
{
  clib_mem_trace_enable_disable(1);
  clib_mem_trace (1);

  int rv = stat_segment_connect (STAT_SEGMENT_SOCKET_FILE);
  assert(rv == 0);

  u32 *dir;
  int i, j, k;
  stat_segment_data_t *res;
  u8 **pattern = 0;
  vec_add1(pattern, (u8 *)"/if/names");
  vec_add1(pattern, (u8 *)"/err");

  dir = stat_segment_ls ((u8 **)pattern);

  res = stat_segment_dump (dir);
  for (i = 0; i < vec_len (res); i++) {
    switch (res[i].type) {
    case STAT_DIR_TYPE_NAME_VECTOR:
      if (res[i].name_vector == 0)
	continue;
      for (k = 0; k < vec_len (res[i].name_vector); k++)
	if (res[i].name_vector[k])
	  fformat (stdout, "[%d]: %s %s\n", k, res[i].name_vector[k],
		   res[i].name);
      break;
    case STAT_DIR_TYPE_ERROR_INDEX:
      for (j = 0; j < vec_len (res[i].error_vector); j++)
	fformat (stdout, "%llu %s\n", res[i].error_vector[j],
		 res[i].name);
      break;
    default:
      assert(0);
    }
  }
  stat_segment_data_free (res);
  stat_segment_disconnect();

  vec_free(pattern);
  vec_free(dir);

  (void) clib_mem_trace_enable_disable (0);
  u8 *leak_report = format (0, "%U", format_clib_mem_heap, 0,
                            1 /* verbose, i.e. print leaks */ );
  printf("%s", leak_report);
  vec_free (leak_report);
  clib_mem_trace (0);
}

int main (int argc, char ** argv)
{
  clib_mem_init (0, 3ULL << 30);
  test_stats();

  int i;

  for (i = 0; i < 1000; i++) {
    test_connect();
  }
  test_messages();
  exit (0);
}
