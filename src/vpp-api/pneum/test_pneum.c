/*
 *------------------------------------------------------------------
 * test_pneum.c
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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>

#include <time.h>       /* time_t, time (for timestamp in second) */
#include <sys/timeb.h>  /* ftime, timeb (for timestamp in millisecond) */
#include <sys/time.h>   /* gettimeofday, timeval (for timestamp in microsecond) */

#include <vnet/vnet.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip.h>

#include <vpp/api/vpe_msg_enum.h>
#include <signal.h>
#include <setjmp.h>
#include "pneum.h"

#define vl_typedefs             /* define message structures */
#include <vpp/api/vpe_all_api_h.h> 
#undef vl_typedefs

/* we are not linking with vlib */
vlib_main_t vlib_global_main;
vlib_main_t **vlib_mains;

volatile int sigterm_received = 0;
volatile u32 result_ready;
volatile u16 result_msg_id;

/* M_NOALLOC: construct, but don't yet send a message */

#define M_NOALLOC(T,t)                          \
  do {						\
    result_ready = 0;                           \
    memset (mp, 0, sizeof (*mp));		\
    mp->_vl_msg_id = ntohs (VL_API_##T);	\
    mp->client_index = am->my_client_index;	\
  } while(0);



int
wrap_pneum_callback (char *data, int len)
{
  //printf("Callback %d\n", len);
  result_ready = 1;
  result_msg_id = ntohs(*((u16 *)data));
  return (0);
}

int main (int argc, char ** argv)
{
  api_main_t * am = &api_main;
  vl_api_show_version_t message;
  vl_api_show_version_t *mp;
  int async = 1;
  int rv = pneum_connect("pneum_client", NULL, NULL, 32 /* rx queue-length*/);

  if (rv != 0) {
    printf("Connect failed: %d\n", rv);
    exit(rv);
  }
 
 struct timeb timer_msec;
  long long int timestamp_msec_start; /* timestamp in millisecond. */
  if (!ftime(&timer_msec)) {
    timestamp_msec_start = ((long long int) timer_msec.time) * 1000ll + 
      (long long int) timer_msec.millitm;
  }
  else {
    timestamp_msec_start = -1;
  }

 
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
    pneum_write((char *)mp, sizeof(*mp));
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
    pneum_write((char *)mp, sizeof(*mp));

    while (result_msg_id != VL_API_CONTROL_PING_REPLY);
  }

  long long int timestamp_msec_end; /* timestamp in millisecond. */
  if (!ftime(&timer_msec)) {
    timestamp_msec_end = ((long long int) timer_msec.time) * 1000ll + 
      (long long int) timer_msec.millitm;
  }
  else {
    timestamp_msec_end = -1;
  }
  
  printf("Took %lld msec, %lld msgs/msec \n", (timestamp_msec_end - timestamp_msec_start),
	 no_msgs/(timestamp_msec_end - timestamp_msec_start));
  fformat(stdout, "Exiting...\n");
  pneum_disconnect();
  exit (0);
}
