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
#include <stdlib.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
#include <setjmp.h>
#include <stdbool.h>

#include <vnet/vnet.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vpp-api/vpe_msg_enum.h>

#include "pneum.h"

#define vl_typedefs             /* define message structures */
#include <vpp-api/vpe_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun             /* define message structures */
#include <vpp-api/vpe_all_api_h.h>
#undef vl_endianfun

typedef struct {
  u8 rx_thread_jmpbuf_valid;
  u8 connected_to_vlib;
  jmp_buf rx_thread_jmpbuf;
  pthread_t rx_thread_handle;
} pneum_main_t;

pneum_main_t pneum_main;

extern int wrap_pneum_callback(char *data, int len);

/*
 * Satisfy external references when -lvlib is not available.
 */
void vlib_cli_output (struct vlib_main_t * vm, char * fmt, ...)
{
  clib_warning ("vlib_cli_output called...");
}

#define vl_api_version(n,v) static u32 vpe_api_version = v;
#include <vpp-api/vpe.api.h>
#undef vl_api_version
void
vl_client_add_api_signatures (vl_api_memclnt_create_t *mp)
{
  /*
   * Send the main API signature in slot 0. This bit of code must
   * match the checks in ../vpe/api/api.c: vl_msg_api_version_check().
   */
  mp->api_versions[0] = clib_host_to_net_u32 (vpe_api_version);
}

static void
pneum_api_handler (void *msg)
{
  u16 id = ntohs(*((u16 *)msg));

  if (id == VL_API_RX_THREAD_EXIT) {
    pneum_main_t *pm = &pneum_main;
    vl_msg_api_free(msg);
    longjmp(pm->rx_thread_jmpbuf, 1);
  }
  msgbuf_t *msgbuf = (msgbuf_t *)(((u8 *)msg) - offsetof(msgbuf_t, data));
  int l = ntohl(msgbuf->data_len);
  if (l == 0)
    clib_warning("Message ID %d has wrong length: %d\n", id, l);

  /* Call Python callback */
  (void)wrap_pneum_callback(msg, l);
  vl_msg_api_free(msg);
}

static void *
pneum_rx_thread_fn (void *arg)
{
  unix_shared_memory_queue_t *q;
  pneum_main_t *pm = &pneum_main;
  api_main_t *am = &api_main;
  uword msg;

  q = am->vl_input_queue;

  /* So we can make the rx thread terminate cleanly */
  if (setjmp(pm->rx_thread_jmpbuf) == 0) {
    pm->rx_thread_jmpbuf_valid = 1;
    while (1)
      while (!unix_shared_memory_queue_sub(q, (u8 *)&msg, 0))
        pneum_api_handler((void *)msg);
  }
  pthread_exit(0);
}

int
pneum_connect (char *name)
{
  int rv = 0;
  pneum_main_t *pm = &pneum_main;

  if ((rv = vl_client_api_map("/vpe-api"))) {
    clib_warning ("vl_client_api map rv %d", rv);
    return rv;
  }

  if (vl_client_connect(name, 0, 32) < 0) {
    vl_client_api_unmap();
    return (-1);
  }

  /* Start the rx queue thread */
  rv = pthread_create(&pm->rx_thread_handle, NULL, pneum_rx_thread_fn, 0);
  if (rv) {
    clib_warning("pthread_create returned %d", rv);
    vl_client_api_unmap();
    return (-1);
  }

  pm->connected_to_vlib = 1;

  return (0);
}

int
pneum_disconnect (void)
{
  api_main_t *am = &api_main;
  pneum_main_t *pm = &pneum_main;

  fformat (stdout,"disconnecting from vpe \n");

  if (pm->rx_thread_jmpbuf_valid) {
    vl_api_rx_thread_exit_t *ep;
    uword junk;
    ep = vl_msg_api_alloc (sizeof (*ep));
    ep->_vl_msg_id = ntohs(VL_API_RX_THREAD_EXIT);
    vl_msg_api_send_shmem(am->vl_input_queue, (u8 *)&ep);
    pthread_join(pm->rx_thread_handle, (void **) &junk);
  }
  if (pm->connected_to_vlib) {
    vl_client_disconnect();
    vl_client_api_unmap();
  }
  memset (pm, 0, sizeof (*pm));

  return (0);
}

int
pneum_read (char **p, int *l)
{
  unix_shared_memory_queue_t *q;
  api_main_t *am = &api_main;
  uword msg;

  *l = 0;

  if (am->our_pid == 0) return (-1);

  q = am->vl_input_queue;
  int rv = unix_shared_memory_queue_sub(q, (u8 *)&msg, 0);
  if (rv == 0) {
    u16 msg_id = ntohs(*((u16 *)msg));
    msgbuf_t *msgbuf = (msgbuf_t *)(((u8 *)msg) - offsetof(msgbuf_t, data));
    *l = ntohl(msgbuf->data_len);
    if (*l == 0) {
      printf("Unregistered API message: %d\n", msg_id);
      return (-1);
    }
    *p = (char *)msg;
  } else {
    printf("Read failed with %d\n", rv);
  }
  return (rv);
}

/*
 * XXX: Makes the assumption that client_index is the first member
 */
typedef VL_API_PACKED(struct _vl_api_header {
  u16 _vl_msg_id;
  u32 client_index;
}) vl_api_header_t;

static unsigned int
pneum_client_index (void)
{
  return (api_main.my_client_index);
}

int
pneum_write (char *p, int l)
{
  int rv = -1;
  api_main_t *am = &api_main;
  vl_api_header_t *mp = vl_msg_api_alloc(l);
  unix_shared_memory_queue_t *q;

  if (!mp) return (-1);
  memcpy(mp, p, l);
  mp->client_index = pneum_client_index();
  q = am->shmem_hdr->vl_input_queue;
  rv = unix_shared_memory_queue_add(q, (u8 *)&mp, 0);
  if (rv != 0) {
    printf("vpe_api_write fails: %d\n", rv);
    /* Clear message */
    vl_msg_api_free(mp);
  }
  return (rv);
}
