/* 
 *------------------------------------------------------------------
 * memory_client.c - API message handling, client code.
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
#include <setjmp.h>
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
#include <vppinfra/mheap.h>
#include <vppinfra/heap.h>
#include <vppinfra/pool.h>
#include <vppinfra/format.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlibmemory/api.h>

#include <vlibmemory/vl_memory_msg_enum.h>

#define vl_typedefs             /* define message structures */
#include <vlibmemory/vl_memory_api_h.h> 
#undef vl_typedefs

#define vl_endianfun             /* define message structures */
#include <vlibmemory/vl_memory_api_h.h> 
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) clib_warning (__VA_ARGS__)
#define vl_printfun
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_printfun

typedef struct {
    u8 rx_thread_jmpbuf_valid;
    u8 connected_to_vlib;
    jmp_buf rx_thread_jmpbuf;
    pthread_t rx_thread_handle;
    /* Plugin message base lookup scheme */
    volatile u8 first_msg_id_reply_ready;
    u16 first_msg_id_reply;
} memory_client_main_t;

memory_client_main_t memory_client_main;

static void *rx_thread_fn(void *arg)
{
    unix_shared_memory_queue_t *q;
    memory_client_main_t *mm = &memory_client_main;
    api_main_t *am = &api_main;

    q = am->vl_input_queue;

    /* So we can make the rx thread terminate cleanly */
    if (setjmp(mm->rx_thread_jmpbuf) == 0) {
        mm->rx_thread_jmpbuf_valid = 1;
        while (1) {
            vl_msg_api_queue_handler (q);
        }
    }
    pthread_exit(0);
}

static void vl_api_rx_thread_exit_t_handler (
    vl_api_rx_thread_exit_t *mp)
{
    memory_client_main_t *mm = &memory_client_main;
    vl_msg_api_free (mp);
    longjmp (mm->rx_thread_jmpbuf, 1);
}

static void noop_handler (void *notused)
{
}

#define foreach_api_msg						\
_(RX_THREAD_EXIT, rx_thread_exit)

static int connect_to_vlib_internal (char *svm_name, char *client_name, 
                                     int rx_queue_size, int want_pthread)
{
    int rv=0;
    memory_client_main_t *mm = &memory_client_main;
    
    if ((rv = vl_client_api_map(svm_name))) {
        clib_warning ("vl_client_api map rv %d", rv);
        return rv;
    }
    
#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                            vl_api_##n##_t_handler,             \
                            noop_handler,                       \
                            vl_api_##n##_t_endian,              \
                            vl_api_##n##_t_print,               \
                            sizeof(vl_api_##n##_t), 1); 
    foreach_api_msg;
#undef _

    if (vl_client_connect(client_name, 0 /* punt quota */,
                          rx_queue_size /* input queue */) < 0) {
        vl_client_api_unmap();
        return -1;
    }

    /* Start the rx queue thread */
    
    if (want_pthread) {
        rv = pthread_create(&mm->rx_thread_handle, 
                            NULL /*attr*/, rx_thread_fn, 0);
        if (rv)
            clib_warning("pthread_create returned %d", rv);
    }
    
    mm->connected_to_vlib = 1;
    return 0;
}

int vl_client_connect_to_vlib(char *svm_name, char *client_name, 
                              int rx_queue_size)
{
    return connect_to_vlib_internal (svm_name, client_name, rx_queue_size,
                                     1 /* want pthread */);
}

int vl_client_connect_to_vlib_no_rx_pthread (char *svm_name, char *client_name, 
                                             int rx_queue_size)
{
    return connect_to_vlib_internal (svm_name, client_name, rx_queue_size,
                                     0 /* want pthread */);
}

void vl_client_disconnect_from_vlib (void)
{
    memory_client_main_t *mm = &memory_client_main;
    api_main_t *am = &api_main;
    uword junk;

    if (mm->rx_thread_jmpbuf_valid) {
        vl_api_rx_thread_exit_t *ep;
        ep = vl_msg_api_alloc (sizeof (*ep));
        ep->_vl_msg_id = ntohs(VL_API_RX_THREAD_EXIT);
        vl_msg_api_send_shmem (am->vl_input_queue, (u8 *)&ep);
        pthread_join (mm->rx_thread_handle, (void **) &junk);
    }
    if (mm->connected_to_vlib) {
        vl_client_disconnect();
        vl_client_api_unmap();
    }
    memset (mm, 0, sizeof (*mm));
}

static void vl_api_get_first_msg_id_reply_t_handler
(vl_api_get_first_msg_id_reply_t * mp)
{
    memory_client_main_t *mm = &memory_client_main;
    i32 retval = ntohl(mp->retval);

    mm->first_msg_id_reply = (retval >= 0) ? ntohs(mp->first_msg_id) : ~0;
    mm->first_msg_id_reply_ready = 1;
}

u16 vl_client_get_first_plugin_msg_id (char * plugin_name)
{
    vl_api_get_first_msg_id_t * mp;
    api_main_t * am = &api_main;
    memory_client_main_t * mm = &memory_client_main;
    f64 timeout;
    void * old_handler;
    clib_time_t clib_time;
    u16 rv = ~0;

    if (strlen(plugin_name) + 1 > sizeof (mp->name))
        return (rv);

    memset (&clib_time, 0, sizeof (clib_time));
    clib_time_init (&clib_time);

    /* Push this plugin's first_msg_id_reply handler */
    old_handler = am->msg_handlers[VL_API_GET_FIRST_MSG_ID_REPLY];
    am->msg_handlers[VL_API_GET_FIRST_MSG_ID_REPLY] = (void *)
        vl_api_get_first_msg_id_reply_t_handler;

    /* Ask the data-plane for the message-ID base of the indicated plugin */
    mm->first_msg_id_reply_ready = 0;

    mp = vl_msg_api_alloc (sizeof(*mp));
    memset (mp, 0, sizeof (*mp));
    mp->_vl_msg_id = ntohs(VL_API_GET_FIRST_MSG_ID);
    mp->client_index = am->my_client_index;
    strncpy ((char *) mp->name, plugin_name, sizeof (mp->name) - 1);

    vl_msg_api_send_shmem (am->shmem_hdr->vl_input_queue, (u8 *)&mp);

    /* Synchronously wait for the answer */
    do {                                          
        timeout = clib_time_now (&clib_time) + 1.0;       
        
        while (clib_time_now (&clib_time) < timeout) {    
            if (mm->first_msg_id_reply_ready == 1) {         
                rv = mm->first_msg_id_reply;
                goto result;
            }                                     
        }                                         
        /* Restore old handler */
        am->msg_handlers[VL_API_GET_FIRST_MSG_ID_REPLY] = old_handler;

        return rv;
    } while(0);

result:

    /* Restore the old handler */
    am->msg_handlers[VL_API_GET_FIRST_MSG_ID_REPLY] = old_handler;

    if (rv == (u16) ~0)
        clib_warning ("plugin '%s' not registered", plugin_name);

    return rv;
}

void vlib_node_sync_stats (vlib_main_t * vm, vlib_node_t * n)
{ clib_warning ("STUB called..."); }
