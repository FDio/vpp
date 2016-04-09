/* 
 *------------------------------------------------------------------
 * memclnt_shared.c - API message handling, common code for both clients
 * and the vlib process itself.
 * 
 *
 * Copyright (c) 2009 Cisco and/or its affiliates.
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
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <vppinfra/format.h>
#include <vppinfra/byte_order.h>
#include <vppinfra/error.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlibmemory/api.h>
#include <vlibmemory/unix_shared_memory_queue.h>

#include <vlibmemory/vl_memory_msg_enum.h>   

#define vl_typedefs 
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_typedefs

static inline void *vl_msg_api_alloc_internal(int nbytes, int pool)
{
    int i;
    msgbuf_t *rv;
    ring_alloc_t *ap;
    unix_shared_memory_queue_t *q;
    void *oldheap;
    vl_shmem_hdr_t *shmem_hdr;
    api_main_t *am = &api_main;

    shmem_hdr = am->shmem_hdr;

    if (shmem_hdr == 0) {
        clib_warning ("shared memory header NULL");
        return 0;
    }

    /* account for the msgbuf_t header*/
    nbytes += sizeof(msgbuf_t);

    if (shmem_hdr->vl_rings == 0) {
        clib_warning ("vl_rings NULL");
        return 0;
    }

    if (shmem_hdr->client_rings == 0) {
        clib_warning ("client_rings NULL");
        return 0;
    }

    ap = pool ? shmem_hdr->vl_rings : shmem_hdr->client_rings;
    for (i = 0; i < vec_len (ap); i++) {
        /* Too big? */
        if (nbytes > ap[i].size) {
            continue;
        }

        q = ap[i].rp;
        if (pool == 0) {
            pthread_mutex_lock(&q->mutex);
        }
        rv = (msgbuf_t *) (&q->data[0] + q->head*q->elsize);
        /*
         * Is this item still in use? 
         */
        if (rv->q) {
            /* yes, loser; try next larger pool */
            ap[i].misses++;
            if (pool == 0)
                pthread_mutex_unlock(&q->mutex);
            continue;
        }
        /* OK, we have a winner */
        ap[i].hits++;
        /*
         * Remember the source queue, although we
         * don't need to know the queue to free the item.
         */
        rv->q = q;
        q->head++;
        if (q->head == q->maxsize)
            q->head = 0;
                
        if (pool == 0)
            pthread_mutex_unlock(&q->mutex);
        goto out;
    }

    /*
     * Request too big, or head element of all size-compatible rings
     * still in use. Fall back to shared-memory malloc.
     */
    am->ring_misses++;

    pthread_mutex_lock (&am->vlib_rp->mutex);
    oldheap = svm_push_data_heap (am->vlib_rp);
    rv = clib_mem_alloc(nbytes);
    rv->q = 0;
    svm_pop_heap (oldheap);
    pthread_mutex_unlock (&am->vlib_rp->mutex);

 out:
    rv->data_len = htonl(nbytes - sizeof(msgbuf_t));
    return(rv->data);
}

void *vl_msg_api_alloc (int nbytes)
{
    int pool;
    api_main_t *am = &api_main;
    vl_shmem_hdr_t *shmem_hdr = am->shmem_hdr;

    /*
     * Clients use pool-0, vlib proc uses pool 1
     */
    pool = (am->our_pid == shmem_hdr->vl_pid);
    return vl_msg_api_alloc_internal (nbytes, pool);
}

void *vl_msg_api_alloc_as_if_client (int nbytes)
{
    return vl_msg_api_alloc_internal (nbytes, 0);
}

void vl_msg_api_free(void *a)
{
    msgbuf_t *rv;
    void *oldheap;
    api_main_t *am = &api_main;
    
    rv = (msgbuf_t *)(((u8 *)a) - offsetof(msgbuf_t, data));

    /*
     * Here's the beauty of the scheme.  Only one proc/thread has
     * control of a given message buffer. To free a buffer, we just clear the 
     * queue field, and leave. No locks, no hits, no errors...
     */
    if (rv->q) {
        rv->q = 0;
        return;
    }

    pthread_mutex_lock (&am->vlib_rp->mutex);
    oldheap = svm_push_data_heap (am->vlib_rp);
    clib_mem_free (rv);
    svm_pop_heap (oldheap);
    pthread_mutex_unlock (&am->vlib_rp->mutex);
}

static void vl_msg_api_free_nolock (void *a)
{
    msgbuf_t *rv;
    void *oldheap;
    api_main_t *am = &api_main;
    
    rv = (msgbuf_t *)(((u8 *)a) - offsetof(msgbuf_t, data));
    /*
     * Here's the beauty of the scheme.  Only one proc/thread has
     * control of a given message buffer. To free a buffer, we just clear the 
     * queue field, and leave. No locks, no hits, no errors...
     */
    if (rv->q) {
        rv->q = 0;
        return;
    }

    oldheap = svm_push_data_heap (am->vlib_rp);
    clib_mem_free (rv);
    svm_pop_heap (oldheap);
}

void vl_set_memory_root_path (char *name)
{
    api_main_t *am = &api_main;

    am->root_path = name;
}

int vl_map_shmem (char *region_name, int is_vlib)
{
    svm_map_region_args_t *a = 0;
    svm_region_t *vlib_rp, *root_rp;
    void *oldheap;
    vl_shmem_hdr_t *shmem_hdr=0;
    api_main_t *am = &api_main;
    int i;
    struct timespec ts, tsrem;

    if (is_vlib == 0)
        svm_region_init_chroot(am->root_path);

    vec_validate (a, 0);

    a->name = region_name;
    a->size = 16<<20;
    a->flags = SVM_FLAGS_MHEAP;

    vlib_rp = svm_region_find_or_create (a);
    
    vec_free (a);

    if (vlib_rp == 0)
        return (-2);

    pthread_mutex_lock (&vlib_rp->mutex);
    /* Has someone else set up the shared-memory variable table? */
    if (vlib_rp->user_ctx) {
        am->shmem_hdr = (void *) vlib_rp->user_ctx;
        am->our_pid = getpid();
        if (is_vlib) {
            unix_shared_memory_queue_t *q;
            uword old_msg;
            /* 
             * application restart. Reset cached pids, API message
             * rings, list of clients; otherwise, various things
             * fail. (e.g. queue non-empty notification) 
             */

            /* ghosts keep the region from disappearing properly */
            svm_client_scan_this_region_nolock(vlib_rp);
            am->shmem_hdr->application_restarts++;
            q = am->shmem_hdr->vl_input_queue;
            am->shmem_hdr->vl_pid = getpid();
            q->consumer_pid = am->shmem_hdr->vl_pid;
            /* Drain the input queue, freeing msgs */
            for (i = 0; i < 10; i++) {
                if (pthread_mutex_trylock (&q->mutex) == 0) {
                    pthread_mutex_unlock (&q->mutex);
                    goto mutex_ok;
                }
                ts.tv_sec = 0;
                ts.tv_nsec = 10000*1000;  /* 10 ms */
                while (nanosleep(&ts, &tsrem) < 0)
                    ts = tsrem;
            }
            /* Mutex buggered, "fix" it */
            memset (&q->mutex, 0, sizeof (q->mutex));
            clib_warning ("forcibly release main input queue mutex");

        mutex_ok:
	    am->vlib_rp = vlib_rp;
            while (unix_shared_memory_queue_sub (q, 
                                                 (u8 *)&old_msg, 
                                                 1 /* nowait */) 
                   != -2 /* queue underflow */) {
                vl_msg_api_free_nolock ((void *)old_msg);
                am->shmem_hdr->restart_reclaims++;
            }
            pthread_mutex_unlock (&vlib_rp->mutex);
            root_rp = svm_get_root_rp();
            ASSERT(root_rp);
            /* Clean up the root region client list */
            pthread_mutex_lock (&root_rp->mutex);
            svm_client_scan_this_region_nolock (root_rp);
            pthread_mutex_unlock (&root_rp->mutex);
        } else {
            pthread_mutex_unlock (&vlib_rp->mutex);
            /* 
             * Make sure the vlib app is really there...
             * Wait up to 100 seconds... 
             */
            for (i = 0; i < 10000; i++) {
                /* Yup, it's there, off we go... */
                if (kill (am->shmem_hdr->vl_pid, 0) >= 0)
                    break;

                ts.tv_sec = 0;
                ts.tv_nsec = 10000*1000;  /* 10 ms */
                while (nanosleep(&ts, &tsrem) < 0)
                    ts = tsrem;
            }
        }

        am->vlib_rp = vlib_rp;
        vec_add1(am->mapped_shmem_regions, vlib_rp);
        return 0;
    }
    /* Clients simply have to wait... */
    if (!is_vlib) {
        pthread_mutex_unlock (&vlib_rp->mutex);

        /* Wait up to 100 seconds... */
        for (i = 0; i < 10000; i++) {
            ts.tv_sec = 0;
            ts.tv_nsec = 10000*1000;  /* 10 ms */
            while (nanosleep(&ts, &tsrem) < 0)
                ts = tsrem;
            if (vlib_rp->user_ctx)
                goto ready;
        }
        /* Clean up and leave... */
        svm_region_unmap (vlib_rp);
        clib_warning ("region init fail");
        return (-2);

    ready:
        am->shmem_hdr = (void *)vlib_rp->user_ctx;
        am->our_pid = getpid();
        am->vlib_rp = vlib_rp;
        vec_add1(am->mapped_shmem_regions, vlib_rp);
        return 0;
    }

    /* Nope, it's our problem... */

    oldheap = svm_push_data_heap (vlib_rp);

    vec_validate(shmem_hdr, 0);
    shmem_hdr->version = VL_SHM_VERSION;

    /* vlib main input queue */
    shmem_hdr->vl_input_queue = 
        unix_shared_memory_queue_init (1024, sizeof (uword), getpid(),
                                       am->vlib_signal);

    /* Set up the msg ring allocator */
#define _(sz,n)                                                 \
    do {                                                        \
        ring_alloc_t _rp;                                       \
        _rp.rp = unix_shared_memory_queue_init ((n), (sz), 0, 0); \
        _rp.size = (sz);                                        \
        _rp.nitems = n;                                         \
        _rp.hits = 0;                                           \
        _rp.misses = 0;                                         \
        vec_add1(shmem_hdr->vl_rings, _rp);                     \
    } while (0);

    foreach_vl_aring_size;
#undef _

#define _(sz,n)                                                 \
    do {                                                        \
        ring_alloc_t _rp;                                       \
        _rp.rp = unix_shared_memory_queue_init ((n), (sz), 0, 0); \
        _rp.size = (sz);                                        \
        _rp.nitems = n;                                         \
        _rp.hits = 0;                                           \
        _rp.misses = 0;                                         \
        vec_add1(shmem_hdr->client_rings, _rp);                 \
    } while (0);

    foreach_clnt_aring_size;
#undef _

    am->shmem_hdr = shmem_hdr;
    am->vlib_rp = vlib_rp;
    am->our_pid = getpid();
    if (is_vlib)
        am->shmem_hdr->vl_pid = am->our_pid;
    
    svm_pop_heap (oldheap);

    /* 
     * After absolutely everything that a client might see is set up,
     * declare the shmem region valid
     */
    vlib_rp->user_ctx = shmem_hdr;

    pthread_mutex_unlock (&vlib_rp->mutex);
    vec_add1(am->mapped_shmem_regions, vlib_rp);
    return 0;
}

void vl_register_mapped_shmem_region(svm_region_t *rp)
{
    api_main_t *am = &api_main;

    vec_add1(am->mapped_shmem_regions, rp);
}

void vl_unmap_shmem (void)
{
    svm_region_t *rp;
    int i;
    api_main_t *am = &api_main;

    if (! svm_get_root_rp())
      return;

    for (i = 0; i < vec_len(am->mapped_shmem_regions); i++) {
        rp = am->mapped_shmem_regions[i];
        svm_region_unmap (rp);
    }

    vec_free(am->mapped_shmem_regions);
    am->shmem_hdr = 0;

    svm_region_exit ();
    /* $$$ more careful cleanup, valgrind run... */
    vec_free (am->msg_handlers);
    vec_free (am->msg_endian_handlers);
    vec_free (am->msg_print_handlers);
}

void vl_msg_api_send_shmem (unix_shared_memory_queue_t *q, u8 *elem)
{
    api_main_t *am = &api_main;
    uword *trace = (uword *)elem;

    if (am->tx_trace && am->tx_trace->enabled)
        vl_msg_api_trace(am, am->tx_trace, (void *)trace[0]);

    (void)unix_shared_memory_queue_add(q, elem, 0 /* nowait */);
}

void vl_msg_api_send_shmem_nolock (unix_shared_memory_queue_t *q, u8 *elem)
{
    api_main_t *am = &api_main;
    uword *trace = (uword *)elem;

    if (am->tx_trace && am->tx_trace->enabled)
        vl_msg_api_trace(am, am->tx_trace, (void *)trace[0]);

    (void)unix_shared_memory_queue_add_nolock (q, elem);
}

static void vl_api_memclnt_create_reply_t_handler (
    vl_api_memclnt_create_reply_t *mp)
{
    api_main_t *am = &api_main;
    int rv;

    am->my_client_index = mp->index;
    am->my_registration = (vl_api_registration_t *)(uword)
        mp->handle;

    rv = ntohl(mp->response);

    if (rv < 0)
        clib_warning ("WARNING: API mismatch detected");
}        

void vl_client_add_api_signatures (vl_api_memclnt_create_t *mp) 
    __attribute__((weak));

void vl_client_add_api_signatures (vl_api_memclnt_create_t *mp) 
{
    int i;

    for (i = 0; i < ARRAY_LEN(mp->api_versions); i++)
        mp->api_versions[i] = 0;
}

int vl_client_connect (char *name, int ctx_quota, int input_queue_size)
{
    svm_region_t *svm;
    vl_api_memclnt_create_t *mp;
    vl_api_memclnt_create_reply_t *rp;
    unix_shared_memory_queue_t *vl_input_queue;
    vl_shmem_hdr_t *shmem_hdr;
    int rv=0;
    void *oldheap;
    api_main_t *am = &api_main;

    if (am->my_registration) {
        clib_warning ("client %s already connected...", name);
        return -1;
    }

    if (am->vlib_rp == 0) {
        clib_warning ("am->vlib_rp NULL");
        return -1;
    }

    svm = am->vlib_rp;
    shmem_hdr = am->shmem_hdr;

    if (shmem_hdr == 0 || shmem_hdr->vl_input_queue == 0) {
        clib_warning ("shmem_hdr / input queue NULL");
        return -1;
    }

    pthread_mutex_lock (&svm->mutex);
    oldheap = svm_push_data_heap(svm);
    vl_input_queue = 
        unix_shared_memory_queue_init (input_queue_size, sizeof(uword), 
                                       getpid(), 0);
    pthread_mutex_unlock(&svm->mutex);
    svm_pop_heap (oldheap);

    am->my_client_index = ~0;
    am->my_registration = 0;
    am->vl_input_queue = vl_input_queue;

    mp = vl_msg_api_alloc(sizeof(vl_api_memclnt_create_t));
    memset(mp, 0, sizeof (*mp));
    mp->_vl_msg_id = ntohs(VL_API_MEMCLNT_CREATE);
    mp->ctx_quota = ctx_quota;
    mp->input_queue = (uword)vl_input_queue;
    strncpy ((char *) mp->name, name, sizeof(mp->name)-1);

    vl_client_add_api_signatures(mp);
    
    vl_msg_api_send_shmem (shmem_hdr->vl_input_queue, (u8 *)&mp);

    while (1) {
        int qstatus;
        struct timespec ts, tsrem;
        int i;

        /* Wait up to 10 seconds */
        for (i = 0; i < 1000; i++) {
            qstatus = unix_shared_memory_queue_sub (vl_input_queue, (u8 *)&rp, 
                                                    1 /* nowait */);
            if (qstatus == 0)
                goto read_one_msg;
            ts.tv_sec = 0;
            ts.tv_nsec = 10000*1000;  /* 10 ms */
            while (nanosleep(&ts, &tsrem) < 0)
                ts = tsrem;
        }
        /* Timeout... */
        clib_warning ("memclnt_create_reply timeout");
        return -1;

    read_one_msg:
        if (ntohs(rp->_vl_msg_id) != VL_API_MEMCLNT_CREATE_REPLY) {
            clib_warning ("unexpected reply: id %d", ntohs(rp->_vl_msg_id));
            continue;
        }
        rv = clib_net_to_host_u32(rp->response);

        vl_msg_api_handler((void *)rp);
        break;
    }
    return (rv);
}

static void vl_api_memclnt_delete_reply_t_handler (
    vl_api_memclnt_delete_reply_t *mp)
{
    void *oldheap;
    api_main_t *am = &api_main;

    pthread_mutex_lock (&am->vlib_rp->mutex);
    oldheap = svm_push_data_heap(am->vlib_rp);
    unix_shared_memory_queue_free (am->vl_input_queue);
    pthread_mutex_unlock (&am->vlib_rp->mutex);
    svm_pop_heap (oldheap);

    am->my_client_index = ~0;
    am->my_registration = 0;
    am->vl_input_queue = 0;
}        

void vl_client_disconnect (void)
{
    vl_api_memclnt_delete_t *mp;
    vl_api_memclnt_delete_reply_t *rp;
    unix_shared_memory_queue_t *vl_input_queue;
    vl_shmem_hdr_t *shmem_hdr;
    time_t begin;
    api_main_t *am = &api_main;
    
    ASSERT(am->vlib_rp);
    shmem_hdr = am->shmem_hdr;
    ASSERT(shmem_hdr && shmem_hdr->vl_input_queue);

    vl_input_queue = am->vl_input_queue;

    mp = vl_msg_api_alloc(sizeof(vl_api_memclnt_delete_t));
    memset(mp, 0, sizeof (*mp));
    mp->_vl_msg_id = ntohs(VL_API_MEMCLNT_DELETE);
    mp->index = am->my_client_index;
    mp->handle = (uword) am->my_registration;

    vl_msg_api_send_shmem (shmem_hdr->vl_input_queue, (u8 *)&mp);

    /* 
     * Have to be careful here, in case the client is disconnecting
     * because e.g. the vlib process died, or is unresponsive.
     */
    
    begin = time (0);
    while (1) {
        time_t now;

        now = time (0);

        if (now >= (begin + 2)) {
            clib_warning ("peer unresponsive, give up");
            am->my_client_index = ~0;
            am->my_registration = 0;
            am->shmem_hdr = 0;
            break;
        }
        if (unix_shared_memory_queue_sub (vl_input_queue, (u8 *)&rp, 1) < 0)
            continue;
        
        /* drain the queue */
        if (ntohs(rp->_vl_msg_id) != VL_API_MEMCLNT_DELETE_REPLY) {
            vl_msg_api_handler ((void *)rp);
            continue;
        }
        vl_msg_api_handler((void *)rp);
        break;
    }
}

static inline vl_api_registration_t 
*vl_api_client_index_to_registration_internal (u32 handle)
{
    vl_api_registration_t **regpp;
    vl_api_registration_t *regp;
    api_main_t *am = &api_main;
    u32 index;

    index = vl_msg_api_handle_get_index (handle);
    if ((am->shmem_hdr->application_restarts & VL_API_EPOCH_MASK)
        != vl_msg_api_handle_get_epoch (handle)) {
        vl_msg_api_increment_missing_client_counter();
        return 0;
    }

    regpp = am->vl_clients + index;

    if (pool_is_free(am->vl_clients, regpp)) {
        vl_msg_api_increment_missing_client_counter();
        return 0;
    }
    regp = *regpp;
    return (regp);
}

vl_api_registration_t *vl_api_client_index_to_registration (u32 index)
{
    return (vl_api_client_index_to_registration_internal (index));
}

unix_shared_memory_queue_t *vl_api_client_index_to_input_queue (u32 index)
{
    vl_api_registration_t *regp;

    regp = vl_api_client_index_to_registration_internal (index);
    if (!regp)
        return 0;
    return (regp->vl_input_queue);
}

#define foreach_api_client_msg                  \
_(MEMCLNT_CREATE_REPLY, memclnt_create_reply)   \
_(MEMCLNT_DELETE_REPLY, memclnt_delete_reply)

int vl_client_api_map (char *region_name)
{
    int rv;

    if ((rv = vl_map_shmem (region_name, 0 /* is_vlib */)) < 0) {
        return rv;
    }

#define _(N,n)                                                          \
    vl_msg_api_set_handlers(VL_API_##N, 0 /* name */,                   \
                           vl_api_##n##_t_handler,                      \
                           0/* cleanup */, 0/* endian */, 0/* print */, \
                           sizeof(vl_api_##n##_t), 1); 
    foreach_api_client_msg;
#undef _
    return 0;
}

void vl_client_api_unmap (void)
{
    vl_unmap_shmem();
}
