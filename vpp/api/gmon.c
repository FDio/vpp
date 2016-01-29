/* 
 * Copyright (c) 2012 Cisco and/or its affiliates.
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
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>

#include <svmdb.h>

typedef struct {
    svmdb_client_t *svmdb_client;
    f64 *vector_rate_ptr;
    f64 *input_rate_ptr;
    pid_t *vpef_pid_ptr;
    vlib_main_t *vlib_main;
} gmon_main_t;

#if DPDK == 0
static inline u64 vnet_get_aggregate_rx_packets (void)
{ return 0; }
#else
#include <vnet/vnet.h>
#include <vnet/devices/dpdk/dpdk.h>
#endif

gmon_main_t gmon_main;

static uword
gmon_process (vlib_main_t * vm,
              vlib_node_runtime_t * rt,
              vlib_frame_t * f)
{
    f64 vector_rate;
    u64 input_packets, last_input_packets;
    f64 last_runtime, dt, now;
    gmon_main_t *gm = &gmon_main;
    pid_t vpefpid;

    vpefpid = getpid();
    *gm->vpef_pid_ptr = vpefpid;

    last_runtime = 0.0; 
    last_input_packets = 0;
	      
    last_runtime = 0.0;
    last_input_packets = 0;

    while (1) {
        vlib_process_suspend (vm, 5.0);
        vector_rate = vlib_last_vector_length_per_node (vm);
        *gm->vector_rate_ptr = vector_rate;
        now = vlib_time_now(vm);
        dt = now - last_runtime;
        input_packets =  vnet_get_aggregate_rx_packets();
        *gm->input_rate_ptr = (f64)(input_packets - last_input_packets) / dt;
        last_runtime = now;
        last_input_packets = input_packets;
    }

    return 0; /* not so much */
}

VLIB_REGISTER_NODE (gmon_process_node,static) = {
    .function = gmon_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "gmon-process",
};

static clib_error_t *
gmon_init (vlib_main_t *vm)
{
    gmon_main_t *gm = &gmon_main;
    api_main_t * am = &api_main;
    pid_t *swp = 0;
    f64 *v = 0;

    gm->vlib_main = vm;
    gm->svmdb_client = svmdb_map_chroot(am->root_path);

    /* Find or create, set to zero */
    vec_add1 (v, 0.0);
    svmdb_local_set_vec_variable(gm->svmdb_client, 
                                 "vpp_vector_rate", 
                                 (char *)v, sizeof (*v));
    vec_free(v);
    vec_add1 (v, 0.0);
    svmdb_local_set_vec_variable(gm->svmdb_client, 
                                 "vpp_input_rate", 
                                 (char *)v, sizeof (*v));
    vec_free(v);

    vec_add1 (swp, 0.0);
    svmdb_local_set_vec_variable(gm->svmdb_client, 
                                 "vpp_pid", 
                                 (char *)swp, sizeof (*swp));
    vec_free(swp);

    /* the value cell will never move, so acquire a reference to it */
    gm->vector_rate_ptr = 
        svmdb_local_get_variable_reference (gm->svmdb_client,
                                            SVMDB_NAMESPACE_VEC, 
                                            "vpp_vector_rate");
    gm->input_rate_ptr = 
        svmdb_local_get_variable_reference (gm->svmdb_client,
                                            SVMDB_NAMESPACE_VEC, 
                                            "vpp_input_rate");
    gm->vpef_pid_ptr = 
        svmdb_local_get_variable_reference (gm->svmdb_client,
                                            SVMDB_NAMESPACE_VEC, 
                                            "vpp_pid");
    return 0;
}

VLIB_INIT_FUNCTION (gmon_init);

static clib_error_t *gmon_exit (vlib_main_t *vm)
{
    gmon_main_t *gm = &gmon_main;

    if (gm->vector_rate_ptr) {
        *gm->vector_rate_ptr = 0.0;
        *gm->vpef_pid_ptr = 0;
        *gm->input_rate_ptr = 0.0;
        svmdb_unmap (gm->svmdb_client);
    }
    return 0;
}
VLIB_MAIN_LOOP_EXIT_FUNCTION (gmon_exit);
