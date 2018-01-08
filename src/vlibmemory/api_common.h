/*
 *------------------------------------------------------------------
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

#ifndef included_vlibmemory_api_common_h
#define included_vlibmemory_api_common_h

#include <svm/svm_common.h>
#include <vlibapi/api.h>
#include <vlibmemory/memory_api.h>
#include <vlibmemory/memory_client.h>
#include <vlibmemory/socket_api.h>
#include <vlibmemory/socket_client.h>

void vl_api_rpc_call_main_thread (void *fp, u8 * data, u32 data_length);
u16 vl_client_get_first_plugin_msg_id (const char *plugin_name);
void vl_api_send_pending_rpc_requests (vlib_main_t * vm);
u8 *vl_api_serialize_message_table (api_main_t * am, u8 * vector);

always_inline void
vl_api_send_msg (vl_api_registration_t * rp, u8 * elem)
{
  if (PREDICT_FALSE (rp->registration_type > REGISTRATION_TYPE_SHMEM))
    {
      vl_socket_api_send (rp, elem);
    }
  else
    {
      vl_msg_api_send_shmem (rp->vl_input_queue, (u8 *) & elem);
    }
}

always_inline vl_api_registration_t *
vl_api_client_index_to_registration (u32 index)
{
  if (PREDICT_FALSE (socket_main.current_rp != 0))
    return socket_main.current_rp;

  return (vl_mem_api_client_index_to_registration (index));
}

/*
 * vl_api_clnt process data used by transports (socket api in particular)
 */
extern vlib_node_registration_t vl_api_clnt_node;
extern volatile int **vl_api_queue_cursizes;

typedef enum vl_api_clnt_process_events
{
  QUEUE_SIGNAL_EVENT = 1,
  SOCKET_READ_EVENT
} vl_api_clnt_process_events_t;

#define foreach_histogram_bucket                \
_(400)                                          \
_(200)                                          \
_(100)                                          \
_(10)

typedef enum
{
#define _(n) SLEEP_##n##_US,
  foreach_histogram_bucket
#undef _
    SLEEP_N_BUCKETS,
} histogram_index_t;

extern u64 vector_rate_histogram[];

/*
 * sockclnt APIs XXX are these actually used anywhere?
 */
vl_api_registration_t *sockclnt_get_registration (u32 index);
void socksvr_add_pending_output (struct clib_file *uf,
				 struct vl_api_registration_ *cf,
				 u8 * buffer, uword buffer_bytes);
void vl_socket_process_msg (struct clib_file *uf,
			    struct vl_api_registration_ *rp, i8 * input_v);
u32 sockclnt_open_index (char *client_name, char *hostname, int port);
void sockclnt_close_index (u32 index);
void vl_client_msg_api_send (vl_api_registration_t * cm, u8 * elem);

#endif /* included_vlibmemory_api_common_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
