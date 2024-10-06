/*
 * Copyright (c) 2024 InMon Corp.
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
#ifndef __included_sflow_vapi_h__
#define __included_sflow_vapi_h__

#include <vnet/vnet.h>
#include <sflow/sflow_common.h>

#define SFLOW_VAPI_POLL_INTERVAL 5
#define SFLOW_VAPI_MAX_REQUEST_Q 8
#define SFLOW_VAPI_MAX_RESPONSE_Q 16
#define SFLOW_VAPI_THREAD_NAME "sflow_vapi" // must be <= 15 characters

// #define SFLOW_VAPI_TEST_PLUGIN_SYMBOL

typedef struct {
  volatile int vapi_request_active; // to sync main <-> vapi_thread
  pthread_t vapi_thread;
  sflow_per_interface_data_t *vapi_itfs;
  int vapi_unavailable;
  int vapi_request_status; // written by vapi_thread
  void *vapi_ctx;
} sflow_vapi_client_t;

int sflow_vapi_read_linux_if_index_numbers(sflow_vapi_client_t *vac, sflow_per_interface_data_t *itfs);
int sflow_vapi_check_for_linux_if_index_results(sflow_vapi_client_t *vac, sflow_per_interface_data_t *itfs);


#endif /* __included_sflow_vapi_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

