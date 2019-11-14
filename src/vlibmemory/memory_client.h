/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef SRC_VLIBMEMORY_MEMORY_CLIENT_H_
#define SRC_VLIBMEMORY_MEMORY_CLIENT_H_

#include <vlibmemory/memory_shared.h>
#include <setjmp.h>

/*
 * Exported so folks can code a working custom rx_pthread function
 */
typedef struct
{
  u8 rx_thread_jmpbuf_valid;
  u8 connected_to_vlib;
  jmp_buf rx_thread_jmpbuf;
  pthread_t rx_thread_handle;
  /* Plugin message base lookup scheme */
  volatile u8 first_msg_id_reply_ready;
  u16 first_msg_id_reply;
} memory_client_main_t;

extern memory_client_main_t memory_client_main;

int vl_client_connect (const char *name, int ctx_quota, int input_queue_size);
void vl_client_send_disconnect (u8 do_cleanup);
int vl_client_disconnect (void);
int vl_client_api_map (const char *region_name);
void vl_client_api_unmap (void);
void vl_client_disconnect_from_vlib (void);
void vl_client_disconnect_from_vlib_no_unmap (void);
int vl_client_connect_to_vlib (const char *svm_name, const char *client_name,
			       int rx_queue_size);
int vl_client_connect_to_vlib_thread_fn (const char *svm_name,
					 const char *client_name,
					 int rx_queue_size,
					 void *(*)(void *));
int vl_client_connect_to_vlib_no_rx_pthread (const char *svm_name,
					     const char *client_name,
					     int rx_queue_size);
int vl_client_connect_to_vlib_no_map (const char *svm_name,
				      const char *client_name,
				      int rx_queue_size);
int vl_client_connect_to_vlib_no_rx_pthread_no_map (const char *svm_name,
						    const char *client_name,
						    int rx_queue_size);
void vl_client_install_client_message_handlers (void);
u8 vl_mem_client_is_connected (void);

#endif /* SRC_VLIBMEMORY_MEMORY_CLIENT_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
