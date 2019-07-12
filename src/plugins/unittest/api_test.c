/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <vlibmemory/vl_memory_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_typedefs

static clib_error_t *
test_badmsg_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vl_api_unknown_message_t *mp;
  api_main_t *am = &api_main;
  vl_shmem_hdr_t *shmem_hdr = am->shmem_hdr;
  svm_region_t *svm = am->vlib_rp;;
  void *oldheap;
  u32 my_client_index;
  svm_queue_t *my_input_queue, *q;
  vl_api_memclnt_delete_t *dmp;

  /* Create a Genuine SVM (input) queue for the test */
  pthread_mutex_lock (&svm->mutex);
  oldheap = svm_push_data_heap (svm);
  my_input_queue = svm_queue_alloc_and_init (32, 8, getpid ());
  pthread_mutex_unlock (&svm->mutex);
  svm_pop_heap (oldheap);

  my_client_index = vl_api_memclnt_create_internal ("bad_message_test",
						    my_input_queue);
  /* Send (ourselves) a bogus API message */
  q = shmem_hdr->vl_input_queue;
  mp = vl_msg_api_alloc_as_if_client (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = clib_host_to_net_u16 (0xFECE);
  mp->client_index = my_client_index;
  mp->context = 0xdeadbeef;

  vl_msg_api_send_shmem (q, (u8 *) & mp);

  /* Time to process it */
  vlib_process_suspend (vm, 15e-3);

  /* Clean out our input queue */
  while (svm_queue_sub (my_input_queue, (u8 *) & mp, SVM_Q_NOWAIT, 0) >= 0)
    {
      if (clib_net_to_host_u16 (mp->bad_msg_id) != 0xfece ||
	  mp->context != 0xdeadbeef)
	abort ();
      vlib_cli_output (vm, "vpp response OK: unknown message id 0x%x",
		       (u32) clib_net_to_host_u16 (mp->bad_msg_id));
      vl_msg_api_free (mp);
    }

  /* Ask the normal bits of vpp to delete the test client */
  dmp = vl_msg_api_alloc_as_if_client (sizeof (*dmp));
  clib_memset (dmp, 0, sizeof (*dmp));
  dmp->_vl_msg_id = clib_host_to_net_u16 (VL_API_MEMCLNT_DELETE);
  dmp->index = my_client_index;
  dmp->do_cleanup = 1;

  vl_msg_api_send_shmem (q, (u8 *) & dmp);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_badmsg_command, static) =
{
  .path = "test badmsg",
  .short_help = "Send vpp a bad API message, w/ msg_id == 0",
  .function = test_badmsg_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
