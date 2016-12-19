/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include "ssvm_eth.h"

ssvm_eth_main_t ssvm_eth_main;

#define foreach_ssvm_eth_tx_func_error          \
_(RING_FULL, "Tx packet drops (ring full)")     \
_(NO_BUFFERS, "Tx packet drops (no buffers)")   \
_(ADMIN_DOWN, "Tx packet drops (admin down)")

typedef enum
{
#define _(f,s) SSVM_ETH_TX_ERROR_##f,
  foreach_ssvm_eth_tx_func_error
#undef _
    SSVM_ETH_TX_N_ERROR,
} ssvm_eth_tx_func_error_t;

static u32 ssvm_eth_flag_change (vnet_main_t * vnm,
				 vnet_hw_interface_t * hi, u32 flags);

int
ssvm_eth_create (ssvm_eth_main_t * em, u8 * name, int is_master)
{
  ssvm_private_t *intfc;
  void *oldheap;
  clib_error_t *e;
  unix_shared_memory_queue_t *q;
  ssvm_shared_header_t *sh;
  ssvm_eth_queue_elt_t *elts;
  u32 *elt_indices;
  u8 enet_addr[6];
  int i, rv;

  vec_add2 (em->intfcs, intfc, 1);

  intfc->ssvm_size = em->segment_size;
  intfc->i_am_master = 1;
  intfc->name = name;
  intfc->my_pid = getpid ();
  if (is_master == 0)
    {
      rv = ssvm_slave_init (intfc, 20 /* timeout in seconds */ );
      if (rv < 0)
	return rv;
      goto create_vnet_interface;
    }

  intfc->requested_va = em->next_base_va;
  em->next_base_va += em->segment_size;
  rv = ssvm_master_init (intfc, intfc - em->intfcs /* master index */ );

  if (rv < 0)
    return rv;

  /* OK, segment created, set up queues and so forth.  */

  sh = intfc->sh;
  oldheap = ssvm_push_heap (sh);

  q = unix_shared_memory_queue_init (em->queue_elts, sizeof (u32),
				     0 /* consumer pid not interesting */ ,
				     0 /* signal not sent */ );
  sh->opaque[TO_MASTER_Q_INDEX] = (void *) q;
  q = unix_shared_memory_queue_init (em->queue_elts, sizeof (u32),
				     0 /* consumer pid not interesting */ ,
				     0 /* signal not sent */ );
  sh->opaque[TO_SLAVE_Q_INDEX] = (void *) q;

  /*
   * Preallocate the requested number of buffer chunks
   * There must be a better way to do this, etc.
   * Add some slop to avoid pool reallocation, which will not go well
   */
  elts = 0;
  elt_indices = 0;

  vec_validate_aligned (elts, em->nbuffers - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (elt_indices, em->nbuffers - 1, CLIB_CACHE_LINE_BYTES);

  for (i = 0; i < em->nbuffers; i++)
    elt_indices[i] = i;

  sh->opaque[CHUNK_POOL_INDEX] = (void *) elts;
  sh->opaque[CHUNK_POOL_FREELIST_INDEX] = (void *) elt_indices;
  sh->opaque[CHUNK_POOL_NFREE] = (void *) (uword) em->nbuffers;

  ssvm_pop_heap (oldheap);

create_vnet_interface:

  sh = intfc->sh;

  memset (enet_addr, 0, sizeof (enet_addr));
  enet_addr[0] = 2;
  enet_addr[1] = 0xFE;
  enet_addr[2] = is_master;
  enet_addr[5] = sh->master_index;

  e = ethernet_register_interface
    (em->vnet_main, ssvm_eth_device_class.index, intfc - em->intfcs,
     /* ethernet address */ enet_addr,
     &intfc->vlib_hw_if_index, ssvm_eth_flag_change);

  if (e)
    {
      clib_error_report (e);
      /* $$$$ unmap offending region? */
      return VNET_API_ERROR_INVALID_INTERFACE;
    }

  /* Declare link up */
  vnet_hw_interface_set_flags (em->vnet_main, intfc->vlib_hw_if_index,
			       VNET_HW_INTERFACE_FLAG_LINK_UP);

  /* Let the games begin... */
  if (is_master)
    sh->ready = 1;
  return 0;
}

static clib_error_t *
ssvm_config (vlib_main_t * vm, unformat_input_t * input)
{
  u8 *name;
  int is_master = 1;
  int i, rv;
  ssvm_eth_main_t *em = &ssvm_eth_main;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "base-va %llx", &em->next_base_va))
	;
      else if (unformat (input, "segment-size %lld", &em->segment_size))
	em->segment_size = 1ULL << (max_log2 (em->segment_size));
      else if (unformat (input, "nbuffers %lld", &em->nbuffers))
	;
      else if (unformat (input, "queue-elts %lld", &em->queue_elts))
	;
      else if (unformat (input, "slave"))
	is_master = 0;
      else if (unformat (input, "%s", &name))
	vec_add1 (em->names, name);
      else
	break;
    }

  /* No configured instances, we're done... */
  if (vec_len (em->names) == 0)
    return 0;

  for (i = 0; i < vec_len (em->names); i++)
    {
      rv = ssvm_eth_create (em, em->names[i], is_master);
      if (rv < 0)
	return clib_error_return (0, "ssvm_eth_create '%s' failed, error %d",
				  em->names[i], rv);
    }

  vlib_node_set_state (vm, ssvm_eth_input_node.index,
		       VLIB_NODE_STATE_POLLING);

  return 0;
}

VLIB_CONFIG_FUNCTION (ssvm_config, "ssvm_eth");


static clib_error_t *
ssvm_eth_init (vlib_main_t * vm)
{
  ssvm_eth_main_t *em = &ssvm_eth_main;

  if (((sizeof (ssvm_eth_queue_elt_t) / CLIB_CACHE_LINE_BYTES)
       * CLIB_CACHE_LINE_BYTES) != sizeof (ssvm_eth_queue_elt_t))
    clib_warning ("ssvm_eth_queue_elt_t size %d not a multiple of %d",
		  sizeof (ssvm_eth_queue_elt_t), CLIB_CACHE_LINE_BYTES);

  em->vlib_main = vm;
  em->vnet_main = vnet_get_main ();
  em->elog_main = &vm->elog_main;

  /* default config param values... */

  em->next_base_va = 0x600000000ULL;
  /*
   * Allocate 2 full superframes in each dir (256 x 2 x 2 x 2048 bytes),
   * 2mb; double that so we have plenty of space... 4mb
   */
  em->segment_size = 8 << 20;
  em->nbuffers = 1024;
  em->queue_elts = 512;
  return 0;
}

VLIB_INIT_FUNCTION (ssvm_eth_init);

static char *ssvm_eth_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_ssvm_eth_tx_func_error
#undef _
};

static u8 *
format_ssvm_eth_device_name (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);

  s = format (s, "ssvmEthernet%d", i);
  return s;
}

static u8 *
format_ssvm_eth_device (u8 * s, va_list * args)
{
  s = format (s, "SSVM Ethernet");
  return s;
}

static u8 *
format_ssvm_eth_tx_trace (u8 * s, va_list * args)
{
  s = format (s, "Unimplemented...");
  return s;
}


static uword
ssvm_eth_interface_tx (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * f)
{
  ssvm_eth_main_t *em = &ssvm_eth_main;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  ssvm_private_t *intfc = vec_elt_at_index (em->intfcs, rd->dev_instance);
  ssvm_shared_header_t *sh = intfc->sh;
  unix_shared_memory_queue_t *q;
  u32 *from;
  u32 n_left;
  ssvm_eth_queue_elt_t *elts, *elt, *prev_elt;
  u32 my_pid = intfc->my_pid;
  vlib_buffer_t *b0;
  u32 bi0;
  u32 size_this_buffer;
  u32 chunks_this_buffer;
  u8 i_am_master = intfc->i_am_master;
  u32 elt_index;
  int is_ring_full, interface_down;
  int i;
  volatile u32 *queue_lock;
  u32 n_to_alloc = VLIB_FRAME_SIZE;
  u32 n_allocated, n_present_in_cache, n_available;
  u32 *elt_indices;

  if (i_am_master)
    q = (unix_shared_memory_queue_t *) sh->opaque[TO_SLAVE_Q_INDEX];
  else
    q = (unix_shared_memory_queue_t *) sh->opaque[TO_MASTER_Q_INDEX];

  queue_lock = (u32 *) q;

  from = vlib_frame_vector_args (f);
  n_left = f->n_vectors;
  is_ring_full = 0;
  interface_down = 0;

  n_present_in_cache = vec_len (em->chunk_cache);

  /* admin / link up/down check */
  if (sh->opaque[MASTER_ADMIN_STATE_INDEX] == 0 ||
      sh->opaque[SLAVE_ADMIN_STATE_INDEX] == 0)
    {
      interface_down = 1;
      goto out;
    }

  ssvm_lock (sh, my_pid, 1);

  elts = (ssvm_eth_queue_elt_t *) (sh->opaque[CHUNK_POOL_INDEX]);
  elt_indices = (u32 *) (sh->opaque[CHUNK_POOL_FREELIST_INDEX]);
  n_available = (u32) pointer_to_uword (sh->opaque[CHUNK_POOL_NFREE]);

  if (n_present_in_cache < n_left * 2)
    {
      vec_validate (em->chunk_cache, n_to_alloc + n_present_in_cache - 1);

      n_allocated = n_to_alloc < n_available ? n_to_alloc : n_available;

      if (PREDICT_TRUE (n_allocated > 0))
	{
	  clib_memcpy (&em->chunk_cache[n_present_in_cache],
		       &elt_indices[n_available - n_allocated],
		       sizeof (u32) * n_allocated);
	}

      n_present_in_cache += n_allocated;
      n_available -= n_allocated;
      sh->opaque[CHUNK_POOL_NFREE] = uword_to_pointer (n_available, void *);
      _vec_len (em->chunk_cache) = n_present_in_cache;
    }

  ssvm_unlock (sh);

  while (n_left)
    {
      bi0 = from[0];
      b0 = vlib_get_buffer (vm, bi0);

      size_this_buffer = vlib_buffer_length_in_chain (vm, b0);
      chunks_this_buffer = (size_this_buffer + (SSVM_BUFFER_SIZE - 1))
	/ SSVM_BUFFER_SIZE;

      /* If we're not going to be able to enqueue the buffer, tail drop. */
      if (q->cursize >= q->maxsize)
	{
	  is_ring_full = 1;
	  break;
	}

      prev_elt = 0;
      elt_index = ~0;
      for (i = 0; i < chunks_this_buffer; i++)
	{
	  if (PREDICT_FALSE (n_present_in_cache == 0))
	    goto out;

	  elt_index = em->chunk_cache[--n_present_in_cache];
	  elt = elts + elt_index;

	  elt->type = SSVM_PACKET_TYPE;
	  elt->flags = 0;
	  elt->total_length_not_including_first_buffer =
	    b0->total_length_not_including_first_buffer;
	  elt->length_this_buffer = b0->current_length;
	  elt->current_data_hint = b0->current_data;
	  elt->owner = !i_am_master;
	  elt->tag = 1;

	  clib_memcpy (elt->data, b0->data + b0->current_data,
		       b0->current_length);

	  if (PREDICT_FALSE (prev_elt != 0))
	    prev_elt->next_index = elt - elts;

	  if (PREDICT_FALSE (i < (chunks_this_buffer - 1)))
	    {
	      elt->flags = SSVM_BUFFER_NEXT_PRESENT;
	      ASSERT (b0->flags & VLIB_BUFFER_NEXT_PRESENT);
	      b0 = vlib_get_buffer (vm, b0->next_buffer);
	    }
	  prev_elt = elt;
	}

      while (__sync_lock_test_and_set (queue_lock, 1))
	;

      unix_shared_memory_queue_add_raw (q, (u8 *) & elt_index);
      CLIB_MEMORY_BARRIER ();
      *queue_lock = 0;

      from++;
      n_left--;
    }

out:
  if (PREDICT_FALSE (n_left))
    {
      if (is_ring_full)
	vlib_error_count (vm, node->node_index, SSVM_ETH_TX_ERROR_RING_FULL,
			  n_left);
      else if (interface_down)
	vlib_error_count (vm, node->node_index, SSVM_ETH_TX_ERROR_ADMIN_DOWN,
			  n_left);
      else
	vlib_error_count (vm, node->node_index, SSVM_ETH_TX_ERROR_NO_BUFFERS,
			  n_left);

      vlib_buffer_free (vm, from, n_left);
    }
  else
    vlib_buffer_free (vm, vlib_frame_vector_args (f), f->n_vectors);

  if (PREDICT_TRUE (vec_len (em->chunk_cache)))
    _vec_len (em->chunk_cache) = n_present_in_cache;

  return f->n_vectors;
}

static void
ssvm_eth_clear_hw_interface_counters (u32 instance)
{
  /* Nothing for now */
}

static clib_error_t *
ssvm_eth_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index,
				  u32 flags)
{
  vnet_hw_interface_t *hif = vnet_get_hw_interface (vnm, hw_if_index);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;
  ssvm_eth_main_t *em = &ssvm_eth_main;
  ssvm_private_t *intfc = vec_elt_at_index (em->intfcs, hif->dev_instance);
  ssvm_shared_header_t *sh;

  /* publish link-state in shared-memory, to discourage buffer-wasting */
  sh = intfc->sh;
  if (intfc->i_am_master)
    sh->opaque[MASTER_ADMIN_STATE_INDEX] = (void *) is_up;
  else
    sh->opaque[SLAVE_ADMIN_STATE_INDEX] = (void *) is_up;

  return 0;
}

static clib_error_t *
ssvm_eth_subif_add_del_function (vnet_main_t * vnm,
				 u32 hw_if_index,
				 struct vnet_sw_interface_t *st, int is_add)
{
  /* Nothing for now */
  return 0;
}

/*
 * Dynamically redirect all pkts from a specific interface
 * to the specified node
 */
static void
ssvm_eth_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
				  u32 node_index)
{
  ssvm_eth_main_t *em = &ssvm_eth_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  ssvm_private_t *intfc = pool_elt_at_index (em->intfcs, hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    {
      intfc->per_interface_next_index = node_index;
      return;
    }

  intfc->per_interface_next_index =
    vlib_node_add_next (em->vlib_main, ssvm_eth_input_node.index, node_index);
}

static u32
ssvm_eth_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hi, u32 flags)
{
  /* nothing for now */
  return 0;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (ssvm_eth_device_class) = {
  .name = "ssvm-eth",
  .tx_function = ssvm_eth_interface_tx,
  .tx_function_n_errors = SSVM_ETH_TX_N_ERROR,
  .tx_function_error_strings = ssvm_eth_tx_func_error_strings,
  .format_device_name = format_ssvm_eth_device_name,
  .format_device = format_ssvm_eth_device,
  .format_tx_trace = format_ssvm_eth_tx_trace,
  .clear_counters = ssvm_eth_clear_hw_interface_counters,
  .admin_up_down_function = ssvm_eth_interface_admin_up_down,
  .subif_add_del_function = ssvm_eth_subif_add_del_function,
  .rx_redirect_to_node = ssvm_eth_set_interface_next_node,
};

VLIB_DEVICE_TX_FUNCTION_MULTIARCH (ssvm_eth_device_class,
				   ssvm_eth_interface_tx)
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
