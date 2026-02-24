/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019-2026 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/format.h>
#include <assert.h>

#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/arp_packet.h>
#include <dpdk/device/dpdk.h>
#include <dpdk/device/dpdk_priv.h>
#include <dpdk/device/flow_gen.h>
#include <vppinfra/error.h>

/* constant structs */
static const struct rte_flow_attr ingress = { .ingress = 1 };
static const struct rte_flow_actions_template_attr action_attr = { .ingress = 1 };
static const struct rte_flow_pattern_template_attr pattern_attr = { .ingress = 1,
								    .relaxed_matching = 1 };
static const struct rte_flow_op_attr async_op = { .postpone = 1 };

static int
dpdk_flow_add (dpdk_device_t *xd, vnet_flow_t *f, dpdk_flow_entry_t *fe)
{
  struct rte_flow_item items[DPDK_MAX_FLOW_ITEMS];
  struct rte_flow_action actions[DPDK_MAX_FLOW_ACTIONS];
  int rv = 0;

  if ((rv = dpdk_flow_fill_items (xd, f, fe, items)) != 0)
    return rv;

  if ((rv = dpdk_flow_fill_actions (xd, f, fe, actions)) != 0)
    return rv;

  rv = rte_flow_validate (xd->port_id, &ingress, items, actions, &xd->last_flow_error);

  if (rv)
    {
      if (rv == -EINVAL)
	rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      else if (rv == -EEXIST)
	rv = VNET_FLOW_ERROR_ALREADY_EXISTS;
      else
	rv = VNET_FLOW_ERROR_INTERNAL;

      goto done;
    }

  fe->handle = rte_flow_create (xd->port_id, &ingress, items, actions, &xd->last_flow_error);

  if (!fe->handle)
    rv = VNET_FLOW_ERROR_NOT_SUPPORTED;

done:
  return rv;
}

/*
 * Fast async flow add using pre-computed function pointer arrays.
 * No conditionals in the hot path - all decisions made at template creation.
 */
static int
dpdk_flow_async_add_fast (dpdk_device_t *xd, vnet_flow_t *f, dpdk_flow_template_entry_t *fte,
			  dpdk_flow_entry_t *fe)
{
  struct rte_flow_item items[DPDK_MAX_FLOW_ITEMS];
  struct rte_flow_action actions[DPDK_MAX_FLOW_ACTIONS];

  /* Fill items using function pointer array - no conditionals */
  for (u8 i = 0; i < fte->n_item_fns; i++)
    fte->item_fns[i](f, &items[i]);

  /* Fill actions using function pointer array - no conditionals */
  for (u8 i = 0; i < fte->n_action_fns; i++)
    fte->action_fns[i](f, &actions[i]);

  fe->handle =
    rte_flow_async_create (xd->port_id, DPDK_DEFAULT_ASYNC_FLOW_QUEUE_INDEX, &async_op,
			   fte->table_handle, items, 0, actions, 0, NULL, &xd->last_flow_error);

  return fe->handle ? 0 : VNET_FLOW_ERROR_NOT_SUPPORTED;
}

/*
 * Generic async flow add - uses conditional-heavy fill functions.
 * Used as fallback when function pointers are not populated.
 */
static int
dpdk_flow_async_add (dpdk_device_t *xd, vnet_flow_t *f, dpdk_flow_template_entry_t *fte,
		     dpdk_flow_entry_t *fe)
{
  /* Use fast path if function pointers are populated */
  if (PREDICT_TRUE (fte->n_item_fns > 0))
    return dpdk_flow_async_add_fast (xd, f, fte, fe);

  /* Fallback to generic path */
  struct rte_flow_item items[DPDK_MAX_FLOW_ITEMS];
  struct rte_flow_action actions[DPDK_MAX_FLOW_ACTIONS];
  int rv = 0;

  if ((rv = dpdk_flow_fill_items (xd, f, fe, items)) != 0)
    return rv;

  if ((rv = dpdk_flow_fill_actions (xd, f, fe, actions)) != 0)
    return rv;

  fe->handle =
    rte_flow_async_create (xd->port_id, DPDK_DEFAULT_ASYNC_FLOW_QUEUE_INDEX, &async_op,
			   fte->table_handle, items, 0, actions, 0, NULL, &xd->last_flow_error);

  if (!fe->handle)
    {
      dpdk_device_flow_error (xd, "rte_flow_async_create");
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
    }

  return rv;
}

static int
dpdk_flow_async_template_add (dpdk_device_t *xd, vnet_flow_t *t, dpdk_flow_template_entry_t *fte,
			      u32 nb_flows)
{
  struct rte_flow_item items[DPDK_MAX_FLOW_ITEMS];
  struct rte_flow_action actions[DPDK_MAX_FLOW_ACTIONS];
  struct rte_flow_action actions_mask[DPDK_MAX_FLOW_ACTIONS];
  struct rte_flow_template_table_attr template_attr = {
    .nb_flows = nb_flows,
  };
  int rv = 0;

  clib_memcpy (&template_attr.flow_attr, &ingress, sizeof (ingress));

  if ((rv = dpdk_flow_fill_items_template (xd, t, fte, items)) != 0)
    return rv;

  fte->pattern_handle =
    rte_flow_pattern_template_create (xd->port_id, &pattern_attr, items, &xd->last_flow_error);
  if (!fte->pattern_handle)
    {
      dpdk_device_flow_error (xd, "rte_flow_pattern_template_create");
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done;
    }

  if ((rv = dpdk_flow_fill_actions_template (xd, t, fte, actions, actions_mask)) != 0)
    goto done_pattern_handle;

  fte->actions_handle = rte_flow_actions_template_create (xd->port_id, &action_attr, actions,
							  actions_mask, &xd->last_flow_error);
  if (!fte->actions_handle)
    {
      dpdk_device_flow_error (xd, "rte_flow_actions_template_create");
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done_pattern_handle;
    }

  fte->table_handle =
    rte_flow_template_table_create (xd->port_id, &template_attr, &fte->pattern_handle, 1,
				    &fte->actions_handle, 1, &xd->last_flow_error);
  if (!fte->table_handle)
    {
      dpdk_device_flow_error (xd, "rte_flow_template_table_create");
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done_actions_handle;
    }

  /* Populate function pointer arrays for fast async flow insertion */
  dpdk_flow_template_populate_fns (t, fte);

  return 0;

done_actions_handle:
  rte_flow_actions_template_destroy (xd->port_id, fte->actions_handle, &xd->last_flow_error);
  fte->actions_handle = 0;

done_pattern_handle:
  rte_flow_pattern_template_destroy (xd->port_id, fte->pattern_handle, &xd->last_flow_error);
  fte->pattern_handle = 0;

done:
  return rv;
}

int
dpdk_flow_ops_fn (vnet_main_t * vnm, vnet_flow_dev_op_t op, u32 dev_instance,
		  u32 flow_index, uword * private_data)
{
  vlib_main_t *vm = vlib_get_main ();
  dpdk_main_t *dm = &dpdk_main;
  vnet_flow_t *flow = vnet_get_flow (flow_index);
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, dev_instance);
  dpdk_flow_entry_t *fe;
  dpdk_flow_lookup_entry_t *fle = 0;
  int rv;

  /* recycle old flow lookup entries only after the main loop counter
     increases - i.e. previously DMA'ed packets were handled */
  if (vec_len (xd->parked_lookup_indexes) > 0 &&
      xd->parked_loop_count != vm->main_loop_count)
    {
      u32 *fl_index;

      vec_foreach (fl_index, xd->parked_lookup_indexes)
	pool_put_index (xd->flow_lookup_entries, *fl_index);
      vec_reset_length (xd->parked_lookup_indexes);
    }

  if (op == VNET_FLOW_DEV_OP_DEL_FLOW)
    {
      fe = vec_elt_at_index (xd->flow_entries, *private_data);

      if ((rv = rte_flow_destroy (xd->port_id, fe->handle, &xd->last_flow_error)))
	{
	  dpdk_device_flow_error (xd, "rte_flow_destroy");
	  return VNET_FLOW_ERROR_INTERNAL;
	}

      if (fe->mark)
	{
	  /* make sure no action is taken for in-flight (marked) packets */
	  fle = pool_elt_at_index (xd->flow_lookup_entries, fe->mark);
	  clib_memset (fle, -1, sizeof (*fle));
	  vec_add1 (xd->parked_lookup_indexes, fe->mark);
	  xd->parked_loop_count = vm->main_loop_count;
	}

      clib_memset (fe, 0, sizeof (*fe));
      pool_put (xd->flow_entries, fe);

      goto disable_rx_offload;
    }

  if (op != VNET_FLOW_DEV_OP_ADD_FLOW)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  pool_get (xd->flow_entries, fe);
  fe->flow_index = flow->index;

  if (flow->actions == 0)
    {
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done;
    }

  /* if we need to mark packets, assign one mark */
  if (flow->actions & (VNET_FLOW_ACTION_MARK |
		       VNET_FLOW_ACTION_REDIRECT_TO_NODE |
		       VNET_FLOW_ACTION_BUFFER_ADVANCE))
    {
      /* reserve slot 0 */
      if (xd->flow_lookup_entries == 0)
	pool_get_aligned (xd->flow_lookup_entries, fle,
			  CLIB_CACHE_LINE_BYTES);
      pool_get_aligned (xd->flow_lookup_entries, fle, CLIB_CACHE_LINE_BYTES);
      fe->mark = fle - xd->flow_lookup_entries;

      /* install entry in the lookup table */
      clib_memset (fle, -1, sizeof (*fle));
      if (flow->actions & VNET_FLOW_ACTION_MARK)
	fle->flow_id = flow->mark_flow_id;
      if (flow->actions & VNET_FLOW_ACTION_REDIRECT_TO_NODE)
	fle->next_index = flow->redirect_device_input_next_index;
      if (flow->actions & VNET_FLOW_ACTION_BUFFER_ADVANCE)
	fle->buffer_advance = flow->buffer_advance;
    }
  else
    fe->mark = 0;

  if ((xd->flags & DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD) == 0)
    {
      xd->flags |= DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD;
      dpdk_device_setup (xd);
    }

  switch (flow->type)
    {
    case VNET_FLOW_TYPE_ETHERNET:
    case VNET_FLOW_TYPE_IP4:
    case VNET_FLOW_TYPE_IP6:
    case VNET_FLOW_TYPE_IP4_N_TUPLE:
    case VNET_FLOW_TYPE_IP6_N_TUPLE:
    case VNET_FLOW_TYPE_IP4_VXLAN:
    case VNET_FLOW_TYPE_IP4_GTPC:
    case VNET_FLOW_TYPE_IP4_GTPU:
    case VNET_FLOW_TYPE_IP4_L2TPV3OIP:
    case VNET_FLOW_TYPE_IP4_IPSEC_ESP:
    case VNET_FLOW_TYPE_IP4_IPSEC_AH:
    case VNET_FLOW_TYPE_IP4_IP4:
    case VNET_FLOW_TYPE_IP4_IP4_N_TUPLE:
    case VNET_FLOW_TYPE_IP4_IP6:
    case VNET_FLOW_TYPE_IP4_IP6_N_TUPLE:
    case VNET_FLOW_TYPE_IP6_IP4:
    case VNET_FLOW_TYPE_IP6_IP4_N_TUPLE:
    case VNET_FLOW_TYPE_IP6_IP6:
    case VNET_FLOW_TYPE_IP6_IP6_N_TUPLE:
    case VNET_FLOW_TYPE_GENERIC:
      if ((rv = dpdk_flow_add (xd, flow, fe)))
	goto done;
      break;
    default:
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done;
    }

  *private_data = fe - xd->flow_entries;

done:
  if (rv)
    {
      clib_memset (fe, 0, sizeof (*fe));
      pool_put (xd->flow_entries, fe);
      if (fle)
	{
	  clib_memset (fle, -1, sizeof (*fle));
	  pool_put (xd->flow_lookup_entries, fle);
	}
    }
disable_rx_offload:
  if ((xd->flags & DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD) != 0
      && pool_elts (xd->flow_entries) == 0)
    {
      xd->flags &= ~DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD;
      dpdk_device_setup (xd);
    }

  return rv;
}

static_always_inline int
dpdk_flow_async_push_pull (dpdk_device_t *xd, u32 enqueued, u32 *in_flight, bool force_push,
			   bool force_pull)
{
  static struct rte_flow_op_result results[DPDK_DEFAULT_ASYNC_FLOW_PUSH_BATCH];
  static u32 max_in_flight = (DPDK_DEFAULT_ASYNC_FLOW_QUEUE_SIZE * 3) / 4;

  int rv;
  u32 pulled;
  /* When force_pull is set, wait for ALL operations to complete (in_flight == 0).
   * Otherwise, just keep in_flight below the threshold to avoid queue overflow. */
  u32 target_in_flight = force_pull ? 0 : max_in_flight;
  bool do_pull = force_pull || *in_flight >= target_in_flight;
  // When pulling, we always want the in flight work to be pushed beforehand
  bool do_push = do_pull || force_push || (enqueued % DPDK_DEFAULT_ASYNC_FLOW_PUSH_BATCH) == 0;

  if (PREDICT_FALSE (do_push))
    {
      rv = rte_flow_push (xd->port_id, DPDK_DEFAULT_ASYNC_FLOW_QUEUE_INDEX, &xd->last_flow_error);
      if (rv)
	return VNET_FLOW_ERROR_INTERNAL;
    }

  if (PREDICT_FALSE (do_pull))
    {
      do
	{
	  pulled = rte_flow_pull (xd->port_id, DPDK_DEFAULT_ASYNC_FLOW_QUEUE_INDEX, results,
				  DPDK_DEFAULT_ASYNC_FLOW_PUSH_BATCH, &xd->last_flow_error);
	  if (pulled > 0)
	    *in_flight -= pulled;
	  else if (pulled == 0)
	    CLIB_PAUSE ();
	  else
	    return VNET_FLOW_ERROR_INTERNAL;
	}
      while (*in_flight > target_in_flight);
    }
  return 0;
}

static int
dpdk_flow_async_op_del (dpdk_device_t *xd, vnet_flow_range_t *range,
			dpdk_flow_template_entry_t *fte, uword *private_data)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_flow_t *flow;
  dpdk_flow_entry_t *fe;
  dpdk_flow_lookup_entry_t *fle;
  uword per_flow_private_data;
  u32 in_flight = 0, enqueued = 0;
  int rv = 0;

  flow_range_foreach (range, flow)
  {
    per_flow_private_data = vec_elt (private_data, enqueued);
    fe = vec_elt_at_index (xd->flow_entries, per_flow_private_data);

    if ((rv = dpdk_flow_async_push_pull (xd, enqueued, &in_flight, false, false)))
      return rv;

    if ((rv = rte_flow_async_destroy (xd->port_id, DPDK_DEFAULT_ASYNC_FLOW_QUEUE_INDEX, &async_op,
				      fe->handle, NULL, &xd->last_flow_error)))
      {
	dpdk_device_flow_error (xd, "rte_flow_async_destroy");
	return VNET_FLOW_ERROR_INTERNAL;
      }

    in_flight++;
    enqueued++;

    if (fe->mark)
      {
	/* make sure no action is taken for in-flight (marked) packets */
	fle = pool_elt_at_index (xd->flow_lookup_entries, fe->mark);
	clib_memset (fle, -1, sizeof (*fle));
	vec_add1 (xd->parked_lookup_indexes, fe->mark);
	xd->parked_loop_count = vm->main_loop_count;
      }

    clib_memset (fe, 0, sizeof (*fe));
    pool_put (xd->flow_entries, fe);
  }

  if (pool_elts (xd->flow_entries) == 0)
    xd->flags &= ~DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD;

  if ((rv = dpdk_flow_async_push_pull (xd, enqueued, &in_flight, true, true)))
    return rv;

  return 0;
}

static int
dpdk_flow_async_op_add (dpdk_device_t *xd, vnet_flow_range_t *range,
			dpdk_flow_template_entry_t *fte, uword *private_data)
{
  vnet_flow_t *flow;
  dpdk_flow_entry_t *fe = 0;
  dpdk_flow_lookup_entry_t *fle = 0;
  uword *per_flow_private_data;
  u32 in_flight = 0, enqueued = 0;
  int rv = 0;

  /* Set offload flag once before loop */
  xd->flags |= DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD;

  flow_range_foreach (range, flow)
  {
    per_flow_private_data = vec_elt_at_index (private_data, enqueued);

    if ((rv = dpdk_flow_async_push_pull (xd, enqueued, &in_flight, false, false)))
      return rv;

    pool_get (xd->flow_entries, fe);
    fe->flow_index = flow->index;
    *per_flow_private_data = fe - xd->flow_entries;

    /* if we need to mark packets, assign one mark */
    if (flow->actions & (VNET_FLOW_ACTION_MARK | VNET_FLOW_ACTION_REDIRECT_TO_NODE |
			 VNET_FLOW_ACTION_BUFFER_ADVANCE))
      {
	/* reserve slot 0 */
	if (xd->flow_lookup_entries == 0)
	  pool_get_aligned (xd->flow_lookup_entries, fle, CLIB_CACHE_LINE_BYTES);
	pool_get_aligned (xd->flow_lookup_entries, fle, CLIB_CACHE_LINE_BYTES);
	fe->mark = fle - xd->flow_lookup_entries;

	/* install entry in the lookup table */
	clib_memset (fle, -1, sizeof (*fle));
	if (flow->actions & VNET_FLOW_ACTION_MARK)
	  fle->flow_id = flow->mark_flow_id;
	if (flow->actions & VNET_FLOW_ACTION_REDIRECT_TO_NODE)
	  fle->next_index = flow->redirect_device_input_next_index;
	if (flow->actions & VNET_FLOW_ACTION_BUFFER_ADVANCE)
	  fle->buffer_advance = flow->buffer_advance;
      }
    else
      {
	fe->mark = 0;
      }

    /* Fast path uses function pointers from template, fallback to generic */
    if (PREDICT_FALSE ((rv = dpdk_flow_async_add (xd, flow, fte, fe))))
      goto insert_error;

    in_flight++;
    enqueued++;
  }

  if ((rv = dpdk_flow_async_push_pull (xd, enqueued, &in_flight, true, true)))
    return rv;

  return 0;

insert_error:
  if (fe)
    {
      clib_memset (fe, 0, sizeof (*fe));
      pool_put (xd->flow_entries, fe);
    }
  if (fle)
    {
      clib_memset (fle, -1, sizeof (*fle));
      pool_put (xd->flow_lookup_entries, fle);
    }
  return rv;
}

int
dpdk_flow_async_ops_fn (vnet_main_t *vnm, vnet_flow_dev_op_t op, u32 dev_instance,
			vnet_flow_range_t *range, uword *private_template_data, uword *private_data)
{
  vlib_main_t *vm = vlib_get_main ();
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, dev_instance);
  dpdk_flow_template_entry_t *fte;

  /* recycle old flow lookup entries only after the main loop counter
     increases - i.e. previously DMA'ed packets were handled */
  if (vec_len (xd->parked_lookup_indexes) > 0 && xd->parked_loop_count != vm->main_loop_count)
    {
      u32 *fl_index;

      vec_foreach (fl_index, xd->parked_lookup_indexes)
	pool_put_index (xd->flow_lookup_entries, *fl_index);
      vec_reset_length (xd->parked_lookup_indexes);
    }

  fte = vec_elt_at_index (xd->flow_template_entries, *private_template_data);

  switch (op)
    {
    case VNET_FLOW_DEV_OP_DEL_FLOW:
      return dpdk_flow_async_op_del (xd, range, fte, private_data);
    case VNET_FLOW_DEV_OP_ADD_FLOW:
      return dpdk_flow_async_op_add (xd, range, fte, private_data);
    default:
      return VNET_FLOW_ERROR_NOT_SUPPORTED;
    }
}

int
dpdk_flow_async_template_ops_fn (vnet_main_t *vnm, vnet_flow_dev_op_t op, u32 dev_instance,
				 u32 flow_template_index, uword *private_data)
{
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, dev_instance);
  vnet_flow_t *template = vnet_get_flow_async_template (flow_template_index);
  dpdk_flow_template_entry_t *fte;
  u32 n_flows = 0;
  int rv;

  if (op != VNET_FLOW_DEV_OP_ADD_FLOW && op != VNET_FLOW_DEV_OP_DEL_FLOW)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  if (template == 0)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  if (op == VNET_FLOW_DEV_OP_DEL_FLOW)
    {
      fte = vec_elt_at_index (xd->flow_template_entries, *private_data);

      if ((rv = rte_flow_template_table_destroy (xd->port_id, fte->table_handle,
						 &xd->last_flow_error)))
	{
	  dpdk_device_flow_error (xd, "rte_flow_template_table_destroy");
	  return VNET_FLOW_ERROR_INTERNAL;
	}

      if ((rv = rte_flow_actions_template_destroy (xd->port_id, fte->actions_handle,
						   &xd->last_flow_error)))
	{
	  dpdk_device_flow_error (xd, "rte_flow_actions_template_destroy");
	  return VNET_FLOW_ERROR_INTERNAL;
	}

      if ((rv = rte_flow_pattern_template_destroy (xd->port_id, fte->pattern_handle,
						   &xd->last_flow_error)))
	{
	  dpdk_device_flow_error (xd, "rte_flow_pattern_template_destroy");
	  return VNET_FLOW_ERROR_INTERNAL;
	}

      clib_memset (fte, 0, sizeof (*fte));
      pool_put (xd->flow_template_entries, fte);
      return 0;
    }

  if (template->actions == 0)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  // when adding a flow template the private_data is set to the number of flow to allocate for
  n_flows = (u32) *private_data;

  pool_get (xd->flow_template_entries, fte);

  xd->flags |= DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD;

  switch (template->type)
    {
    case VNET_FLOW_TYPE_ETHERNET:
    case VNET_FLOW_TYPE_IP4:
    case VNET_FLOW_TYPE_IP6:
    case VNET_FLOW_TYPE_IP4_N_TUPLE:
    case VNET_FLOW_TYPE_IP6_N_TUPLE:
    case VNET_FLOW_TYPE_IP4_VXLAN:
    case VNET_FLOW_TYPE_IP4_GTPC:
    case VNET_FLOW_TYPE_IP4_GTPU:
    case VNET_FLOW_TYPE_IP4_L2TPV3OIP:
    case VNET_FLOW_TYPE_IP4_IPSEC_ESP:
    case VNET_FLOW_TYPE_IP4_IPSEC_AH:
    case VNET_FLOW_TYPE_IP4_IP4:
    case VNET_FLOW_TYPE_IP4_IP4_N_TUPLE:
    case VNET_FLOW_TYPE_IP4_IP6:
    case VNET_FLOW_TYPE_IP4_IP6_N_TUPLE:
    case VNET_FLOW_TYPE_IP6_IP4:
    case VNET_FLOW_TYPE_IP6_IP4_N_TUPLE:
    case VNET_FLOW_TYPE_IP6_IP6:
    case VNET_FLOW_TYPE_IP6_IP6_N_TUPLE:
    case VNET_FLOW_TYPE_GENERIC:
      if ((rv = dpdk_flow_async_template_add (xd, template, fte, n_flows)))
	goto done;
      break;
    default:
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done;
    }

  *private_data = fte - xd->flow_template_entries;

done:
  if (rv)
    {
      clib_memset (fte, 0, sizeof (*fte));
      pool_put (xd->flow_template_entries, fte);
    }
  return rv;
}

u8 *
format_dpdk_flow (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  u32 flow_index = va_arg (*args, u32);
  uword private_data = va_arg (*args, uword);
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, dev_instance);
  dpdk_flow_entry_t *fe;

  if (flow_index == ~0)
    {
      s = format (s, "%-25s: %U\n", "supported flow actions", format_flow_actions,
		  xd->supported_flow_actions);
      s = format (s, "%-25s: %d\n", "last DPDK error type", xd->last_flow_error.type);
      s = format (s, "%-25s: %s\n", "last DPDK error message",
		  xd->last_flow_error.message ? xd->last_flow_error.message : "n/a");
      return s;
    }

  if (private_data >= vec_len (xd->flow_entries))
    return format (s, "unknown flow");

  fe = vec_elt_at_index (xd->flow_entries, private_data);
  s = format (s, "mark %u", fe->mark);
  return s;
}
