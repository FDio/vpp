/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/bus/platform.h>
#include <vppinfra/ring.h>
#include <dev_armada/musdk.h>
#include <dev_armada/pp2/pp2.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "pp2-port",
};

vnet_dev_rv_t
mvpp2_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv = VNET_DEV_OK;
  struct pp2_ppio_link_info li;
  enum pp2_ppio_hash_type hash_type = PP2_PPIO_HASH_T_5_TUPLE;
  struct pp2_ppio_inq_params *inqs_params = 0;
  char match[16];
  int mrv;
  u16 n_rxq = 0;
  u8 index;

  log_debug (port->dev, "");

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      vec_add1 (inqs_params, (struct pp2_ppio_inq_params){ .size = q->size });
      n_rxq++;
    }

  foreach_vnet_dev_args (arg, port)
    if (arg->id == MVPP2_PORT_ARG_RSS_HASH)
      {
	if (n_rxq > 1)
	  hash_type = vnet_dev_arg_get_enum (arg);
      }
    else if (arg->id == MVPP2_PORT_ARG_DSA_ENABLED)
      switch (vnet_dev_arg_get_enum (arg))
	{
	case MVPP2_PORT_DSA_ENABLED_ON:
	  mp->is_dsa = 1;
	  break;
	case MVPP2_PORT_DSA_ENABLED_OFF:
	  mp->is_dsa = 0;
	  break;
	case MVPP2_PORT_DSA_ENABLED_AUTO:
	  break;
	default:
	  ASSERT (0);
	  break;
	}

  index = get_lowest_set_bit_index (md->free_bpools);
  md->free_bpools ^= 1 << index;
  snprintf (match, sizeof (match), "pool-%u:%u", md->pp_id, index);

  mrv = pp2_bpool_init (
    &(struct pp2_bpool_params){
      .match = match,
      .buff_len = vlib_buffer_get_default_data_size (vm),
    },
    &mp->bpool);
  if (mrv < 0)
    {
      log_err (dev, "pp2_bpool_init failed for bpool %u, err %d", index, mrv);
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto done;
    }
  log_debug (dev, "pp2_bpool_init(bpool %u) pool-%u:%u ok", index,
	     mp->bpool->pp2_id, mp->bpool->id);

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      mvpp2_rxq_t *prq = vnet_dev_get_rx_queue_data (q);

      for (u32 j = 0; j < ARRAY_LEN (prq->bre); j++)
	prq->bre[j].bpool = mp->bpool;

      for (u32 i = 0; i < VLIB_FRAME_SIZE; i++)
	prq->desc_ptrs[i] = prq->descs + i;
    }

  snprintf (match, sizeof (match), "ppio-%d:%d", md->pp_id, port->port_id);

  struct pp2_ppio_params ppio_params = {
    .match = match,
    .type = PP2_PPIO_T_NIC,
    .eth_start_hdr = mp->is_dsa ? PP2_PPIO_HDR_ETH_DSA : PP2_PPIO_HDR_ETH,
    .inqs_params = {
      .num_tcs = 1,
      .hash_type = n_rxq > 1 ? hash_type : PP2_PPIO_HASH_T_NONE,
      .tcs_params[0] = {
	.num_in_qs = n_rxq,
	.inqs_params = inqs_params,
	.pools[0][0] = mp->bpool,
	.pools[0][1] = md->dummy_short_bpool,
      },
    },
  };

  foreach_vnet_dev_port_tx_queue (q, port)
    {
      struct pp2_ppio_outqs_params *oqs = &ppio_params.outqs_params;
      oqs->outqs_params[q->queue_id].weight = 1;
      oqs->outqs_params[q->queue_id].size = q->size;
      oqs->num_outqs++;
    }

  mrv = pp2_ppio_init (&ppio_params, &mp->ppio);
  if (mrv)
    {
      rv = VNET_DEV_ERR_INIT_FAILED;
      log_err (dev, "port %u ppio '%s' init failed, rv %d", port->port_id,
	       match, mrv);
      goto done;
    }
  log_debug (dev, "port %u ppio '%s' init ok", port->port_id, match);

  mrv = pp2_ppio_get_link_info (mp->ppio, &li);
  if (mrv)
    {
      rv = VNET_DEV_ERR_INIT_FAILED;
      log_err (dev, "failed to get link info for port %u, rv %d",
	       port->port_id, mrv);
      goto done;
    }

  log_debug (dev, "port %u %U", port->port_id, format_pp2_ppio_link_info, &li);

  mvpp2_port_add_counters (vm, port);

done:
  if (rv != VNET_DEV_OK)
    mvpp2_port_stop (vm, port);
  return rv;
}

void
mvpp2_port_deinit (vlib_main_t *vm, vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);

  log_debug (port->dev, "");

  if (mp->ppio)
    {
      pp2_ppio_deinit (mp->ppio);
      mp->ppio = 0;
    }

  if (mp->bpool)
    {
      pp2_bpool_deinit (mp->bpool);
      mp->bpool = 0;
    }
}

void
mvpp2_port_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  vnet_dev_t *dev = port->dev;
  vnet_dev_port_state_changes_t changes = {};
  struct pp2_ppio_link_info li;
  int mrv;

  mrv = pp2_ppio_get_link_info (mp->ppio, &li);

  if (mrv)
    {
      log_debug (dev, "pp2_ppio_get_link_info: failed, rv %d", mrv);
      return;
    }

  if (mp->last_link_info.up != li.up)
    {
      changes.change.link_state = 1;
      changes.link_state = li.up != 0;
      log_debug (dev, "link state changed to %u", changes.link_state);
    }

  if (mp->last_link_info.duplex != li.duplex)
    {
      changes.change.link_duplex = 1;
      changes.full_duplex = li.duplex != 0;
      log_debug (dev, "link full duplex changed to %u", changes.full_duplex);
    }

  if (mp->last_link_info.speed != li.speed)
    {
      u32 speeds[] = {
	[MV_NET_LINK_SPEED_AN] = 0,
	[MV_NET_LINK_SPEED_10] = 10000,
	[MV_NET_LINK_SPEED_100] = 100000,
	[MV_NET_LINK_SPEED_1000] = 1000000,
	[MV_NET_LINK_SPEED_2500] = 2500000,
	[MV_NET_LINK_SPEED_10000] = 10000000,
      };

      if (li.speed < ARRAY_LEN (speeds))
	{
	  changes.change.link_speed = 1;
	  changes.link_speed = speeds[li.speed];
	  log_debug (dev, "link speed changed to %u", changes.link_speed);
	}
    }

  if (changes.change.any)
    {
      mp->last_link_info = li;
      vnet_dev_port_state_change (vm, port, changes);
    }

  mvpp2_port_get_stats (vm, port);
}

vnet_dev_rv_t
mvpp2_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int mrv;

  log_debug (port->dev, "");

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      mvpp2_rxq_t *prq = vnet_dev_get_rx_queue_data (q);
      prq->n_bpool_refill = VLIB_FRAME_SIZE;
      mrvl_pp2_bpool_put_no_inline (vm, q);
      if (prq->n_bpool_refill)
	log_warn (port->dev, "mrvl_pp2_bpool_put failed to fill %u buffers",
		  prq->n_bpool_refill);
    }

  mrv = pp2_ppio_enable (mp->ppio);
  if (mrv)
    {
      log_err (port->dev, "pp2_ppio_enable() failed, rv %d", mrv);
      return VNET_DEV_ERR_NOT_READY;
    }

  mp->is_enabled = 1;

  vnet_dev_poll_port_add (vm, port, 0.5, mvpp2_port_poll);

  return VNET_DEV_OK;
}

void
mvpp2_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  struct pp2_buff_inf bi;
  int rv;

  log_debug (port->dev, "");

  if (mp->is_enabled)
    {
      vnet_dev_poll_port_remove (vm, port, mvpp2_port_poll);

      rv = pp2_ppio_disable (mp->ppio);
      if (rv)
	log_err (dev, "pp2_ppio_disable() failed, rv %d", rv);

      vnet_dev_port_state_change (vm, port,
				  (vnet_dev_port_state_changes_t){
				    .change.link_state = 1,
				    .change.link_speed = 1,
				    .link_speed = 0,
				    .link_state = 0,
				  });
      mp->is_enabled = 0;
    }

  while (pp2_bpool_get_buff (md->hif[vm->thread_index], mp->bpool, &bi) == 0)
    vlib_buffer_free (vm, &(u32){ bi.cookie }, 1);
}

vnet_dev_rv_t
mvpp2_port_add_sec_if (vlib_main_t *vm, vnet_dev_port_t *port, void *p)
{
  vnet_dev_port_interface_t *sif = p;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 port_id = CLIB_U32_MAX, switch_id = 0, index;

  if (mp->is_dsa == 0)
    return VNET_DEV_ERR_NOT_SUPPORTED;

  foreach_vnet_dev_args (a, sif)
    {
      switch (a->id)
	{
	case MVPP2_SEC_IF_ARG_DSA_PORT:
	  if (a->val_set)
	    port_id = vnet_dev_arg_get_uint32 (a);
	  break;
	case MVPP2_SEC_IF_ARG_DSA_SWITCH:
	  switch_id = vnet_dev_arg_get_uint32 (a);
	  break;
	default:
	  break;
	}
    }

  if (port_id == CLIB_U32_MAX)
    {
      log_err (port->dev, "missing dsa_port argument");
      return VNET_DEV_ERR_INVALID_ARG;
    }

  log_debug (port->dev, "switch %u port %u", switch_id, port_id);

  mv_dsa_tag_t tag = {
    .tag_type = MV_DSA_TAG_TYPE_FROM_CPU,
    .src_port_or_lag = port_id,
    .src_dev = switch_id,
  };

  index = switch_id << 5 | port_id;

  sif->user_data = tag.as_u32;
  uword_bitmap_set_bits_at_index (mp->valid_dsa_src_bitmap, index, 1);
  mp->dsa_to_sec_if[index] = sif->index;
  return VNET_DEV_OK;
}

vnet_dev_rv_t
mvpp2_port_del_sec_if (vlib_main_t *vm, vnet_dev_port_t *port, void *p)
{
  vnet_dev_port_interface_t *sif = p;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mv_dsa_tag_t tag = { .as_u32 = sif->user_data };
  u32 index = tag.src_dev << 5 | tag.src_port_or_lag;

  log_debug (port->dev, "switch %u port %u", tag.src_dev, tag.src_port_or_lag);

  uword_bitmap_clear_bits_at_index (mp->valid_dsa_src_bitmap, index, 1);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
mvpp2_port_cfg_change_validate (vlib_main_t *vm, vnet_dev_port_t *port,
				vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;

  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_PROMISC_MODE:
    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      break;

    default:
      rv = VNET_DEV_ERR_NOT_SUPPORTED;
    };

  return rv;
}

vnet_dev_rv_t
mvpp2_port_cfg_change (vlib_main_t *vm, vnet_dev_port_t *port,
		       vnet_dev_port_cfg_change_req_t *req)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv = VNET_DEV_OK;
  eth_addr_t addr;
  int mrv;

  switch (req->type)
    {

    case VNET_DEV_PORT_CFG_PROMISC_MODE:
      mrv = pp2_ppio_set_promisc (mp->ppio, req->promisc);
      if (mrv)
	{
	  log_err (port->dev, "pp2_ppio_set_promisc: failed, rv %d", mrv);
	  rv = VNET_DEV_ERR_INTERNAL;
	}
      else
	log_debug (port->dev, "pp2_ppio_set_promisc: promisc %u",
		   req->promisc);
      break;

    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
      clib_memcpy (&addr, req->addr.eth_mac, sizeof (addr));
      mrv = pp2_ppio_set_mac_addr (mp->ppio, addr);
      if (mrv)
	{
	  log_err (port->dev, "pp2_ppio_set_mac_addr: failed, rv %d", mrv);
	  rv = VNET_DEV_ERR_INTERNAL;
	}
      else
	log_debug (port->dev, "pp2_ppio_set_mac_addr: %U added",
		   format_ethernet_address, &addr);
      break;

    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
      clib_memcpy (&addr, req->addr.eth_mac, sizeof (addr));
      mrv = pp2_ppio_add_mac_addr (mp->ppio, addr);
      if (mrv)
	{
	  log_err (port->dev, "pp2_ppio_add_mac_addr: failed, rv %d", mrv);
	  rv = VNET_DEV_ERR_INTERNAL;
	}
      else
	log_debug (port->dev, "pp2_ppio_add_mac_addr: %U added",
		   format_ethernet_address, &addr);
      break;

    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      clib_memcpy (&addr, req->addr.eth_mac, sizeof (addr));
      mrv = pp2_ppio_remove_mac_addr (mp->ppio, addr);
      if (mrv)
	{
	  log_err (port->dev, "pp2_ppio_remove_mac_addr: failed, rv %d", mrv);
	  rv = VNET_DEV_ERR_INTERNAL;
	}
      else
	log_debug (port->dev, "pp2_ppio_remove_mac_addr: %U added",
		   format_ethernet_address, &addr);
      break;

    default:
      return VNET_DEV_ERR_NOT_SUPPORTED;
    };

  return rv;
}
