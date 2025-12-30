/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <common.h>

VLIB_REGISTER_LOG_CLASS (mlx5_log, static) = {
  .class_name = "mlx5",
  .subclass_name = "flow",
};

typedef struct
{
  struct ibv_flow_attr attr;
  struct ibv_flow_spec_eth spec_eth;
} __attribute__ ((packed)) mlx5_flow_attr_t;

vnet_dev_rv_t
mlx5_rxq_add_flow (vnet_dev_t *dev, struct ibv_qp *qp, struct ibv_flow ***flows, u8 ibv_port,
		   const u8 *mac, const u8 *mask, u16 ether_type, u32 flags)
{
  mlx5_flow_attr_t fa = {};
  struct ibv_flow *flow;

  fa.attr.num_of_specs = 1;
  fa.attr.port = ibv_port;
  fa.attr.flags = flags;
  fa.spec_eth.type = IBV_FLOW_SPEC_ETH;
  fa.spec_eth.size = sizeof (struct ibv_flow_spec_eth);
  clib_memcpy (fa.spec_eth.val.dst_mac, mac, sizeof (fa.spec_eth.val.dst_mac));
  clib_memcpy (fa.spec_eth.mask.dst_mac, mask, sizeof (fa.spec_eth.mask.dst_mac));

  if (ether_type)
    {
      fa.spec_eth.val.ether_type = ether_type;
      fa.spec_eth.mask.ether_type = 0xffff;
    }

  flow = ibv_create_flow (qp, &fa.attr);
  if (flow == 0)
    {
      log_err (dev, "ibv_create_flow failed port %u flags 0x%x", ibv_port, flags);
      return VNET_DEV_ERR_INIT_FAILED;
    }
  log_debug (dev, "ibv_create_flow ok port %u flags 0x%x", ibv_port, flags);

  vec_add1 (*flows, flow);
  return VNET_DEV_OK;
}

void
mlx5_rxq_destroy_flows (vnet_dev_t *dev, struct ibv_flow ***flows)
{
  struct ibv_flow **f;
  int rv;

  if (*flows == 0)
    return;

  vec_foreach (f, *flows)
    if (f[0])
      {
	rv = ibv_destroy_flow (f[0]);
	if (rv)
	  log_err (dev, "ibv_destroy_flow failed rv %d", rv);
	else
	  log_debug (dev, "ibv_destroy_flow ok");
      }

  vec_free (*flows);
  *flows = 0;
}
