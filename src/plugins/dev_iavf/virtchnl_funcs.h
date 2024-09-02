/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _IIAVF_VIRTCHNL_FUNCS_H_
#define _IIAVF_VIRTCHNL_FUNCS_H_

#include <vppinfra/clib.h>
#include <vnet/dev/dev.h>
#include <dev_iavf/iavf.h>

/* Message size is offset right after last index, and size is one plus max index. */
#define VIRTCHNL_MSG_SZ(s, e, n) STRUCT_OFFSET_OF (s, e[(n)])

typedef struct
{
  virtchnl_op_t op;
  u8 no_reply : 1;
  u16 req_sz;
  u16 resp_sz;
  virtchnl_status_t status;
  const void *req;
  void *resp;
} iavf_virtchnl_req_t;

vnet_dev_rv_t iavf_virtchnl_req (vlib_main_t *, vnet_dev_t *,
				 iavf_virtchnl_req_t *);

static_always_inline vnet_dev_rv_t
iavf_vc_op_version (vlib_main_t *vm, vnet_dev_t *dev,
		    const virtchnl_version_info_t *req,
		    virtchnl_version_info_t *resp)
{
  iavf_virtchnl_req_t vr = {
    .op = VIRTCHNL_OP_VERSION,
    .req = req,
    .req_sz = sizeof (*req),
    .resp = resp,
    .resp_sz = sizeof (*resp),
  };

  return iavf_virtchnl_req (vm, dev, &vr);
}

static_always_inline vnet_dev_rv_t
iavf_vc_op_reset_vf (vlib_main_t *vm, vnet_dev_t *dev)
{
  iavf_virtchnl_req_t vr = {
    .op = VIRTCHNL_OP_RESET_VF,
    .no_reply = 1,
  };

  return iavf_virtchnl_req (vm, dev, &vr);
}

static_always_inline vnet_dev_rv_t
iavf_vc_op_get_vf_resources (vlib_main_t *vm, vnet_dev_t *dev, const u32 *req,
			     virtchnl_vf_resource_t *resp)
{
  iavf_virtchnl_req_t vr = {
    .op = VIRTCHNL_OP_GET_VF_RESOURCES,
    .req = req,
    .req_sz = sizeof (*req),
    .resp = resp,
    .resp_sz = sizeof (*resp),
  };

  return iavf_virtchnl_req (vm, dev, &vr);
}

static_always_inline vnet_dev_rv_t
iavf_vc_op_enable_queues (vlib_main_t *vm, vnet_dev_t *dev,
			  const virtchnl_queue_select_t *req)
{
  iavf_virtchnl_req_t vr = {
    .op = VIRTCHNL_OP_ENABLE_QUEUES,
    .req = req,
    .req_sz = sizeof (*req),
  };
  return iavf_virtchnl_req (vm, dev, &vr);
}

static_always_inline vnet_dev_rv_t
iavf_vc_op_disable_queues (vlib_main_t *vm, vnet_dev_t *dev,
			   const virtchnl_queue_select_t *req)
{
  iavf_virtchnl_req_t vr = {
    .op = VIRTCHNL_OP_DISABLE_QUEUES,
    .req = req,
    .req_sz = sizeof (*req),
  };
  return iavf_virtchnl_req (vm, dev, &vr);
}

static_always_inline vnet_dev_rv_t
iavf_vc_op_config_vsi_queues (vlib_main_t *vm, vnet_dev_t *dev,
			      const virtchnl_vsi_queue_config_info_t *req)
{
  iavf_virtchnl_req_t vr = {
    .op = VIRTCHNL_OP_CONFIG_VSI_QUEUES,
    .req = req,
    .req_sz = VIRTCHNL_MSG_SZ (virtchnl_vsi_queue_config_info_t, qpair,
			       req->num_queue_pairs),
  };

  return iavf_virtchnl_req (vm, dev, &vr);
}

static_always_inline vnet_dev_rv_t
iavf_vc_op_config_irq_map (vlib_main_t *vm, vnet_dev_t *dev,
			   const virtchnl_irq_map_info_t *req)
{
  iavf_virtchnl_req_t vr = {
    .op = VIRTCHNL_OP_CONFIG_IRQ_MAP,
    .req = req,
    .req_sz =
      VIRTCHNL_MSG_SZ (virtchnl_irq_map_info_t, vecmap, req->num_vectors),
  };

  return iavf_virtchnl_req (vm, dev, &vr);
}

static_always_inline vnet_dev_rv_t
iavf_vc_op_config_rss_lut (vlib_main_t *vm, vnet_dev_t *dev,
			   const virtchnl_rss_lut_t *req)
{
  iavf_virtchnl_req_t vr = {
    .op = VIRTCHNL_OP_CONFIG_RSS_LUT,
    .req = req,
    /* Message size from lut_entries would miss the mull-terminator byte. */
    .req_sz = VIRTCHNL_MSG_SZ (virtchnl_rss_lut_t, lut, req->lut_entries + 1),
  };

  return iavf_virtchnl_req (vm, dev, &vr);
}

static_always_inline vnet_dev_rv_t
iavf_vc_op_config_rss_key (vlib_main_t *vm, vnet_dev_t *dev,
			   const virtchnl_rss_key_t *req)
{
  iavf_virtchnl_req_t vr = {
    .op = VIRTCHNL_OP_CONFIG_RSS_KEY,
    .req = req,
    /* Message size from key_len would miss the mull-terminator byte. */
    .req_sz = VIRTCHNL_MSG_SZ (virtchnl_rss_key_t, key, req->key_len + 1),
  };

  return iavf_virtchnl_req (vm, dev, &vr);
}

static_always_inline vnet_dev_rv_t
iavf_vc_op_config_promisc_mode (vlib_main_t *vm, vnet_dev_t *dev,
				const virtchnl_promisc_info_t *req)
{
  iavf_virtchnl_req_t vr = {
    .op = VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE,
    .req = req,
    .req_sz = sizeof (*req),
  };

  return iavf_virtchnl_req (vm, dev, &vr);
}

static_always_inline vnet_dev_rv_t
iavf_vc_op_disable_vlan_stripping (vlib_main_t *vm, vnet_dev_t *dev)
{
  iavf_virtchnl_req_t vr = {
    .op = VIRTCHNL_OP_DISABLE_VLAN_STRIPPING,
  };

  return iavf_virtchnl_req (vm, dev, &vr);
}

static_always_inline vnet_dev_rv_t
iavf_vc_op_add_eth_addr (vlib_main_t *vm, vnet_dev_t *dev,
			 const virtchnl_ether_addr_list_t *req)
{
  iavf_virtchnl_req_t vr = {
    .op = VIRTCHNL_OP_ADD_ETH_ADDR,
    .req = req,
    .req_sz =
      VIRTCHNL_MSG_SZ (virtchnl_ether_addr_list_t, list, req->num_elements),
  };

  return iavf_virtchnl_req (vm, dev, &vr);
}

static_always_inline vnet_dev_rv_t
iavf_vc_op_del_eth_addr (vlib_main_t *vm, vnet_dev_t *dev,
			 const virtchnl_ether_addr_list_t *req)
{
  iavf_virtchnl_req_t vr = {
    .op = VIRTCHNL_OP_DEL_ETH_ADDR,
    .req = req,
    .req_sz =
      VIRTCHNL_MSG_SZ (virtchnl_ether_addr_list_t, list, req->num_elements),
  };

  return iavf_virtchnl_req (vm, dev, &vr);
}

static_always_inline vnet_dev_rv_t
iavf_vc_op_get_offload_vlan_v2_caps (vlib_main_t *vm, vnet_dev_t *dev,
				     virtchnl_vlan_caps_t *resp)
{
  iavf_virtchnl_req_t vr = {
    .op = VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS,
    .resp = resp,
    .resp_sz = sizeof (*resp),
  };

  return iavf_virtchnl_req (vm, dev, &vr);
}

static_always_inline vnet_dev_rv_t
iavf_vc_op_get_stats (vlib_main_t *vm, vnet_dev_t *dev,
		      const virtchnl_queue_select_t *req,
		      virtchnl_eth_stats_t *resp)
{
  iavf_virtchnl_req_t vr = {
    .op = VIRTCHNL_OP_GET_STATS,
    .req = req,
    .req_sz = sizeof (*req),
    .resp = resp,
    .resp_sz = sizeof (*resp),
  };

  return iavf_virtchnl_req (vm, dev, &vr);
}

static_always_inline vnet_dev_rv_t
iavf_vc_op_disable_vlan_stripping_v2 (vlib_main_t *vm, vnet_dev_t *dev,
				      const virtchnl_vlan_setting_t *req)
{
  iavf_virtchnl_req_t vr = {
    .op = VIRTCHNL_OP_DISABLE_VLAN_STRIPPING_V2,
    .req = req,
    .req_sz = sizeof (*req),
  };

  return iavf_virtchnl_req (vm, dev, &vr);
}

#endif /* _IIAVF_VIRTCHNL_FUNCS_H_ */
